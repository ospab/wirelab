//! What an observer on the path sees, and statistics over it.
//!
//! An [`Observation`] holds a timestamp, a direction and the datagram bytes,
//! and nothing else. Anything built on top of it (summaries now, censor
//! models later) therefore cannot use keys or endpoint state even by mistake.
//!
//! Tap point: the sender's egress, before the link's faults. A datagram the
//! link later loses was still seen.

use bytes::Bytes;
use serde::Serialize;
use std::collections::BTreeMap;
use wirelab_core::{Dir, SimTime};

#[derive(Debug, Clone)]
pub struct Observation {
    pub at: SimTime,
    pub dir: Dir,
    pub data: Bytes,
}

/// Shannon entropy in bits per byte. On short datagrams it is biased low
/// (a 64-byte sample cannot reach 8.0), so compare like with like.
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone, Serialize)]
pub struct DirSummary {
    pub dir: Dir,
    pub packets: u64,
    pub bytes: u64,
    pub size_min: Option<usize>,
    pub size_median: Option<usize>,
    pub size_max: Option<usize>,
    pub distinct_sizes: usize,
    /// Most frequent sizes, `(size, count)`. A protocol that pads to a few
    /// fixed sizes shows up here at once.
    pub top_sizes: Vec<(usize, u64)>,
    pub first_sizes: Vec<usize>,
    pub mean_entropy: Option<f64>,
    /// Gaps between consecutive datagrams. `None` when the run's timing is
    /// not trustworthy (see the run's timing note) or there are too few.
    pub gap_median_ms: Option<f64>,
    pub gap_p90_ms: Option<f64>,
}

pub fn summarize(obs: &[Observation], dir: Dir, timing_valid: bool) -> DirSummary {
    let seen: Vec<&Observation> = obs.iter().filter(|o| o.dir == dir).collect();
    let mut sizes: Vec<usize> = seen.iter().map(|o| o.data.len()).collect();
    let first_sizes = sizes.iter().take(16).copied().collect();

    let mut histogram: BTreeMap<usize, u64> = BTreeMap::new();
    for &s in &sizes {
        *histogram.entry(s).or_default() += 1;
    }
    let mut top_sizes: Vec<(usize, u64)> = histogram.iter().map(|(&s, &c)| (s, c)).collect();
    top_sizes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top_sizes.truncate(8);

    sizes.sort_unstable();
    let mean_entropy = (!seen.is_empty())
        .then(|| seen.iter().map(|o| byte_entropy(&o.data)).sum::<f64>() / seen.len() as f64);

    let (gap_median_ms, gap_p90_ms) = if timing_valid && seen.len() >= 2 {
        let mut gaps: Vec<f64> = seen.windows(2).map(|w| w[1].at.saturating_sub(w[0].at).as_ms_f64()).collect();
        gaps.sort_by(|a, b| a.total_cmp(b));
        (Some(percentile(&gaps, 0.5)), Some(percentile(&gaps, 0.9)))
    } else {
        (None, None)
    };

    DirSummary {
        dir,
        packets: seen.len() as u64,
        bytes: sizes.iter().map(|&s| s as u64).sum(),
        size_min: sizes.first().copied(),
        size_median: (!sizes.is_empty()).then(|| sizes[sizes.len() / 2]),
        size_max: sizes.last().copied(),
        distinct_sizes: histogram.len(),
        top_sizes,
        first_sizes,
        mean_entropy,
        gap_median_ms,
        gap_p90_ms,
    }
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(byte_entropy(&[7; 100]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((byte_entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn summary_counts_one_direction() {
        let obs = vec![
            Observation { at: SimTime::from_ms(0), dir: Dir::C2s, data: Bytes::from(vec![0; 100]) },
            Observation { at: SimTime::from_ms(1), dir: Dir::S2c, data: Bytes::from(vec![0; 50]) },
            Observation { at: SimTime::from_ms(4), dir: Dir::C2s, data: Bytes::from(vec![0; 100]) },
        ];
        let s = summarize(&obs, Dir::C2s, true);
        assert_eq!(s.packets, 2);
        assert_eq!(s.bytes, 200);
        assert_eq!(s.top_sizes, vec![(100, 2)]);
        assert_eq!(s.gap_median_ms, Some(4.0));
        assert_eq!(summarize(&obs, Dir::C2s, false).gap_median_ms, None);
    }
}
