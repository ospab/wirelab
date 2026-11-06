//! Measurements over captured packets: what the panel charts and what the
//! test runner and the CRTS export report. Each function says what it
//! measured and on how many packets; none of them guesses a protocol.

use crate::capture::{Packet, TcpMeta};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Way {
    C2s,
    S2c,
}

/// Round-trip time seen from the wire, passively, from TCP: a client data
/// segment going by, then the server's ACK that covers it. The wire captures
/// on the client side, so this is the path wire → server → wire, which is
/// the whole impaired path. Retransmitted segments are not sampled (Karn).
#[derive(Default)]
pub struct TcpRtt {
    /// Per flow (client port, server port): sequence end of segments in
    /// flight and when each was first seen, oldest first.
    flows: HashMap<(u16, u16), Vec<(u32, u64, bool)>>,
}

const MAX_IN_FLIGHT: usize = 4096;

impl TcpRtt {
    /// Feed one packet; returns an RTT sample in µs when this packet is an
    /// ACK that covers a segment seen once.
    pub fn push(&mut self, way: Way, p: &Packet) -> Option<u64> {
        let tcp: TcpMeta = p.tcp?;
        match way {
            Way::C2s => {
                let mut len = p.payload_len as u32;
                if tcp.flags & (TcpMeta::SYN | TcpMeta::FIN) != 0 {
                    len += 1;
                }
                if len == 0 {
                    return None;
                }
                let end = tcp.seq.wrapping_add(len);
                let q = self.flows.entry((p.sport, p.dport)).or_default();
                if let Some(e) = q.iter_mut().find(|e| e.0 == end) {
                    e.2 = true; // retransmitted: its ACK no longer says when it arrived
                } else {
                    if q.len() >= MAX_IN_FLIGHT {
                        q.remove(0);
                    }
                    q.push((end, p.t_us, false));
                }
                None
            }
            Way::S2c => {
                if tcp.flags & TcpMeta::ACK == 0 {
                    return None;
                }
                let q = self.flows.get_mut(&(p.dport, p.sport))?;
                // Segments whose end the ACK reaches, in serial-number order.
                let covered = |end: u32| (tcp.ack.wrapping_sub(end) as i32) >= 0;
                let mut sample = None;
                q.retain(|&(end, t, retx)| {
                    if covered(end) {
                        if !retx && p.t_us >= t {
                            // The newest covered segment gives the freshest sample.
                            sample = Some(p.t_us - t);
                        }
                        false
                    } else {
                        true
                    }
                });
                if tcp.flags & (TcpMeta::RST | TcpMeta::FIN) != 0 && q.is_empty() {
                    self.flows.remove(&(p.dport, p.sport));
                }
                sample
            }
        }
    }
}

/// How lengths are distributed: the most frequent one and its share, and
/// whether lengths collapse onto multiples of one step (CRTS CT-006).
#[derive(Debug, Clone, Serialize)]
pub struct LengthStats {
    pub packets: usize,
    pub mode_len: usize,
    pub mode_share: f64,
    /// Largest step from 16 to 1500 that at least `STEP_SHARE` of the
    /// lengths are multiples of, over at least three distinct lengths (one
    /// or two lengths are the mode, reported above); none when no step
    /// covers that many.
    pub step: Option<usize>,
    pub step_share: f64,
    pub distinct: usize,
}

/// Share of lengths on one step that counts as degenerating onto it. By
/// chance a step of 16 covers about 1/16 of lengths.
pub const STEP_SHARE: f64 = 0.9;

pub fn length_stats(lengths: &[usize]) -> Option<LengthStats> {
    if lengths.is_empty() {
        return None;
    }
    let mut hist: HashMap<usize, usize> = HashMap::new();
    for &l in lengths {
        *hist.entry(l).or_default() += 1;
    }
    // Ties go to the shorter length, so the result does not depend on hash order.
    let (&mode_len, &mode_n) = hist.iter().max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0))).unwrap();
    let n = lengths.len() as f64;
    let mut step = None;
    let mut step_share = 0.0;
    // A dominant mode already says everything a step would.
    let steps = if (mode_n as f64 / n) < STEP_SHARE { 16..=1500 } else { 1..=0 };
    for s in steps.rev() {
        let on = lengths.iter().filter(|&&l| l % s == 0).count() as f64 / n;
        if on >= STEP_SHARE && hist.keys().filter(|&&l| l % s == 0).count() >= 3 {
            step = Some(s);
            step_share = on;
            break;
        }
    }
    Some(LengthStats { packets: lengths.len(), mode_len, mode_share: mode_n as f64 / n, step, step_share, distinct: hist.len() })
}

/// Periodicity of arrival times (CRTS CT-007): arrivals are counted in bins,
/// and the normalised autocorrelation of those counts is searched for its
/// highest peak at a lag of at least `min_lag_us`. A train of packets every
/// T seconds gives a peak near 1 at lag T; independent arrivals give values
/// near 0.
#[derive(Debug, Clone, Serialize)]
pub struct Periodicity {
    pub packets: usize,
    pub span_s: f64,
    pub peak: f64,
    pub peak_lag_ms: f64,
    pub bin_ms: f64,
}

pub fn periodicity(times_us: &[u64], bin_us: u64, min_lag_us: u64, max_lag_us: u64) -> Option<Periodicity> {
    if times_us.len() < 8 || bin_us == 0 {
        return None;
    }
    let t0 = *times_us.iter().min()?;
    let t1 = *times_us.iter().max()?;
    let bins = ((t1 - t0) / bin_us + 1) as usize;
    let max_lag = ((max_lag_us / bin_us) as usize).min(bins / 2);
    let min_lag = ((min_lag_us / bin_us) as usize).max(1);
    if max_lag <= min_lag {
        return None;
    }
    let mut x = vec![0f64; bins];
    for &t in times_us {
        x[((t - t0) / bin_us) as usize] += 1.0;
    }
    let mean = x.iter().sum::<f64>() / bins as f64;
    for v in &mut x {
        *v -= mean;
    }
    let var: f64 = x.iter().map(|v| v * v).sum();
    if var == 0.0 {
        return None;
    }
    let mut peak = f64::MIN;
    let mut peak_lag = 0;
    for k in min_lag..=max_lag {
        let r: f64 = (0..bins - k).map(|i| x[i] * x[i + k]).sum::<f64>() / var;
        if r > peak {
            peak = r;
            peak_lag = k;
        }
    }
    Some(Periodicity {
        packets: times_us.len(),
        span_s: (t1 - t0) as f64 / 1e6,
        peak,
        peak_lag_ms: (peak_lag as u64 * bin_us) as f64 / 1000.0,
        bin_ms: bin_us as f64 / 1000.0,
    })
}

/// IP bytes per second in each direction, from `t0_us` on.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Throughput {
    pub c2s: Vec<u64>,
    pub s2c: Vec<u64>,
}

impl Throughput {
    pub fn add(&mut self, t0_us: u64, way: Way, p: &Packet) {
        let Some(dt) = p.t_us.checked_sub(t0_us) else { return };
        let sec = (dt / 1_000_000) as usize;
        // A packet a day after the start is a clock problem, not a measurement.
        if sec > 86_400 {
            return;
        }
        let v = match way {
            Way::C2s => &mut self.c2s,
            Way::S2c => &mut self.s2c,
        };
        if v.len() <= sec {
            v.resize(sec + 1, 0);
        }
        v[sec] += p.ip_len as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Transport;
    use std::net::Ipv4Addr;

    fn tcp(t_us: u64, c2s: bool, seq: u32, ack: u32, flags: u8, len: usize) -> Packet {
        let (c, s) = (Ipv4Addr::new(10, 77, 1, 3), Ipv4Addr::new(10, 77, 2, 3));
        let (src, dst, sport, dport) = if c2s { (c, s, 40000, 443) } else { (s, c, 443, 40000) };
        Packet {
            t_us,
            src,
            dst,
            transport: Transport::Tcp,
            sport,
            dport,
            ip_len: 52 + len,
            payload_len: len,
            payload: Vec::new(),
            tcp: Some(TcpMeta { seq, ack, flags }),
        }
    }

    #[test]
    fn rtt_from_data_and_its_ack() {
        let mut r = TcpRtt::default();
        assert_eq!(r.push(Way::C2s, &tcp(1_000, true, 100, 0, TcpMeta::ACK, 50)), None);
        assert_eq!(r.push(Way::C2s, &tcp(2_000, true, 150, 0, TcpMeta::ACK, 50)), None);
        // Covers the first segment only.
        assert_eq!(r.push(Way::S2c, &tcp(41_000, false, 0, 150, TcpMeta::ACK, 0)), Some(40_000));
        assert_eq!(r.push(Way::S2c, &tcp(42_500, false, 0, 200, TcpMeta::ACK, 0)), Some(40_500));
        // Nothing left to cover.
        assert_eq!(r.push(Way::S2c, &tcp(50_000, false, 0, 200, TcpMeta::ACK, 0)), None);
    }

    #[test]
    fn retransmitted_segments_are_not_sampled() {
        let mut r = TcpRtt::default();
        r.push(Way::C2s, &tcp(1_000, true, 100, 0, TcpMeta::ACK, 50));
        r.push(Way::C2s, &tcp(300_000, true, 100, 0, TcpMeta::ACK, 50));
        assert_eq!(r.push(Way::S2c, &tcp(340_000, false, 0, 150, TcpMeta::ACK, 0)), None);
    }

    #[test]
    fn sequence_wraparound() {
        let mut r = TcpRtt::default();
        r.push(Way::C2s, &tcp(0, true, u32::MAX - 9, 0, TcpMeta::ACK, 20));
        assert_eq!(r.push(Way::S2c, &tcp(10, false, 0, 10, TcpMeta::ACK, 0)), Some(10));
    }

    #[test]
    fn length_mode_and_step() {
        let mut l = vec![1200; 60];
        for _ in 0..4 {
            l.extend([100, 200, 300, 400, 500]);
        }
        l.extend([333, 444]);
        let s = length_stats(&l).unwrap();
        assert_eq!(s.mode_len, 1200);
        assert!((s.mode_share - 60.0 / 82.0).abs() < 1e-9);
        // 80 of 82 are multiples of 100 (and of 50, 25...): the largest step wins.
        assert_eq!(s.step, Some(100));

        // One length nearly everywhere is a mode, not a step.
        let mut one = vec![1350; 95];
        one.extend([30, 60, 90, 120, 150]);
        assert_eq!(length_stats(&one).unwrap().step, None);

        let spread: Vec<usize> = (0..500).map(|i| 60 + (i * 7919) % 1400).collect();
        let s = length_stats(&spread).unwrap();
        assert!(s.mode_share < 0.01, "{}", s.mode_share);
        assert_eq!(s.step, None);
    }

    #[test]
    fn periodic_train_peaks_at_its_period() {
        // A packet every 2 s for 2 minutes.
        let train: Vec<u64> = (0..60).map(|i| i * 2_000_000).collect();
        let p = periodicity(&train, 50_000, 100_000, 30_000_000).unwrap();
        assert!(p.peak > 0.9, "{p:?}");
        assert!((p.peak_lag_ms - 2000.0).abs() < 1.0, "{p:?}");

        // Pseudo-random arrivals over the same span.
        let mut x: u64 = 12345;
        let mut noise: Vec<u64> = (0..60)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 33) % 120_000_000
            })
            .collect();
        noise.sort();
        let p = periodicity(&noise, 50_000, 100_000, 30_000_000).unwrap();
        assert!(p.peak < 0.5, "{p:?}");
    }
}
