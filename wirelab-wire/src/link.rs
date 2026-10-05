//! One direction of a simulated link, timed in simulated microseconds.
//!
//! Jitter keeps FIFO order: a real path is a chain of queues, and delay that
//! varies inside a queue does not let a later datagram overtake an earlier
//! one. Reordering is its own knob, because on real paths it comes from
//! something else (parallel links, ECMP) and is far rarer than jitter.

use anyhow::{bail, Result};
use bytes::{Bytes, BytesMut};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use wirelab_core::{Fate, SimTime};

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinkProfile {
    /// One-way propagation delay.
    pub latency_ms: f64,
    /// Each datagram's delay is `latency ± jitter`, uniform, floored at zero,
    /// and never earlier than the datagram sent before it.
    pub jitter_ms: f64,
    /// Probability that a datagram leaves the FIFO and takes an extra
    /// `0..reorder_delay_ms`, letting later ones overtake it.
    pub reorder: f64,
    pub reorder_delay_ms: f64,
    pub loss: f64,
    pub duplicate: f64,
    /// Probability of one flipped bit.
    pub corrupt: f64,
    /// Bottleneck rate. 0 means unlimited.
    pub bandwidth_kbps: f64,
    /// Longest queue the bottleneck holds before tail-dropping, in time to
    /// drain it. 0 means unbounded. Only meaningful with a bandwidth limit.
    pub queue_ms: f64,
    /// Datagrams larger than this are dropped. 0 means no limit.
    pub mtu: usize,
    /// Loss, duplication and corruption start this long into the run. Delay
    /// and the bandwidth limit apply from the start: they are properties of
    /// the path, not faults.
    pub impair_from_ms: f64,
}

impl LinkProfile {
    pub fn validate(&self, label: &str) -> Result<()> {
        for (name, p) in [("loss", self.loss), ("duplicate", self.duplicate), ("corrupt", self.corrupt), ("reorder", self.reorder)] {
            if !(0.0..=1.0).contains(&p) {
                bail!("{label}.{name} = {p}: a probability must be between 0 and 1");
            }
        }
        for (name, v) in [
            ("latency_ms", self.latency_ms),
            ("jitter_ms", self.jitter_ms),
            ("reorder_delay_ms", self.reorder_delay_ms),
            ("bandwidth_kbps", self.bandwidth_kbps),
            ("queue_ms", self.queue_ms),
            ("impair_from_ms", self.impair_from_ms),
        ] {
            if !(v >= 0.0 && v.is_finite()) {
                bail!("{label}.{name} = {v}: must be a non-negative number");
            }
        }
        if self.reorder > 0.0 && self.reorder_delay_ms == 0.0 {
            bail!("{label}.reorder needs reorder_delay_ms: with no extra delay nothing can overtake");
        }
        if self.queue_ms > 0.0 && self.bandwidth_kbps == 0.0 {
            bail!("{label}.queue_ms needs bandwidth_kbps: an unlimited link never queues");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LinkStats {
    pub offered: u64,
    pub offered_bytes: u64,
    pub delivered: u64,
    pub lost: u64,
    pub corrupted: u64,
    pub duplicated: u64,
    pub reordered: u64,
    pub mtu_dropped: u64,
    pub queue_dropped: u64,
}

pub struct Delivery {
    pub at: SimTime,
    pub data: Bytes,
}

pub struct Transmission {
    pub fate: Fate,
    pub deliveries: Vec<Delivery>,
}

pub struct Link {
    profile: LinkProfile,
    rng: StdRng,
    /// When the bottleneck finishes serialising what it already holds.
    busy_until: SimTime,
    /// Latest arrival handed out so far; in-order datagrams never beat it.
    last_arrival: SimTime,
    stats: LinkStats,
}

impl Link {
    pub fn new(profile: LinkProfile, seed: u64) -> Link {
        Link { profile, rng: StdRng::seed_from_u64(seed), busy_until: SimTime::ZERO, last_arrival: SimTime::ZERO, stats: LinkStats::default() }
    }

    pub fn transmit(&mut self, now: SimTime, data: Bytes) -> Transmission {
        let p = &self.profile;
        self.stats.offered += 1;
        self.stats.offered_bytes += data.len() as u64;

        // Every roll is drawn up front in a fixed order, so the random stream
        // advances the same way whichever branch is taken and two profiles that
        // differ in one knob still see the same draws for the others.
        let lost = self.rng.gen::<f64>() < p.loss;
        let duplicated = self.rng.gen::<f64>() < p.duplicate;
        let corrupted = self.rng.gen::<f64>() < p.corrupt;
        let jitter = [self.rng.gen::<f64>(), self.rng.gen::<f64>()];
        let flip = self.rng.gen::<u64>();
        let reordered = self.rng.gen::<f64>() < p.reorder;
        let reorder_extra = self.rng.gen::<f64>() * p.reorder_delay_ms;

        if p.mtu > 0 && data.len() > p.mtu {
            self.stats.mtu_dropped += 1;
            return Transmission { fate: Fate::MtuDrop, deliveries: Vec::new() };
        }

        let departs = if p.bandwidth_kbps > 0.0 {
            let start = now.max(self.busy_until);
            let queued = start.saturating_sub(now);
            if p.queue_ms > 0.0 && queued.as_ms_f64() > p.queue_ms {
                self.stats.queue_dropped += 1;
                return Transmission { fate: Fate::QueueDrop, deliveries: Vec::new() };
            }
            let serialise_ms = data.len() as f64 * 8.0 / p.bandwidth_kbps;
            self.busy_until = SimTime(start.as_us() + SimTime::from_ms_f64(serialise_ms).as_us());
            self.busy_until
        } else {
            now
        };

        let faults = now.as_ms_f64() >= p.impair_from_ms;
        if faults && lost {
            self.stats.lost += 1;
            return Transmission { fate: Fate::Lost, deliveries: Vec::new() };
        }

        let (data, fate) = if faults && corrupted && !data.is_empty() {
            self.stats.corrupted += 1;
            let mut buf = BytesMut::from(&data[..]);
            let bit = (flip % (buf.len() as u64 * 8)) as usize;
            buf[bit / 8] ^= 1 << (bit % 8);
            (buf.freeze(), Fate::Corrupted)
        } else {
            (data, Fate::Delivered)
        };

        let copies = if faults && duplicated { 2 } else { 1 };
        if copies == 2 {
            self.stats.duplicated += 1;
        }
        let reordered = faults && reordered;
        if reordered {
            self.stats.reordered += 1;
        }
        let mut deliveries = Vec::with_capacity(copies);
        for &u in &jitter[..copies] {
            let delay = (p.latency_ms + p.jitter_ms * (2.0 * u - 1.0)).max(0.0);
            let mut at = SimTime(departs.as_us() + SimTime::from_ms_f64(delay).as_us());
            if reordered {
                at = SimTime(at.as_us() + SimTime::from_ms_f64(reorder_extra).as_us());
            } else {
                at = at.max(self.last_arrival);
                self.last_arrival = at;
            }
            deliveries.push(Delivery { at, data: data.clone() });
        }
        self.stats.delivered += deliveries.len() as u64;
        Transmission { fate, deliveries }
    }

    pub fn stats(&self) -> LinkStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(profile: LinkProfile, seed: u64, n: usize) -> Vec<(Fate, Vec<u64>, Bytes)> {
        let mut link = Link::new(profile, seed);
        (0..n)
            .map(|i| {
                let t = link.transmit(SimTime::from_ms(i as u64), Bytes::from(vec![i as u8; 100]));
                let at = t.deliveries.iter().map(|d| d.at.as_us()).collect();
                let data = t.deliveries.first().map(|d| d.data.clone()).unwrap_or_default();
                (t.fate, at, data)
            })
            .collect()
    }

    #[test]
    fn clean_link_delivers_after_latency() {
        let out = run(LinkProfile { latency_ms: 20.0, ..Default::default() }, 1, 10);
        for (i, (fate, at, _)) in out.iter().enumerate() {
            assert_eq!(*fate, Fate::Delivered);
            assert_eq!(at, &vec![(i as u64 + 20) * 1000]);
        }
    }

    #[test]
    fn same_seed_same_run() {
        let p = LinkProfile { latency_ms: 30.0, jitter_ms: 10.0, loss: 0.2, duplicate: 0.1, corrupt: 0.1, ..Default::default() };
        assert_eq!(run(p.clone(), 7, 200), run(p, 7, 200));
    }

    #[test]
    fn bandwidth_serialises_back_to_back_datagrams() {
        // 1000 bytes at 800 kbit/s takes 10 ms on the wire.
        let mut link = Link::new(LinkProfile { bandwidth_kbps: 800.0, ..Default::default() }, 0);
        let a = link.transmit(SimTime::ZERO, Bytes::from(vec![0; 1000]));
        let b = link.transmit(SimTime::ZERO, Bytes::from(vec![0; 1000]));
        assert_eq!(a.deliveries[0].at, SimTime::from_ms(10));
        assert_eq!(b.deliveries[0].at, SimTime::from_ms(20));
    }

    #[test]
    fn full_queue_tail_drops() {
        let mut link = Link::new(LinkProfile { bandwidth_kbps: 800.0, queue_ms: 15.0, ..Default::default() }, 0);
        let fates: Vec<Fate> = (0..4).map(|_| link.transmit(SimTime::ZERO, Bytes::from(vec![0; 1000])).fate).collect();
        // Queued 0, 10 and 20 ms: the third exceeds the 15 ms bound.
        assert_eq!(fates, [Fate::Delivered, Fate::Delivered, Fate::QueueDrop, Fate::QueueDrop]);
        assert_eq!(link.stats().queue_dropped, 2);
    }

    #[test]
    fn oversized_datagram_is_dropped() {
        let mut link = Link::new(LinkProfile { mtu: 500, ..Default::default() }, 0);
        assert_eq!(link.transmit(SimTime::ZERO, Bytes::from(vec![0; 501])).fate, Fate::MtuDrop);
        assert_eq!(link.transmit(SimTime::ZERO, Bytes::from(vec![0; 500])).fate, Fate::Delivered);
    }

    #[test]
    fn corruption_flips_one_bit() {
        let out = run(LinkProfile { corrupt: 1.0, ..Default::default() }, 3, 20);
        for (i, (fate, _, data)) in out.iter().enumerate() {
            assert_eq!(*fate, Fate::Corrupted);
            let flipped: u32 = data.iter().map(|b| (b ^ i as u8).count_ones()).sum();
            assert_eq!(flipped, 1);
        }
    }

    #[test]
    fn faults_wait_for_impair_from() {
        let out = run(LinkProfile { loss: 1.0, impair_from_ms: 5.0, ..Default::default() }, 0, 10);
        let lost: Vec<bool> = out.iter().map(|(f, _, _)| *f == Fate::Lost).collect();
        assert_eq!(lost, [false, false, false, false, false, true, true, true, true, true]);
    }

    #[test]
    fn jitter_keeps_order() {
        let out = run(LinkProfile { latency_ms: 50.0, jitter_ms: 20.0, ..Default::default() }, 9, 100);
        let arrivals: Vec<u64> = out.iter().map(|(_, at, _)| at[0]).collect();
        assert!(arrivals.windows(2).all(|w| w[0] <= w[1]), "jitter alone must not reorder");
        assert!(arrivals.windows(2).any(|w| w[1] - w[0] != 1000), "jitter must still vary the spacing");
    }

    #[test]
    fn reorder_lets_later_datagrams_overtake() {
        let p = LinkProfile { latency_ms: 50.0, reorder: 0.2, reorder_delay_ms: 10.0, ..Default::default() };
        let mut link = Link::new(p, 4);
        let arrivals: Vec<u64> =
            (0..100).map(|i| link.transmit(SimTime::from_ms(i), Bytes::from_static(b"x")).deliveries[0].at.as_us()).collect();
        assert!(arrivals.windows(2).any(|w| w[0] > w[1]));
        assert!(link.stats().reordered > 0);
    }

    #[test]
    fn validate_rejects_bad_probability() {
        assert!(LinkProfile { loss: 1.5, ..Default::default() }.validate("wire").is_err());
        assert!(LinkProfile { queue_ms: 10.0, ..Default::default() }.validate("wire").is_err());
    }
}
