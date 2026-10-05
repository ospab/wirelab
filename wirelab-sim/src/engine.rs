//! Discrete-event simulator: two endpoints, two link directions, one clock.

use crate::scenario::{Pace, Scenario, Transfer};
use bytes::Bytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::time::{Duration, Instant};
use wirelab_core::{ClockKind, Endpoint, Event, Output, Record, Side, SimTime, Zone};
use wirelab_wire::{byte_entropy, Link, LinkStats, Observation};

/// How the run actually advanced time, after resolving `Pace::Auto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolvedPace {
    Virtual,
    Realtime,
}

pub struct TransferResult {
    pub spec: Transfer,
    pub sent: usize,
    pub delivered: usize,
    /// First byte offset where the delivered stream differs from what was sent.
    pub first_mismatch: Option<usize>,
    pub started_at: Option<SimTime>,
    pub completed_at: Option<SimTime>,
}

pub struct RunOutput {
    pub pace: ResolvedPace,
    /// Whether simulated timestamps can be read as real durations. False when
    /// an endpoint reads the OS clock but simulated time ran ahead of it.
    pub timing_valid: bool,
    pub records: Vec<Record>,
    pub observations: Vec<Observation>,
    pub link_stats: [LinkStats; 2],
    pub established_at: [Option<SimTime>; 2],
    pub transfers: Vec<TransferResult>,
    pub ended_at: SimTime,
    pub end_reason: String,
    pub protocol: &'static str,
}

enum Ev {
    Arrive { to: Side, data: Bytes },
    Tick(Side),
    Sample,
}

struct Queued {
    at: SimTime,
    seq: u64,
    ev: Ev,
}

impl PartialEq for Queued {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.seq) == (o.at, o.seq)
    }
}
impl Eq for Queued {}
impl PartialOrd for Queued {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Queued {
    // `seq` breaks ties in insertion order, which keeps runs reproducible.
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.at, self.seq).cmp(&(o.at, o.seq))
    }
}

struct Active {
    spec: Transfer,
    payload: Vec<u8>,
    sent: usize,
    started_at: Option<SimTime>,
    completed_at: Option<SimTime>,
}

struct Sim<'a> {
    sc: &'a Scenario,
    endpoints: [Box<dyn Endpoint>; 2],
    links: [Link; 2],
    queue: BinaryHeap<Reverse<Queued>>,
    seq: u64,
    packet_id: u64,
    records: Vec<Record>,
    observations: Vec<Observation>,
    established_at: [Option<SimTime>; 2],
    transfers: Vec<Active>,
    /// Bytes delivered at a side, per stream, in delivery order.
    received: HashMap<(Side, u32), Vec<u8>>,
}

pub fn run(sc: &Scenario, client: Box<dyn Endpoint>, server: Box<dyn Endpoint>, pace: Pace) -> RunOutput {
    let wall_clock = client.clock() == ClockKind::Wall || server.clock() == ClockKind::Wall;
    let pace = match pace {
        Pace::Auto if wall_clock => ResolvedPace::Realtime,
        Pace::Auto | Pace::Virtual => ResolvedPace::Virtual,
        Pace::Realtime => ResolvedPace::Realtime,
    };
    let protocol = client.protocol();

    let transfers = sc
        .transfers
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut payload = vec![0u8; t.bytes];
            StdRng::seed_from_u64(sc.seed ^ (0x7472_616e_7366_6572 + i as u64)).fill_bytes(&mut payload);
            Active { spec: t.clone(), payload, sent: 0, started_at: None, completed_at: None }
        })
        .collect();

    let mut sim = Sim {
        sc,
        endpoints: [client, server],
        // Distinct seeds per direction: a shared one would drop the same
        // packet indices both ways, which no real path does.
        links: [Link::new(sc.c2s().clone(), sc.seed), Link::new(sc.s2c().clone(), sc.seed ^ 0x5555_5555_5555_5555)],
        queue: BinaryHeap::new(),
        seq: 0,
        packet_id: 0,
        records: Vec::new(),
        observations: Vec::new(),
        established_at: [None, None],
        transfers,
        received: HashMap::new(),
    };

    let (ended_at, end_reason) = sim.run_loop(pace);
    let transfers = sim
        .transfers
        .iter()
        .map(|a| {
            let got = sim.received.get(&(a.spec.from.peer(), a.spec.stream)).map(Vec::as_slice).unwrap_or(&[]);
            let first_mismatch = got.iter().zip(&a.payload).position(|(x, y)| x != y).or_else(|| {
                (got.len() > a.payload.len()).then_some(a.payload.len())
            });
            TransferResult {
                spec: a.spec.clone(),
                sent: a.sent,
                delivered: got.len(),
                first_mismatch,
                started_at: a.started_at,
                completed_at: a.completed_at,
            }
        })
        .collect();

    RunOutput {
        pace,
        timing_valid: !(pace == ResolvedPace::Virtual && wall_clock),
        records: sim.records,
        observations: sim.observations,
        link_stats: [sim.links[0].stats(), sim.links[1].stats()],
        established_at: sim.established_at,
        transfers,
        ended_at,
        end_reason,
        protocol,
    }
}

impl Sim<'_> {
    fn schedule(&mut self, at: SimTime, ev: Ev) {
        self.seq += 1;
        self.queue.push(Reverse(Queued { at, seq: self.seq, ev }));
    }

    fn record(&mut self, at: SimTime, zone: Zone, event: Event) {
        self.records.push(Record { t_us: at.as_us(), zone, event });
    }

    fn run_loop(&mut self, pace: ResolvedPace) -> (SimTime, String) {
        let tick = Duration::from_millis(self.sc.tick_ms);
        let sample = Duration::from_millis(self.sc.sample_ms);
        let deadline = SimTime::from_ms(self.sc.duration_ms);
        let wall_start = Instant::now();

        for side in Side::BOTH {
            self.drive(side, SimTime::ZERO, |ep, now, out| ep.start(now, out));
            self.schedule(SimTime::ZERO + tick, Ev::Tick(side));
        }
        self.schedule(SimTime::ZERO, Ev::Sample);

        while let Some(Reverse(q)) = self.queue.pop() {
            if q.at > deadline {
                return (deadline, format!("duration_ms = {} reached", self.sc.duration_ms));
            }
            if pace == ResolvedPace::Realtime {
                let due = wall_start + q.at.as_duration();
                let now = Instant::now();
                if due > now {
                    std::thread::sleep(due - now);
                }
            }
            let now = q.at;
            match q.ev {
                Ev::Arrive { to, data } => self.drive(to, now, |ep, now, out| ep.on_datagram(now, data, out)),
                Ev::Tick(side) => {
                    self.drive(side, now, |ep, now, out| ep.tick(now, out));
                    self.schedule(now + tick, Ev::Tick(side));
                }
                Ev::Sample => {
                    for side in Side::BOTH {
                        let values: BTreeMap<String, f64> =
                            self.endpoints[side.index()].metrics().into_iter().map(|(k, v)| (k.to_string(), v)).collect();
                        if !values.is_empty() {
                            self.record(now, side.into(), Event::Metrics { values });
                        }
                    }
                    self.schedule(now + sample, Ev::Sample);
                }
            }
            self.feed(now);

            if self.established_at.iter().all(Option::is_some) && self.transfers.iter().all(|t| t.completed_at.is_some()) {
                let reason = if self.transfers.is_empty() {
                    "both ends established, no transfers configured"
                } else {
                    "every transfer delivered"
                };
                return (now, reason.to_string());
            }
        }
        (deadline, "event queue ran dry".to_string())
    }

    /// Call into one endpoint, then route everything it produced.
    fn drive(&mut self, side: Side, now: SimTime, f: impl FnOnce(&mut dyn Endpoint, SimTime, &mut Output)) {
        let ep = &mut self.endpoints[side.index()];
        let before = ep.state();
        let mut out = Output::default();
        f(ep.as_mut(), now, &mut out);
        let after = ep.state();
        let established = ep.is_established();

        if before != after {
            self.record(now, side.into(), Event::State { from: before, to: after });
        }
        if established && self.established_at[side.index()].is_none() {
            self.established_at[side.index()] = Some(now);
        }
        self.route(side, now, out);
    }

    fn route(&mut self, side: Side, now: SimTime, out: Output) {
        for n in out.notes {
            self.record(now, side.into(), Event::Note { what: n.what.to_string(), detail: n.detail });
        }

        for (stream, data) in out.delivered {
            self.record(now, side.into(), Event::AppDeliver { stream, len: data.len() });
            let buf = self.received.entry((side, stream)).or_default();
            buf.extend_from_slice(&data);
            let got = buf.len();
            if let Some(t) = self
                .transfers
                .iter_mut()
                .find(|t| t.spec.from == side.peer() && t.spec.stream == stream && t.completed_at.is_none())
            {
                if got >= t.payload.len() {
                    t.completed_at = Some(now);
                }
            }
        }

        let dir = side.egress();
        for data in out.datagrams {
            self.packet_id += 1;
            self.observations.push(Observation { at: now, dir, data: data.clone() });
            let entropy = byte_entropy(&data);
            let head = data.iter().take(16).map(|b| format!("{b:02x}")).collect();
            let len = data.len();
            let tx = self.links[dir.index()].transmit(now, data);
            let arrive_us = tx.deliveries.iter().map(|d| d.at.as_us()).collect();
            self.record(now, Zone::Wire, Event::Packet { id: self.packet_id, dir, len, fate: tx.fate, arrive_us, entropy, head });
            for d in tx.deliveries {
                self.schedule(d.at, Ev::Arrive { to: side.peer(), data: d.data });
            }
        }
    }

    /// Hand application data to senders as far as their admission control
    /// allows.
    fn feed(&mut self, now: SimTime) {
        let [Some(c), Some(s)] = self.established_at else { return };
        let both = c.max(s);
        for i in 0..self.transfers.len() {
            let t = &self.transfers[i];
            if t.sent >= t.payload.len() || now < both + Duration::from_millis(t.spec.start_ms) {
                continue;
            }
            let side = t.spec.from;
            while self.transfers[i].sent < self.transfers[i].payload.len() && self.endpoints[side.index()].can_send() {
                let t = &mut self.transfers[i];
                t.started_at.get_or_insert(now);
                let end = (t.sent + t.spec.chunk).min(t.payload.len());
                let chunk = Bytes::copy_from_slice(&t.payload[t.sent..end]);
                let stream = t.spec.stream;
                let mut out = Output::default();
                if let Err(e) = self.endpoints[side.index()].send(now, stream, chunk, &mut out) {
                    // The data was not taken. Leave `sent` where it is so
                    // integrity reports the shortfall instead of hiding it.
                    self.record(now, side.into(), Event::Note { what: "send_error".into(), detail: e.to_string() });
                    self.route(side, now, out);
                    break;
                }
                let len = end - self.transfers[i].sent;
                self.transfers[i].sent = end;
                self.record(now, side.into(), Event::AppSend { stream, len });
                self.route(side, now, out);
            }
        }
    }
}
