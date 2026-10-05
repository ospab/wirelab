//! The run recording: one timeline across all three zones, written as JSON
//! lines so a viewer can stream it and a person can grep it.

use crate::{Dir, Zone};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub t_us: u64,
    pub zone: Zone,
    #[serde(flatten)]
    pub event: Event,
}

/// What happened to a datagram on the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fate {
    Delivered,
    /// Delivered with one bit flipped.
    Corrupted,
    Lost,
    /// Larger than the link MTU.
    MtuDrop,
    /// The bottleneck queue was already longer than the link allows.
    QueueDrop,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Note { what: String, detail: String },
    State { from: String, to: String },
    Metrics { values: BTreeMap<String, f64> },
    AppSend { stream: u32, len: usize },
    AppDeliver { stream: u32, len: usize },
    Packet {
        id: u64,
        dir: Dir,
        len: usize,
        fate: Fate,
        /// Arrival times at the peer; two entries when the link duplicated it.
        arrive_us: Vec<u64>,
        /// Shannon entropy of the datagram's bytes, bits per byte.
        entropy: f64,
        /// First bytes in hex, enough to spot a fixed header by eye.
        head: String,
    },
}
