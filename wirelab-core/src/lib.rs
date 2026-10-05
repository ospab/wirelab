//! Types shared by every wirelab crate: the three zones, simulated time, the
//! protocol adapter contract, the run recording and the verdicts.

pub mod endpoint;
pub mod record;
pub mod time;
pub mod verdict;

pub use endpoint::{ClockKind, Endpoint, Note, Output};
pub use record::{Event, Fate, Record};
pub use time::SimTime;
pub use verdict::{Check, Metric, Outcome};

use serde::{Deserialize, Serialize};

/// One end of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Client,
    Server,
}

impl Side {
    pub const BOTH: [Side; 2] = [Side::Client, Side::Server];

    pub fn peer(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }

    /// Direction of the datagrams this side sends.
    pub fn egress(self) -> Dir {
        match self {
            Side::Client => Dir::C2s,
            Side::Server => Dir::S2c,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// Direction on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    C2s,
    S2c,
}

impl Dir {
    pub const BOTH: [Dir; 2] = [Dir::C2s, Dir::S2c];

    pub fn index(self) -> usize {
        self as usize
    }
}

/// Where a recorded event was observed. The wire zone only ever sees bytes,
/// sizes and timing; it is never handed endpoint state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Zone {
    Client,
    Wire,
    Server,
}

impl From<Side> for Zone {
    fn from(side: Side) -> Zone {
        match side {
            Side::Client => Zone::Client,
            Side::Server => Zone::Server,
        }
    }
}
