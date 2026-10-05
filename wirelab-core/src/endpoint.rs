//! The contract between the simulator and a protocol implementation.
//!
//! An endpoint is one side of a session, driven sans-io: the simulator hands
//! it datagrams and ticks, it hands back datagrams to send and application
//! data it delivered. It never touches a socket, which is what lets the wire
//! between two endpoints be anything the simulator wants it to be.

use crate::SimTime;
use bytes::Bytes;

/// Which clock an implementation reads its timers from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockKind {
    /// Timers follow the `now` the simulator passes in, so simulated time can
    /// run faster than real time and timing stays reproducible.
    Virtual,
    /// The implementation reads the OS clock itself (`Instant::now()`).
    /// Simulated time must then track wall time, or every timer-driven
    /// behaviour (RTO, pacing, delayed ACKs) happens at the wrong moment.
    Wall,
}

/// Something an endpoint wants recorded in its zone.
#[derive(Debug, Clone)]
pub struct Note {
    pub what: &'static str,
    pub detail: String,
}

/// Everything one call into an endpoint produced.
#[derive(Debug, Default)]
pub struct Output {
    pub datagrams: Vec<Bytes>,
    /// `(stream, payload)` handed up to the application, in delivery order.
    pub delivered: Vec<(u32, Bytes)>,
    pub notes: Vec<Note>,
}

impl Output {
    pub fn note(&mut self, what: &'static str, detail: impl Into<String>) {
        self.notes.push(Note { what, detail: detail.into() });
    }
}

pub trait Endpoint {
    /// Stable protocol name, as used in scenario files.
    fn protocol(&self) -> &'static str;

    fn clock(&self) -> ClockKind;

    fn start(&mut self, now: SimTime, out: &mut Output);

    fn on_datagram(&mut self, now: SimTime, data: Bytes, out: &mut Output);

    /// Periodic timer check. Called every `tick_ms` of simulated time.
    fn tick(&mut self, now: SimTime, out: &mut Output);

    fn is_established(&self) -> bool;

    /// Human-readable state, recorded whenever it changes.
    fn state(&self) -> String;

    /// Whether the endpoint would accept application data right now. This is
    /// the implementation's own admission control (congestion window,
    /// pacing), applied the way its production caller applies it.
    fn can_send(&self) -> bool;

    fn send(&mut self, now: SimTime, stream: u32, data: Bytes, out: &mut Output) -> anyhow::Result<()>;

    /// Internal counters sampled periodically into the endpoint's zone.
    fn metrics(&self) -> Vec<(&'static str, f64)> {
        Vec::new()
    }
}
