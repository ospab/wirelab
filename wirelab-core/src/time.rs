use serde::Serialize;
use std::fmt;
use std::ops::Add;
use std::time::Duration;

/// Simulated time since the start of a run, in microseconds.
///
/// Microseconds rather than nanoseconds: pcapng's default resolution is 1 µs,
/// and finer simulated precision would be thrown away on export anyway.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SimTime(pub u64);

impl SimTime {
    pub const ZERO: SimTime = SimTime(0);

    pub fn from_ms(ms: u64) -> SimTime {
        SimTime(ms * 1000)
    }

    pub fn from_ms_f64(ms: f64) -> SimTime {
        SimTime((ms.max(0.0) * 1000.0).round() as u64)
    }

    pub fn as_us(self) -> u64 {
        self.0
    }

    pub fn as_ms_f64(self) -> f64 {
        self.0 as f64 / 1000.0
    }

    pub fn as_duration(self) -> Duration {
        Duration::from_micros(self.0)
    }

    pub fn saturating_sub(self, other: SimTime) -> SimTime {
        SimTime(self.0.saturating_sub(other.0))
    }
}

impl Add<Duration> for SimTime {
    type Output = SimTime;

    fn add(self, d: Duration) -> SimTime {
        SimTime(self.0 + d.as_micros() as u64)
    }
}

impl fmt::Display for SimTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3} ms", self.as_ms_f64())
    }
}
