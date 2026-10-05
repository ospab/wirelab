//! In-process mode: both endpoints in one process, the wire simulated
//! between them. Reproducible by seed for implementations on a virtual clock.

pub mod engine;
pub mod report;
pub mod scenario;

pub use engine::{run, ResolvedPace, RunOutput, TransferResult};
pub use report::Report;
pub use scenario::{Pace, Scenario, Transfer};
