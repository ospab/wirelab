//! The wire zone: the link between the endpoints, and what an observer on it
//! can see.

pub mod capture;
pub mod link;
pub mod observe;
pub mod pcap;

pub use link::{Delivery, Link, LinkProfile, LinkStats, Transmission};
pub use observe::{byte_entropy, summarize, DirSummary, Observation};
pub use pcap::PcapngWriter;
