//! Interactive mode: a lab of three containers left running for a person,
//! and the local panel to work in it.

pub mod docker;
pub mod lab;
pub mod panel;

pub use docker::Docker;
pub use lab::{Base, LabInfo};
