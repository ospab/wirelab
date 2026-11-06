//! Interactive mode: a lab of three containers left running for a person,
//! and the local panel to work in it.

pub mod bench;
pub mod censor_build;
pub mod crts;
pub mod docker;
pub mod doctor;
pub mod export;
pub mod lab;
pub mod panel;
pub mod recipe;
pub mod wirectl;

pub use docker::Docker;
pub use lab::{Base, LabInfo};
