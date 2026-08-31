#![forbid(unsafe_code)]
//! Read-only provider adapters for `AccordLock`'s trusted evidence connectors.
//!
//! This crate deliberately stops before networking and credentials. A runner
//! injects authenticated transports which own TLS, bearer tokens, `SigV4` and
//! provider SDK state. The adapters expose only bounded, typed read specs and
//! turn strict authenticated observations into connector snapshots.

mod common;
mod ecr;
mod github;
mod kubernetes;

pub use common::*;
pub use ecr::*;
pub use github::*;
pub use kubernetes::*;

#[cfg(test)]
mod tests;
