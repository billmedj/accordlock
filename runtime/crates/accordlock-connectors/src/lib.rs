//! Trusted, transport-independent evidence connector boundary.
//!
//! The public collection request is deliberately lookup-only. Source facts,
//! clocks, authority, issuers, and signing identities enter only through the
//! fixed runtime configuration, which is part of the trusted computing base.

mod model;
mod runtime;

pub use model::*;
pub use runtime::*;

#[cfg(test)]
mod tests;
