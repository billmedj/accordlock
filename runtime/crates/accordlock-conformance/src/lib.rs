//! Executable adversarial checks for the provisional local `AccordLock` profile.
//!
//! This crate contains no production implementation. Its tests exercise only
//! public protocol and kernel APIs and do not turn synthetic cases into G0 or
//! benchmark evidence.

/// Marker exposed so documentation builds contain the crate's evidentiary boundary.
pub const EVIDENTIARY_STATUS: &str = "synthetic_non_g0_non_independent";
