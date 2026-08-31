#![forbid(unsafe_code)]

mod http;
pub mod model;
mod runner;
mod transports;

#[cfg(test)]
mod tests;

pub use model::{
    EksEnrollmentEnvelope, EksEnrollmentResult, PreflightProfile, PreflightRunnerBuildMarker,
    SignedPreflightReceipt, verify_receipt,
};
pub use runner::{current_unix_seconds, run_preflight};

/// Perform one authenticated, read-only EKS enrollment discovery. The
/// production transport derives the regional EKS authority and uses the exact
/// compiled `WebPKI` root corpus; callers cannot inject a URL, socket, or CA.
///
/// # Errors
/// Returns a stable error code when the request or credentials are invalid, or
/// authenticated discovery cannot complete.
pub fn discover_eks(
    envelope: EksEnrollmentEnvelope,
    trusted_now: i64,
) -> Result<EksEnrollmentResult, &'static str> {
    envelope.validate().map_err(|error| match error {
        model::ModelError::InvalidCredentials => "INVALID_AWS_CREDENTIALS",
        _ => "INVALID_ENROLLMENT_REQUEST",
    })?;
    let transport = transports::EksEnrollmentTransport::new(
        envelope.request,
        envelope.credentials,
        trusted_now,
    )
    .map_err(|_| "EKS_DISCOVERY_UNAVAILABLE")?;
    transport
        .describe_cluster()
        .map_err(|_| "EKS_DISCOVERY_UNAVAILABLE")
}
