//! Transport-independent application boundary for signed `AccordLock` proposals.
//!
//! There is exactly one submission intent: the `AgentProposal` inside the
//! signed `accordlock-ingress` envelope. [`AccordLockService::submit`] accepts only
//! bounded signed bytes. Its fixed TCB adapter returns the opaque
//! [`trusted::AuthenticatedIngressRequest`], which is moved intact into the
//! trusted workflow. This crate never reconstructs that capability from public
//! tenant or actor strings.
//!
//! This crate intentionally supplies no HTTP/TLS server, durable persistence,
//! production authentication adapter, or live executor. It is an application
//! composition boundary only.
//!
//! The ingress capability cannot be publicly constructed:
//!
//! ```compile_fail
//! use accordlock_service::trusted::AuthenticatedIngressRequest;
//!
//! let _forged = AuthenticatedIngressRequest::new();
//! ```
//!
//! Nor can it be duplicated before consumption:
//!
//! ```compile_fail
//! use accordlock_service::trusted::AuthenticatedIngressRequest;
//!
//! fn duplicate(capability: &AuthenticatedIngressRequest) -> AuthenticatedIngressRequest {
//!     capability.clone()
//! }
//! ```
//!
//! The workflow boundary also consumes it, so the same authenticated request
//! cannot be submitted twice:
//!
//! ```compile_fail
//! use accordlock_service::TrustedWorkflow;
//! use accordlock_service::trusted::AuthenticatedIngressRequest;
//!
//! fn submit_twice<W, Q>(workflow: &W, capability: AuthenticatedIngressRequest)
//! where
//!     W: TrustedWorkflow<Q>,
//! {
//!     let _ = workflow.submit_trusted(capability);
//!     let _ = workflow.submit_trusted(capability);
//! }
//! ```
//!
//! Public receipts and status projections are observations, not execution
//! capabilities:
//!
//! ```compile_fail
//! use accordlock_service::SubmissionReceipt;
//!
//! fn cannot_execute(receipt: SubmissionReceipt) {
//!     receipt.execute();
//! }
//! ```
//!
//! ```compile_fail
//! use accordlock_service::StatusView;
//!
//! fn cannot_dispatch(status: StatusView) {
//!     status.dispatch();
//! }
//! ```

#![forbid(unsafe_code)]

mod api;
pub mod trusted;

pub use api::{
    ActionState, EnvelopeError, EnvelopeViolation, IdentifierError, IdentifierViolation,
    MAX_SIGNED_STATUS_BYTES, MAX_SIGNED_SUBMISSION_BYTES, PublicReasonCode, ReceiptId, RequestId,
    StatusEnvelope, StatusLookup, StatusView, SubmissionEnvelope, SubmissionReceipt,
};
pub use trusted::{
    AccordLockService, ServiceError, TrustedFailureCode, TrustedPipeline, TrustedWorkflow,
};
