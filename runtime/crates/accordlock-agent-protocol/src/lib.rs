//! Generic, model-neutral authorization records for exact agent tool actions.
//!
//! The types in this crate are deliberately independent of EKS and of any
//! particular agent harness. They define a strict transfer chain:
//!
//! `ExecutionRequest -> AuthorizationDecision -> ExecutionAuthorization -> ExecutionRecord`.
//!
//! Every transition repeats and verifies the security-relevant tool bindings.
//! The model may propose a request, but only trusted policy enforcement may
//! authorize it and only a trusted executor may atomically consume its
//! single-use authorization.

#![forbid(unsafe_code)]

mod canonical;
mod model;
mod store;

pub use canonical::{
    AUTHORIZATION_DECISION_DOMAIN, EXECUTION_ARGUMENTS_DOMAIN, EXECUTION_AUTHORIZATION_DOMAIN,
    EXECUTION_RECORD_DOMAIN, EXECUTION_REQUEST_DOMAIN, canonical_args_bytes, canonical_args_hash,
};
pub use model::{
    AUTHORIZATION_DECISION_SCHEMA_VERSION, AuthorizationDecision, AuthorizationOutcome,
    BindingError, EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EXECUTION_PROTOCOL_SCHEMA_VERSION,
    EXECUTION_RECORD_SCHEMA_VERSION, EXECUTION_REQUEST_SCHEMA_VERSION, ExecutionAuthorization,
    ExecutionOutcome, ExecutionRecord, ExecutionRequest, MAX_AUTHORIZATION_LIFETIME_SECONDS,
    MAX_CANONICAL_ARGUMENT_BYTES, MAX_CANONICAL_ARGUMENT_DEPTH, MAX_CANONICAL_ARGUMENT_NODES,
    MAX_DECISION_LIFETIME_SECONDS, MAX_EXECUTION_DURATION_SECONDS, MAX_EXTENSION_BYTES,
    MAX_REASON_CODE_BYTES, MAX_REQUEST_LIFETIME_SECONDS, MAX_RUN_ID_BYTES, MAX_SESSION_ID_BYTES,
    MAX_TOOL_BYTES, MAX_TOOL_CALL_ID_BYTES, MAX_WORKSPACE_BYTES, ValidationError,
};
pub use store::{AuthorizationConsumption, AuthorizationStoreError, MemoryAuthorizationStore};

pub use accordlock_protocol::{CanonicalEncode, CanonicalError, Digest32, canonical_hash};
