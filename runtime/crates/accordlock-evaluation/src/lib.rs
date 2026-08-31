//! Deterministic policy-evaluation primitives for governed execution.
//!
//! Conformance evaluations are evidence, never authority. The policy evaluator
//! can only preserve or strengthen a pre-existing enforcement decision.

#![forbid(unsafe_code)]

mod canonical;
mod intent;
mod local;
mod material;
mod model;
mod policy;
mod provider;
mod record;
mod trace_builder;

pub use canonical::{
    CONFORMANCE_EVALUATION_DOMAIN, EVIDENCE_LEDGER_SNAPSHOT_DOMAIN, EVIDENCE_PROVENANCE_DOMAIN,
    EVIDENCE_TRUST_POLICY_DOMAIN, INTENT_CONFORMANCE_EVALUATION_DOMAIN,
    INTENT_CONFORMANCE_RECORD_DOMAIN, INTENT_EVIDENCE_DOMAIN, INTENT_EVIDENCE_REQUEST_DOMAIN,
    INTENT_EVIDENCE_RESPONSE_DOMAIN, INTENT_TRACE_DOMAIN, POLICY_DECISION_DOMAIN,
    PRE_EXECUTION_INTENT_TRACE_DOMAIN, PROVIDER_RESPONSE_ATTESTATION_DOMAIN,
    PROVIDER_RESPONSE_BODY_DOMAIN, RESOURCE_QUOTA_DOMAIN, RESOURCE_REQUEST_DOMAIN,
    RESOURCE_RESERVATION_DOMAIN, TASK_REQUIREMENT_DOMAIN, TRANSFORMATION_STEP_DOMAIN,
};
pub use intent::{
    CalibrationStatus, EVIDENCE_LEDGER_SNAPSHOT_SCHEMA_VERSION, EVIDENCE_PROVENANCE_SCHEMA_VERSION,
    EVIDENCE_TRUST_POLICY_SCHEMA_VERSION, EvidenceLedgerExpectation, EvidenceLedgerSnapshot,
    EvidenceMethodKind, EvidenceProvenance, EvidenceTrustPolicy, EvidenceVerdict,
    INTENT_CONFORMANCE_EVALUATION_SCHEMA_VERSION, INTENT_EVIDENCE_SCHEMA_VERSION,
    INTENT_TRACE_SCHEMA_VERSION, IntentConformanceEvaluation, IntentConformanceEvaluator,
    IntentConformanceOutcome, IntentEvaluationCheckpoint, IntentEvaluationContext,
    IntentEvaluationProfile, IntentEvidence, IntentFinding, IntentFindingReason, IntentStage,
    IntentTrace, PRE_EXECUTION_INTENT_TRACE_SCHEMA_VERSION, PreExecutionIntentTrace,
};
pub use local::{
    ExactArtifactDigestRule, LocalArtifactField, LocalDeterministicEvidenceError,
    LocalDeterministicEvidenceProvider, LocalEvidenceHarnessError, LocalEvidenceHarnessOutcome,
    LocalEvidenceRecordBinding, LocalEvidenceReviewReason, PinnedLocalArtifactResolver,
    evaluate_local_evidence,
};
pub use material::{
    BoundedEvidenceMaterial, DisclosedEvidenceMaterial, EXTERNAL_DISCLOSURE_GRANT_SCHEMA_VERSION,
    EXTERNAL_DISCLOSURE_GRANT_SIGNATURE_DOMAIN, EvidenceArtifactResolver, EvidenceDisclosurePolicy,
    EvidenceMaterialError, EvidenceMaterialKind, EvidenceResolutionDisposition,
    ExternalDisclosureAuthorizationError, ExternalEvidenceDisclosureGrant,
    MAX_ACTION_EVIDENCE_MATERIAL_BYTES, MAX_EXTERNAL_DISCLOSURE_GRANT_LIFETIME_SECONDS,
    MAX_PLAN_EVIDENCE_MATERIAL_BYTES, MAX_REQUEST_EVIDENCE_MATERIAL_BYTES,
    MAX_RESULT_EVIDENCE_MATERIAL_BYTES, VerifiedExternalEvidenceDisclosure,
};
pub use model::{
    CONFORMANCE_EVALUATION_SCHEMA_VERSION, ConformanceEvaluation, ConformanceResult,
    MAX_EVALUATION_BINDINGS, MAX_RESOURCE_KIND_BYTES, NORMALIZED_SCORE_MAX, NormalizedScore,
    POLICY_DECISION_SCHEMA_VERSION, POLICY_EVALUATION_SCHEMA_VERSION, PolicyDecisionRecord,
    PolicyEvaluationError, RESOURCE_QUOTA_SCHEMA_VERSION, RESOURCE_REQUEST_SCHEMA_VERSION,
    RESOURCE_RESERVATION_SCHEMA_VERSION, ResourceQuota, ResourceRequest, ResourceReservation,
    ScoreInterval, TASK_REQUIREMENT_SCHEMA_VERSION, TRANSFORMATION_STEP_SCHEMA_VERSION,
    TaskRequirement, TransformationStep, WorkflowStage,
};
pub use policy::{DecisionReason, EnforcementDecision, PolicyEvaluation, PolicyEvaluator};
pub use provider::{
    INTENT_EVIDENCE_REQUEST_SCHEMA_VERSION, INTENT_EVIDENCE_RESPONSE_SCHEMA_VERSION,
    IntentEvidenceProvider, IntentEvidenceRequest, IntentEvidenceResponse,
    MAX_PROVIDER_ATTESTATION_LIFETIME_SECONDS, PROVIDER_RESPONSE_ATTESTATION_SIGNATURE_DOMAIN,
    ProviderAuthenticationError, ProviderResponseAuthentication,
};
pub use record::{INTENT_CONFORMANCE_RECORD_SCHEMA_VERSION, IntentConformanceRecord};
pub use trace_builder::{
    ActionArtifact, AwaitingAction, AwaitingPlan, AwaitingResult, CompletedIntentTrace,
    IntentTraceBuilder, PlanArtifact, RequestArtifact, RequirementCommitment, ResultArtifact,
};

pub use accordlock_protocol::{CanonicalEncode, CanonicalError, Digest32, canonical_hash};
