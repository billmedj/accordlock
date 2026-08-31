use std::convert::Infallible;

use accordlock_protocol::{CanonicalEncode, CanonicalError, Digest32};
use minicbor::Encoder;
use minicbor::encode::Error as EncodeError;

use crate::material::{EXTERNAL_DISCLOSURE_GRANT_SIGNATURE_DOMAIN, ExternalDisclosureAttestation};
use crate::model::{
    ConformanceEvaluation, PolicyDecisionRecord, ResourceQuota, ResourceRequest,
    ResourceReservation, ScoreInterval, TaskRequirement, TransformationStep,
};
use crate::provider::{ProviderResponseAttestation, ProviderResponseBody};
use crate::{
    EvidenceDisclosurePolicy, EvidenceLedgerSnapshot, EvidenceProvenance, EvidenceTrustPolicy,
    IntentConformanceEvaluation, IntentConformanceRecord, IntentEvidence, IntentEvidenceRequest,
    IntentEvidenceResponse, IntentTrace, PreExecutionIntentTrace, ProviderResponseAuthentication,
};

/// Domain marker for canonical task requirements.
pub const TASK_REQUIREMENT_DOMAIN: &str = "accordlock:v2:task-requirement";
/// Domain marker for canonical workflow transformations.
pub const TRANSFORMATION_STEP_DOMAIN: &str = "accordlock:v2:transformation-step";
/// Domain marker for canonical conformance evaluations.
pub const CONFORMANCE_EVALUATION_DOMAIN: &str = "accordlock:v2:conformance-evaluation";
/// Domain marker for canonical request-to-result traces.
pub const INTENT_TRACE_DOMAIN: &str = "accordlock:v2:intent-trace";
/// Domain marker for canonical request-plan-action checkpoints.
pub const PRE_EXECUTION_INTENT_TRACE_DOMAIN: &str = "accordlock:v1:pre-execution-intent-trace";
/// Domain marker for canonical intent evidence.
pub const INTENT_EVIDENCE_DOMAIN: &str = "accordlock:v2:intent-evidence";
/// Domain marker for canonical evidence provenance tuples.
pub const EVIDENCE_PROVENANCE_DOMAIN: &str = "accordlock:v2:evidence-provenance";
/// Domain marker for canonical evidence trust policies.
pub const EVIDENCE_TRUST_POLICY_DOMAIN: &str = "accordlock:v2:evidence-trust-policy";
/// Domain marker for canonical evidence-ledger snapshots.
pub const EVIDENCE_LEDGER_SNAPSHOT_DOMAIN: &str = "accordlock:v2:evidence-ledger-snapshot";
/// Domain marker for canonical intent-conformance summaries.
pub const INTENT_CONFORMANCE_EVALUATION_DOMAIN: &str =
    "accordlock:v3:intent-conformance-evaluation";
/// Domain marker for externally serializable intent-conformance records.
pub const INTENT_CONFORMANCE_RECORD_DOMAIN: &str = "accordlock:v2:intent-conformance-record";
/// Domain marker for provider-neutral evidence requests.
pub const INTENT_EVIDENCE_REQUEST_DOMAIN: &str = "accordlock:v2:intent-evidence-request";
/// Domain marker for provider-neutral evidence responses.
pub const INTENT_EVIDENCE_RESPONSE_DOMAIN: &str = "accordlock:v2:intent-evidence-response";
/// Domain marker for the unsigned response body committed by an attestation.
pub const PROVIDER_RESPONSE_BODY_DOMAIN: &str = "accordlock:v1:provider-response-body";
/// Domain marker for the signed provider response attestation payload.
pub const PROVIDER_RESPONSE_ATTESTATION_DOMAIN: &str =
    "accordlock:v1:provider-response-attestation";
/// Domain marker for canonical resource requests.
pub const RESOURCE_REQUEST_DOMAIN: &str = "accordlock:v2:resource-request";
/// Domain marker for canonical resource quotas.
pub const RESOURCE_QUOTA_DOMAIN: &str = "accordlock:v2:resource-quota";
/// Domain marker for canonical resource reservations.
pub const RESOURCE_RESERVATION_DOMAIN: &str = "accordlock:v2:resource-reservation";
/// Domain marker for a complete canonical policy decision.
pub const POLICY_DECISION_DOMAIN: &str = "accordlock:v2:policy-decision";

type VecEncoder = Encoder<Vec<u8>>;
type VecEncodeError = EncodeError<Infallible>;

fn finish(result: Result<Vec<u8>, VecEncodeError>) -> Result<Vec<u8>, CanonicalError> {
    result.map_err(|error| CanonicalError::Encode(error.to_string()))
}

fn invalid(record: &'static str) -> CanonicalError {
    CanonicalError::InvalidValue(record)
}

fn encode_optional_digest(
    encoder: &mut VecEncoder,
    value: Option<Digest32>,
) -> Result<(), VecEncodeError> {
    if let Some(hash) = value {
        encoder.bytes(hash.as_bytes())?;
    } else {
        encoder.null()?;
    }
    Ok(())
}

fn encode_score(encoder: &mut VecEncoder, score: ScoreInterval) -> Result<(), VecEncodeError> {
    encoder.array(3)?;
    encoder.u32(score.lower().get())?;
    encoder.u32(score.estimate().get())?;
    encoder.u32(score.upper().get())?;
    Ok(())
}

fn encode_digests(encoder: &mut VecEncoder, values: &[Digest32]) -> Result<(), VecEncodeError> {
    encoder.array(u64::try_from(values.len()).unwrap_or(u64::MAX))?;
    for value in values {
        encoder.bytes(value.as_bytes())?;
    }
    Ok(())
}

impl CanonicalEncode for TaskRequirement {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| invalid("task requirement"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(6)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.requirement_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.statement_hash.as_bytes())?;
            encoder.u32(self.minimum_score.get())?;
            encoder.str(TASK_REQUIREMENT_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for TransformationStep {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("transformation step"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(11)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.step_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.u64(self.sequence)?;
            encode_optional_digest(&mut encoder, self.parent_step_hash)?;
            encoder.u8(self.source_stage.code())?;
            encoder.bytes(self.source_hash.as_bytes())?;
            encoder.u8(self.target_stage.code())?;
            encoder.bytes(self.target_hash.as_bytes())?;
            encoder.i64(self.recorded_at)?;
            encoder.str(TRANSFORMATION_STEP_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ConformanceEvaluation {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("conformance evaluation"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(13)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.conformance_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.u64(self.sequence)?;
            encode_optional_digest(&mut encoder, self.parent_evaluation_hash)?;
            encoder.bytes(self.requirement_hash.as_bytes())?;
            encoder.bytes(self.transformation_step_hash.as_bytes())?;
            encoder.u8(self.result.code())?;
            encode_score(&mut encoder, self.score)?;
            encoder.bytes(self.method_hash.as_bytes())?;
            encoder.bytes(self.evidence_hash.as_bytes())?;
            encoder.i64(self.evaluated_at)?;
            encoder.str(CONFORMANCE_EVALUATION_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for IntentTrace {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| invalid("intent trace"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(11)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.trace_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encode_digests(&mut encoder, &self.requirement_hashes)?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.bytes(self.plan_hash.as_bytes())?;
            encoder.bytes(self.action_hash.as_bytes())?;
            encoder.bytes(self.result_hash.as_bytes())?;
            encode_digests(&mut encoder, &self.transformation_step_hashes)?;
            encoder.i64(self.recorded_at)?;
            encoder.str(INTENT_TRACE_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for PreExecutionIntentTrace {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("pre-execution intent trace"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(10)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.trace_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encode_digests(&mut encoder, &self.requirement_hashes)?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.bytes(self.plan_hash.as_bytes())?;
            encoder.bytes(self.action_hash.as_bytes())?;
            encode_digests(&mut encoder, &self.transformation_step_hashes)?;
            encoder.i64(self.recorded_at)?;
            encoder.str(PRE_EXECUTION_INTENT_TRACE_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for IntentEvidence {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| invalid("intent evidence"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(21)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.evidence_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.trace_id.as_bytes())?;
            encoder.bytes(self.ledger_hash.as_bytes())?;
            encoder.u64(self.sequence)?;
            encode_optional_digest(&mut encoder, self.parent_evidence_hash)?;
            encoder.bytes(self.requirement_hash.as_bytes())?;
            encoder.u8(self.stage.code())?;
            encoder.bytes(self.subject_hash.as_bytes())?;
            encode_optional_digest(&mut encoder, self.transformation_step_hash)?;
            encoder.u8(self.verdict.code())?;
            encode_score(&mut encoder, self.confidence)?;
            encoder.u8(self.method_kind.code())?;
            encoder.bytes(self.method_hash.as_bytes())?;
            encoder.bytes(self.evaluator_hash.as_bytes())?;
            encoder.u8(self.calibration_status.code())?;
            encode_optional_digest(&mut encoder, self.calibration_hash)?;
            encoder.bytes(self.payload_hash.as_bytes())?;
            encoder.i64(self.observed_at)?;
            encoder.str(INTENT_EVIDENCE_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for EvidenceProvenance {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("evidence provenance"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(7)?;
            encoder.u16(self.schema_version)?;
            encoder.u8(self.method_kind.code())?;
            encoder.bytes(self.method_hash.as_bytes())?;
            encoder.bytes(self.evaluator_hash.as_bytes())?;
            encoder.u8(self.calibration_status.code())?;
            encode_optional_digest(&mut encoder, self.calibration_hash)?;
            encoder.str(EVIDENCE_PROVENANCE_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for EvidenceTrustPolicy {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("evidence trust policy"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(8)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.policy_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.u64(self.policy_epoch)?;
            encode_digests(&mut encoder, &self.trusted_provenance_hashes)?;
            encoder.i64(self.valid_from)?;
            encoder.i64(self.valid_until)?;
            encoder.str(EVIDENCE_TRUST_POLICY_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for EvidenceLedgerSnapshot {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("evidence ledger snapshot"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(11)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.snapshot_id.as_bytes())?;
            encoder.bytes(self.ledger_hash.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.trace_id.as_bytes())?;
            encoder.u64(self.epoch)?;
            encoder.u64(self.evidence_count)?;
            encode_optional_digest(&mut encoder, self.evidence_head)?;
            encoder.i64(self.captured_at)?;
            encoder.i64(self.valid_until)?;
            encoder.str(EVIDENCE_LEDGER_SNAPSHOT_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for IntentConformanceEvaluation {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("intent conformance evaluation"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(18)?;
            encoder.u16(self.schema_version)?;
            encoder.u8(self.profile.code())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.trace_hash.as_bytes())?;
            encoder.bytes(self.ledger_snapshot_hash.as_bytes())?;
            encoder.bytes(self.trust_policy_hash.as_bytes())?;
            encoder.bytes(self.expected_ledger_hash.as_bytes())?;
            encoder.u64(self.minimum_ledger_epoch)?;
            encoder.u64(self.minimum_trust_policy_epoch)?;
            encoder.i64(self.evaluated_at)?;
            encode_optional_digest(&mut encoder, self.evidence_head)?;
            encode_digests(&mut encoder, &self.evidence_hashes)?;
            encoder.u8(self.outcome.code())?;
            encoder.u8(self.policy_evaluation.baseline_decision().code())?;
            encoder.u8(self.policy_evaluation.decision().code())?;
            encoder
                .array(u64::try_from(self.policy_evaluation.reasons().len()).unwrap_or(u64::MAX))?;
            for reason in self.policy_evaluation.reasons() {
                encoder.u8(reason.code())?;
            }
            encoder.array(u64::try_from(self.findings.len()).unwrap_or(u64::MAX))?;
            for finding in &self.findings {
                encoder.array(4)?;
                encode_optional_digest(&mut encoder, finding.requirement_hash)?;
                if let Some(stage) = finding.stage {
                    encoder.u8(stage.code())?;
                } else {
                    encoder.null()?;
                }
                encode_optional_digest(&mut encoder, finding.evidence_hash)?;
                encoder.u8(finding.reason.code())?;
            }
            encoder.str(INTENT_CONFORMANCE_EVALUATION_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for IntentConformanceRecord {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("intent conformance record"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(20)?;
            encoder.u16(self.schema_version)?;
            encoder.u16(self.evaluation_schema_version)?;
            encoder.u8(self.profile.code())?;
            encoder.bytes(self.evaluation_hash.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.trace_hash.as_bytes())?;
            encoder.bytes(self.ledger_snapshot_hash.as_bytes())?;
            encoder.bytes(self.trust_policy_hash.as_bytes())?;
            encoder.bytes(self.expected_ledger_hash.as_bytes())?;
            encoder.u64(self.minimum_ledger_epoch)?;
            encoder.u64(self.minimum_trust_policy_epoch)?;
            encoder.i64(self.evaluated_at)?;
            encode_optional_digest(&mut encoder, self.evidence_head)?;
            encode_digests(&mut encoder, &self.evidence_hashes)?;
            encoder.u8(self.outcome.code())?;
            encoder.u8(self.baseline_decision.code())?;
            encoder.u8(self.decision.code())?;
            encoder.array(u64::try_from(self.reasons.len()).unwrap_or(u64::MAX))?;
            for reason in &self.reasons {
                encoder.u8(reason.code())?;
            }
            encoder.array(u64::try_from(self.findings.len()).unwrap_or(u64::MAX))?;
            for finding in &self.findings {
                encoder.array(4)?;
                encode_optional_digest(&mut encoder, finding.requirement_hash)?;
                if let Some(stage) = finding.stage {
                    encoder.u8(stage.code())?;
                } else {
                    encoder.null()?;
                }
                encode_optional_digest(&mut encoder, finding.evidence_hash)?;
                encoder.u8(finding.reason.code())?;
            }
            encoder.str(INTENT_CONFORMANCE_RECORD_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for IntentEvidenceRequest {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("intent evidence request"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(16)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.request_id.as_bytes())?;
            encoder.u8(self.evaluation_profile.code())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.trace_id.as_bytes())?;
            encoder.bytes(self.requirement_hash.as_bytes())?;
            encoder.u8(self.stage.code())?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.bytes(self.proposal_hash.as_bytes())?;
            encoder.bytes(self.context_hash.as_bytes())?;
            encoder.bytes(self.profile_hash.as_bytes())?;
            encoder.bytes(self.resolver_policy_hash.as_bytes())?;
            match &self.disclosure_policy {
                EvidenceDisclosurePolicy::LocalOnly => {
                    encoder.array(1)?;
                    encoder.u8(self.disclosure_policy.code())?;
                }
                EvidenceDisclosurePolicy::AllowlistedExternal {
                    provider_id_hash,
                    egress_policy_hash,
                    provider_trust_root,
                    egress_authority_root,
                } => {
                    encoder.array(5)?;
                    encoder.u8(self.disclosure_policy.code())?;
                    encoder.bytes(provider_id_hash.as_bytes())?;
                    encoder.bytes(egress_policy_hash.as_bytes())?;
                    encoder.bytes(provider_trust_root.as_bytes())?;
                    encoder.bytes(egress_authority_root.as_bytes())?;
                }
            }
            encoder.bytes(self.challenge_hash.as_bytes())?;
            encoder.i64(self.requested_at)?;
            encoder.str(INTENT_EVIDENCE_REQUEST_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ExternalDisclosureAttestation<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let grant = self.grant;
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(15)?;
            encoder.u16(grant.schema_version)?;
            encoder.bytes(grant.source_request_hash.as_bytes())?;
            encoder.bytes(grant.task_hash.as_bytes())?;
            encoder.bytes(grant.trace_id.as_bytes())?;
            encoder.u8(grant.evaluation_profile.code())?;
            encoder.u8(grant.stage.code())?;
            encoder.bytes(grant.provider_id_hash.as_bytes())?;
            encoder.bytes(grant.egress_policy_hash.as_bytes())?;
            encoder.bytes(grant.provider_trust_root.as_bytes())?;
            encoder.bytes(grant.challenge_hash.as_bytes())?;
            encoder.str(&grant.authority_key_id)?;
            encoder.bytes(grant.egress_authority_root.as_bytes())?;
            encoder.i64(grant.issued_at)?;
            encoder.i64(grant.valid_until)?;
            encoder.str(EXTERNAL_DISCLOSURE_GRANT_SIGNATURE_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for IntentEvidenceResponse {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("intent evidence response"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(11)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.response_id.as_bytes())?;
            encoder.bytes(self.source_request_hash.as_bytes())?;
            encoder.bytes(self.evidence_hash.as_bytes())?;
            encoder.bytes(self.provenance_hash.as_bytes())?;
            encoder.u8(self.calibration_status.code())?;
            encode_optional_digest(&mut encoder, self.calibration_hash)?;
            encoder.bytes(self.body_hash.as_bytes())?;
            encoder.i64(self.responded_at)?;
            match &self.authentication {
                ProviderResponseAuthentication::Local => {
                    encoder.array(1)?;
                    encoder.u8(0)?;
                }
                ProviderResponseAuthentication::External {
                    provider_key_id,
                    provider_trust_root,
                    challenge_hash,
                    issued_at,
                    valid_until,
                    cose_sign1,
                } => {
                    encoder.array(7)?;
                    encoder.u8(1)?;
                    encoder.str(provider_key_id)?;
                    encoder.bytes(provider_trust_root.as_bytes())?;
                    encoder.bytes(challenge_hash.as_bytes())?;
                    encoder.i64(*issued_at)?;
                    encoder.i64(*valid_until)?;
                    encoder.bytes(cose_sign1)?;
                }
            }
            encoder.str(INTENT_EVIDENCE_RESPONSE_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ProviderResponseBody {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(9)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.response_id.as_bytes())?;
            encoder.bytes(self.source_request_hash.as_bytes())?;
            encoder.bytes(self.evidence_hash.as_bytes())?;
            encoder.bytes(self.provenance_hash.as_bytes())?;
            encoder.u8(self.calibration_status.code())?;
            encode_optional_digest(&mut encoder, self.calibration_hash)?;
            encoder.i64(self.responded_at)?;
            encoder.str(PROVIDER_RESPONSE_BODY_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ProviderResponseAttestation {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(9)?;
            encoder.u16(self.schema_version)?;
            encoder.str(&self.provider_key_id)?;
            encoder.bytes(self.provider_trust_root.as_bytes())?;
            encoder.bytes(self.challenge_hash.as_bytes())?;
            encoder.bytes(self.source_request_hash.as_bytes())?;
            encoder.bytes(self.response_body_hash.as_bytes())?;
            encoder.i64(self.issued_at)?;
            encoder.i64(self.valid_until)?;
            encoder.str(PROVIDER_RESPONSE_ATTESTATION_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ResourceRequest {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| invalid("resource request"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(7)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.request_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.action_hash.as_bytes())?;
            encoder.str(&self.resource_kind)?;
            encoder.u64(self.units)?;
            encoder.str(RESOURCE_REQUEST_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ResourceQuota {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| invalid("resource quota"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(7)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.quota_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.str(&self.resource_kind)?;
            encoder.u64(self.limit)?;
            encoder.u64(self.policy_epoch)?;
            encoder.str(RESOURCE_QUOTA_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ResourceReservation {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate()
            .map_err(|_| invalid("resource reservation"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(15)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.reservation_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.bytes(self.quota_hash.as_bytes())?;
            encoder.str(&self.resource_kind)?;
            encoder.u64(self.units)?;
            encoder.u64(self.quota_units)?;
            encoder.u64(self.reserved_before)?;
            encoder.u64(self.reserved_through)?;
            encoder.u64(self.remaining_after)?;
            encoder.u64(self.sequence)?;
            encode_optional_digest(&mut encoder, self.parent_reservation_hash)?;
            encoder.i64(self.reserved_at)?;
            encoder.str(RESOURCE_RESERVATION_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for PolicyDecisionRecord {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| invalid("policy decision"))?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(18)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.decision_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.action_hash.as_bytes())?;
            encoder.u64(self.sequence)?;
            encode_optional_digest(&mut encoder, self.parent_decision_hash)?;
            encode_digests(&mut encoder, &self.requirement_hashes)?;
            encode_digests(&mut encoder, &self.transformation_step_hashes)?;
            encode_digests(&mut encoder, &self.conformance_evaluation_hashes)?;
            encode_digests(&mut encoder, &self.resource_request_hashes)?;
            encode_digests(&mut encoder, &self.resource_quota_hashes)?;
            encode_digests(&mut encoder, &self.resource_reservation_hashes)?;
            encoder.u8(self.baseline_decision.code())?;
            encoder.u8(self.decision.code())?;
            encoder.array(u64::try_from(self.reasons.len()).unwrap_or(u64::MAX))?;
            for reason in &self.reasons {
                encoder.u8(reason.code())?;
            }
            encoder.u64(self.policy_epoch)?;
            encoder.i64(self.evaluated_at)?;
            encoder.str(POLICY_DECISION_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}
