//! `PostgreSQL` implementation of the durable v13 control-plane boundary.
//!
//! This module stays separate from the legacy transactional adapter so the
//! v13 state machine has one auditable set of transaction/lock paths.

use std::str::FromStr as _;

use accordlock_ingress::{
    FrozenIngressVerifier, IngressRecoveryProbe, StaticallyVerifiedIngressSubmission,
    VerifiedHistoricalIngress,
};
use accordlock_protocol::{
    AuthorityVector, CanonicalEncode, CoseVerifier, DecisionOutcome, Digest32,
    EVALUATION_ATTESTATION_SCHEMA_VERSION, EVALUATION_DOMAIN, ReasonCode, SignedEvaluation,
    canonical_hash, evaluator_verifier_root, verify_cose,
};
use postgres::{GenericClient, IsolationLevel, Row, Transaction};
use uuid::Uuid;

use super::{
    ConsumeKey, ConsumeSuccess, ConsumptionReceipt, GrantRegistration, GrantSnapshot,
    IssuanceSnapshot, IssuedAuthorizationRecord, OutboxEntry, OutboxStatus, PostgresStore,
    SERIALIZATION_ATTEMPTS, Scope, StateError, TlsPostgresStore, decode_json,
    decode_stored_authorization_row, encode_json, is_retryable, is_temporal_rejection_for_sample,
    is_unique_violation, validate_consumption, validate_current_grant,
    validate_dispatch_immutable_facts, validate_grant_for_authorization,
    validate_postgres_control_consumption_lineage_if_owned, validate_recovered_consumption,
};
use crate::control::{
    CONTROL_WORK_LEASE_SECONDS, ClaimedControlWork, ControlConsumptionCommitOutcome,
    ControlConsumptionWork, ControlDecisionReason, ControlDecisionReceipt, ControlEvaluationWork,
    ControlIssuanceCommitOutcome, ControlIssuanceWork, ControlKernelOutcome, ControlOutcome,
    ControlPhaseCompletionReceipt, ControlPlaneState, ControlStatusCode, ControlStatusReason,
    ControlStatusSnapshot, ControlSubmissionIntakeOutcome, ControlSubmissionRecoveryKey,
    ControlWorkClaimOutcome, ControlWorkClaimRecoveryKey, ControlWorkClaimRequest,
    ControlWorkFinalizationReason, ControlWorkFinalizationReceipt, ControlWorkLease,
    ControlWorkPhase, ControlWorkerRole, RecoveredSubmissionRef, StoredControlDecision,
    StoredControlSubmission, control_decision_commitment, control_evaluation_commitment,
    control_event_commitment, derive_control_decision_id, derive_control_evaluation_id,
};
use crate::ingress_replay::IngressReplayScope;

fn parse_digest(value: &str, label: &str) -> Result<Digest32, StateError> {
    Digest32::from_str(value).map_err(|error| {
        StateError::InvalidRecord(format!("stored {label} digest is invalid: {error}"))
    })
}

fn fixed_public_key(bytes: Vec<u8>, label: &str) -> Result<[u8; 32], StateError> {
    bytes.try_into().map_err(|_| {
        StateError::InvalidRecord(format!("stored {label} public key is not 32 bytes"))
    })
}

fn phase_sql(phase: ControlWorkPhase) -> &'static str {
    match phase {
        ControlWorkPhase::Evaluate => "EVALUATE",
        ControlWorkPhase::Issue => "ISSUE",
        ControlWorkPhase::Consume => "CONSUME",
        ControlWorkPhase::Done => "DONE",
    }
}

fn parse_phase(value: &str) -> Result<ControlWorkPhase, StateError> {
    match value {
        "EVALUATE" => Ok(ControlWorkPhase::Evaluate),
        "ISSUE" => Ok(ControlWorkPhase::Issue),
        "CONSUME" => Ok(ControlWorkPhase::Consume),
        "DONE" => Ok(ControlWorkPhase::Done),
        _ => Err(StateError::InvalidRecord(format!(
            "unsupported control work phase {value}"
        ))),
    }
}

fn role_sql(role: ControlWorkerRole) -> &'static str {
    match role {
        ControlWorkerRole::Evaluator => "EVALUATOR",
        ControlWorkerRole::Issuer => "ISSUER",
        ControlWorkerRole::Consumer => "CONSUMER",
    }
}

fn parse_kernel_outcome(value: Option<&str>) -> Result<Option<ControlKernelOutcome>, StateError> {
    match value {
        None => Ok(None),
        Some("ALLOW") => Ok(Some(ControlKernelOutcome::Allow)),
        Some("DENY") => Ok(Some(ControlKernelOutcome::Deny)),
        Some(other) => Err(StateError::InvalidRecord(format!(
            "unsupported kernel outcome {other}"
        ))),
    }
}

fn control_outcome_sql(outcome: ControlOutcome) -> &'static str {
    match outcome {
        ControlOutcome::Allow => "ALLOW",
        ControlOutcome::Deny => "DENY",
        ControlOutcome::Manual => "MANUAL",
    }
}

fn parse_control_outcome(value: &str) -> Result<ControlOutcome, StateError> {
    match value {
        "ALLOW" => Ok(ControlOutcome::Allow),
        "DENY" => Ok(ControlOutcome::Deny),
        "MANUAL" => Ok(ControlOutcome::Manual),
        _ => Err(StateError::InvalidRecord(format!(
            "unsupported control outcome {value}"
        ))),
    }
}

fn decision_reason_sql(reason: ControlDecisionReason) -> &'static str {
    match reason {
        ControlDecisionReason::ControlAllow => "CONTROL_ALLOW",
        ControlDecisionReason::IngressExpired => "INGRESS_EXPIRED",
        ControlDecisionReason::AuthorityChanged => "AUTHORITY_CHANGED",
        ControlDecisionReason::KernelDeny => "KERNEL_DENY",
        ControlDecisionReason::GrantUnavailable => "GRANT_UNAVAILABLE",
        ControlDecisionReason::GrantAmbiguous => "GRANT_AMBIGUOUS",
    }
}

fn parse_decision_reason(value: &str) -> Result<ControlDecisionReason, StateError> {
    match value {
        "CONTROL_ALLOW" => Ok(ControlDecisionReason::ControlAllow),
        "INGRESS_EXPIRED" => Ok(ControlDecisionReason::IngressExpired),
        "AUTHORITY_CHANGED" => Ok(ControlDecisionReason::AuthorityChanged),
        "KERNEL_DENY" => Ok(ControlDecisionReason::KernelDeny),
        "GRANT_UNAVAILABLE" => Ok(ControlDecisionReason::GrantUnavailable),
        "GRANT_AMBIGUOUS" => Ok(ControlDecisionReason::GrantAmbiguous),
        _ => Err(StateError::InvalidRecord(format!(
            "unsupported control decision reason {value}"
        ))),
    }
}

fn finalization_reason_sql(reason: ControlWorkFinalizationReason) -> &'static str {
    match reason {
        ControlWorkFinalizationReason::IngressExpired => "INGRESS_EXPIRED",
        ControlWorkFinalizationReason::AuthorityChanged => "AUTHORITY_CHANGED",
        ControlWorkFinalizationReason::GrantUnavailable => "GRANT_UNAVAILABLE",
        ControlWorkFinalizationReason::AuthorizationExpired => "AUTHORIZATION_EXPIRED",
        ControlWorkFinalizationReason::DispatchWindowExpired => "DISPATCH_WINDOW_EXPIRED",
    }
}

fn parse_finalization_reason(value: &str) -> Result<ControlWorkFinalizationReason, StateError> {
    match value {
        "INGRESS_EXPIRED" => Ok(ControlWorkFinalizationReason::IngressExpired),
        "AUTHORITY_CHANGED" => Ok(ControlWorkFinalizationReason::AuthorityChanged),
        "GRANT_UNAVAILABLE" => Ok(ControlWorkFinalizationReason::GrantUnavailable),
        "AUTHORIZATION_EXPIRED" => Ok(ControlWorkFinalizationReason::AuthorizationExpired),
        "DISPATCH_WINDOW_EXPIRED" => Ok(ControlWorkFinalizationReason::DispatchWindowExpired),
        _ => Err(StateError::InvalidRecord(format!(
            "unsupported control finalization reason {value}"
        ))),
    }
}

fn status_sql(status: ControlStatusCode) -> &'static str {
    match status {
        ControlStatusCode::Accepted => "ACCEPTED",
        ControlStatusCode::Authorized => "AUTHORIZED",
        ControlStatusCode::ControlDenied => "CONTROL_DENIED",
        ControlStatusCode::ManualResolutionRequired => "MANUAL_RESOLUTION_REQUIRED",
        ControlStatusCode::AuthorizationIssued => "AUTHORIZATION_ISSUED",
        ControlStatusCode::DispatchPending => "DISPATCH_PENDING",
        ControlStatusCode::FailedClosed => "FAILED_CLOSED",
    }
}

fn parse_status(value: &str) -> Result<ControlStatusCode, StateError> {
    match value {
        "ACCEPTED" => Ok(ControlStatusCode::Accepted),
        "AUTHORIZED" => Ok(ControlStatusCode::Authorized),
        "CONTROL_DENIED" => Ok(ControlStatusCode::ControlDenied),
        "AUTHORIZATION_ISSUED" => Ok(ControlStatusCode::AuthorizationIssued),
        "DISPATCH_PENDING" => Ok(ControlStatusCode::DispatchPending),
        "FAILED_CLOSED" => Ok(ControlStatusCode::FailedClosed),
        _ => Err(StateError::InvalidRecord(format!(
            "unsupported control status {value}"
        ))),
    }
}

fn status_reason_columns(
    reason: Option<ControlStatusReason>,
) -> (Option<&'static str>, Option<&'static str>) {
    match reason {
        None => (None, None),
        Some(ControlStatusReason::Decision(reason)) => {
            (Some("DECISION"), Some(decision_reason_sql(reason)))
        }
        Some(ControlStatusReason::Finalization(reason)) => {
            (Some("FINALIZATION"), Some(finalization_reason_sql(reason)))
        }
    }
}

fn parse_status_reason(
    kind: Option<&str>,
    code: Option<&str>,
) -> Result<Option<ControlStatusReason>, StateError> {
    match (kind, code) {
        (None, None) => Ok(None),
        (Some("DECISION"), Some(code)) => Ok(Some(ControlStatusReason::Decision(
            parse_decision_reason(code)?,
        ))),
        (Some("FINALIZATION"), Some(code)) => Ok(Some(ControlStatusReason::Finalization(
            parse_finalization_reason(code)?,
        ))),
        _ => Err(StateError::InvalidRecord(
            "stored control status reason columns disagree".to_owned(),
        )),
    }
}

fn submission_from_row(row: &Row) -> Result<StoredControlSubmission, StateError> {
    let stored = StoredControlSubmission {
        state_instance_id: row.get("state_instance_id"),
        submission_id: row.get("submission_id"),
        receipt_id: row.get("receipt_id"),
        evaluation_nonce: row.get("evaluation_nonce"),
        replay_scope: row.get("replay_scope"),
        key_id: row.get("key_id"),
        nonce: row.get("nonce"),
        canonical_payload_commitment: parse_digest(
            row.get("canonical_payload_commitment"),
            "payload",
        )?,
        first_wire_commitment: parse_digest(row.get("first_wire_commitment"), "wire")?,
        first_wire_json: row.get("first_wire_json"),
        canonical_claims: row.get("canonical_claims"),
        cose_sign1: row.get("cose_sign1"),
        proposal: decode_json(row.get("proposal_json"))?,
        proposal_commitment: parse_digest(row.get("proposal_commitment"), "proposal")?,
        tenant: row.get("tenant"),
        environment: row.get("environment"),
        actor: row.get("actor"),
        audience: row.get("audience"),
        ingress_issued_at: row.get("ingress_issued_at"),
        ingress_expires_at: row.get("ingress_expires_at"),
        accepted_at: row.get("accepted_at"),
        key_public_key: fixed_public_key(row.get("key_public_key"), "ingress")?,
        key_not_before: row.get("key_not_before"),
        key_expires_at: row.get("key_expires_at"),
        maximum_lifetime_seconds: row.get("maximum_lifetime_seconds"),
        ingress_authority_domain: decode_json(row.get("ingress_authority_json"))?,
    };
    stored.validate()?;
    if row.get::<_, Uuid>("request_id") != stored.proposal.request_id {
        return Err(StateError::InvalidRecord(
            "stored control request_id column disagrees with proposal JSON".to_owned(),
        ));
    }
    Ok(stored)
}

const SUBMISSION_COLUMNS: &str = "submission_id, receipt_id, state_instance_id, replay_scope, key_id, nonce, \
     canonical_payload_commitment, first_wire_commitment, first_wire_json, canonical_claims, \
     cose_sign1, proposal_json, proposal_commitment, request_id, tenant, environment, \
     actor, audience, ingress_issued_at, ingress_expires_at, accepted_at, key_public_key, \
     key_not_before, key_expires_at, maximum_lifetime_seconds, ingress_authority_json, \
     evaluation_nonce";

fn load_submission_by_payload_commitment<C: GenericClient>(
    client: &mut C,
    payload: Digest32,
) -> Result<Option<StoredControlSubmission>, StateError> {
    let sql = format!(
        "SELECT {SUBMISSION_COLUMNS} FROM public.accordlock_control_submissions \
          WHERE canonical_payload_commitment = $1"
    );
    client
        .query_opt(&sql, &[&payload.to_string()])?
        .map(|row| submission_from_row(&row))
        .transpose()
}

pub(super) fn load_submission_for_update(
    transaction: &mut Transaction<'_>,
    submission_id: Uuid,
) -> Result<StoredControlSubmission, StateError> {
    let sql = format!(
        "SELECT {SUBMISSION_COLUMNS} FROM public.accordlock_control_submissions \
          WHERE submission_id = $1 FOR NO KEY UPDATE"
    );
    let row = transaction
        .query_opt(&sql, &[&submission_id])?
        .ok_or(StateError::ControlSubmissionNotFound)?;
    submission_from_row(&row)
}

fn status_from_row(row: &Row) -> Result<ControlStatusSnapshot, StateError> {
    let revision_i64: i64 = row.get("revision");
    let revision = u64::try_from(revision_i64).map_err(|_| {
        StateError::InvalidRecord("control status revision is not representable".to_owned())
    })?;
    let kind: Option<String> = row.get("reason_kind");
    let code: Option<String> = row.get("reason_code");
    Ok(ControlStatusSnapshot::new(
        row.get("submission_id"),
        row.get("receipt_id"),
        parse_status(row.get::<_, String>("status").as_str())?,
        parse_status_reason(kind.as_deref(), code.as_deref())?,
        revision,
        row.get("observed_at"),
    ))
}

fn load_status<C: GenericClient>(
    client: &mut C,
    submission_id: Uuid,
) -> Result<ControlStatusSnapshot, StateError> {
    let row = client
        .query_opt(
            "SELECT submission_id, receipt_id, status, reason_kind, reason_code,
                    revision, observed_at
               FROM public.accordlock_control_status
              WHERE submission_id = $1",
            &[&submission_id],
        )?
        .ok_or(StateError::ControlStatusNotFound)?;
    status_from_row(&row)
}

fn validate_current_status_event<C: GenericClient>(
    client: &mut C,
    status: &ControlStatusSnapshot,
) -> Result<(), StateError> {
    let revision = i64::try_from(status.revision()).map_err(|_| {
        StateError::InvalidRecord("control status revision is not representable".to_owned())
    })?;
    let row = client
        .query_opt(
            "SELECT receipt_id,status,reason_kind,reason_code,observed_at,event_commitment
               FROM public.accordlock_control_events
              WHERE submission_id=$1 AND revision=$2",
            &[&status.submission_id(), &revision],
        )?
        .ok_or_else(|| {
            StateError::InvalidRecord("control status lacks its exact current event".to_owned())
        })?;
    let reason_kind: Option<String> = row.get("reason_kind");
    let reason_code: Option<String> = row.get("reason_code");
    let event_commitment = parse_digest(row.get("event_commitment"), "control event")?;
    if row.get::<_, Uuid>("receipt_id") != status.receipt_id()
        || parse_status(row.get::<_, String>("status").as_str())? != status.status()
        || parse_status_reason(reason_kind.as_deref(), reason_code.as_deref())? != status.reason()
        || row.get::<_, i64>("observed_at") != status.observed_at()
        || event_commitment != control_event_commitment(status)?
    {
        return Err(StateError::InvalidRecord(
            "control status and current event disagree".to_owned(),
        ));
    }
    Ok(())
}

fn validate_control_event_chain<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
) -> Result<(ControlStatusSnapshot, Vec<ControlStatusSnapshot>), StateError> {
    let current = load_status(client, stored.submission_id)?;
    validate_current_status_event(client, &current)?;
    let rows = client.query(
        "SELECT submission_id,receipt_id,status,reason_kind,reason_code,
                revision,observed_at,event_commitment
           FROM public.accordlock_control_events
          WHERE submission_id=$1
          ORDER BY revision",
        &[&stored.submission_id],
    )?;
    let expected_len = usize::try_from(current.revision()).map_err(|_| {
        StateError::InvalidRecord("control event revision is not representable".to_owned())
    })?;
    if rows.len() != expected_len || rows.is_empty() {
        return Err(StateError::InvalidRecord(
            "control event history is not gapless through the current projection".to_owned(),
        ));
    }
    let mut events = Vec::with_capacity(rows.len());
    let mut prior: Option<ControlStatusSnapshot> = None;
    for (offset, row) in rows.iter().enumerate() {
        let event = status_from_row(row)?;
        let expected_revision = u64::try_from(offset + 1)
            .map_err(|_| StateError::InvalidRecord("control event revision overflow".to_owned()))?;
        let commitment = parse_digest(row.get("event_commitment"), "control event")?;
        let transition_valid = prior.as_ref().is_none_or(|prior| {
            matches!(
                (prior.status(), event.status()),
                (
                    ControlStatusCode::Accepted,
                    ControlStatusCode::Authorized | ControlStatusCode::ControlDenied
                ) | (
                    ControlStatusCode::Authorized,
                    ControlStatusCode::AuthorizationIssued | ControlStatusCode::FailedClosed
                ) | (
                    ControlStatusCode::AuthorizationIssued,
                    ControlStatusCode::DispatchPending | ControlStatusCode::FailedClosed
                )
            ) && event.observed_at() >= prior.observed_at()
        });
        if event.submission_id() != stored.submission_id
            || event.receipt_id() != stored.receipt_id
            || event.revision() != expected_revision
            || commitment != control_event_commitment(&event)?
            || !transition_valid
            || (expected_revision == 1
                && (event.status() != ControlStatusCode::Accepted
                    || event.reason().is_some()
                    || event.observed_at() != stored.accepted_at))
        {
            return Err(StateError::InvalidRecord(
                "control event history has invalid identity, ordering, or commitment".to_owned(),
            ));
        }
        prior = Some(event.clone());
        events.push(event);
    }
    if events.last() != Some(&current) {
        return Err(StateError::InvalidRecord(
            "control status is not the last exact committed event".to_owned(),
        ));
    }
    Ok((current, events))
}

fn recovered_submission<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
) -> Result<RecoveredSubmissionRef, StateError> {
    stored.reverify_frozen_wire()?;
    let (status, _) = validate_control_event_chain(client, stored)?;
    if status.receipt_id() != stored.receipt_id || status.submission_id() != stored.submission_id {
        return Err(StateError::ControlSubmissionMismatch);
    }
    let queue = client
        .query_opt(
            "SELECT phase,state,active_claim_id
               FROM public.accordlock_control_work_queue
              WHERE submission_id=$1",
            &[&stored.submission_id],
        )?
        .ok_or_else(|| {
            StateError::InvalidRecord("control submission lacks its work projection".to_owned())
        })?;
    let phase: String = queue.get("phase");
    let state: String = queue.get("state");
    let active_claim: Option<Uuid> = queue.get("active_claim_id");
    let queue_matches = match status.status() {
        ControlStatusCode::Accepted => {
            phase == "EVALUATE" && matches!(state.as_str(), "READY" | "LEASED")
        }
        ControlStatusCode::Authorized => {
            phase == "ISSUE" && matches!(state.as_str(), "READY" | "LEASED")
        }
        ControlStatusCode::AuthorizationIssued => {
            phase == "CONSUME" && matches!(state.as_str(), "READY" | "LEASED")
        }
        ControlStatusCode::ControlDenied
        | ControlStatusCode::DispatchPending
        | ControlStatusCode::FailedClosed => {
            phase == "DONE" && state == "DONE" && active_claim.is_none()
        }
        ControlStatusCode::ManualResolutionRequired => false,
    };
    if !queue_matches
        || (state == "READY" && active_claim.is_some())
        || (state == "LEASED" && active_claim.is_none())
    {
        return Err(StateError::InvalidRecord(
            "control submission status and work projection disagree".to_owned(),
        ));
    }
    if state == "LEASED" {
        let active_claim_id = active_claim.ok_or_else(|| {
            StateError::InvalidRecord("leased control projection lacks its claim".to_owned())
        })?;
        let claim = client
            .query_opt(
                "SELECT submission_id,phase,role
                   FROM public.accordlock_control_work_claims
                  WHERE claim_id=$1",
                &[&active_claim_id],
            )?
            .ok_or_else(|| {
                StateError::InvalidRecord("leased control projection claim disappeared".to_owned())
            })?;
        let expected_role = match phase.as_str() {
            "EVALUATE" => "EVALUATOR",
            "ISSUE" => "ISSUER",
            "CONSUME" => "CONSUMER",
            _ => {
                return Err(StateError::InvalidRecord(
                    "terminal control projection cannot be leased".to_owned(),
                ));
            }
        };
        if claim.get::<_, Uuid>("submission_id") != stored.submission_id
            || claim.get::<_, String>("phase") != phase
            || claim.get::<_, String>("role") != expected_role
        {
            return Err(StateError::InvalidRecord(
                "leased control projection does not name its exact phase claim".to_owned(),
            ));
        }
    }
    validate_current_control_lineage(client, stored, &status)?;
    Ok(RecoveredSubmissionRef::new(
        stored.receipt(),
        status.status(),
        status.revision(),
    ))
}

fn insert_or_advance_control_status(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    status: ControlStatusCode,
    reason: Option<ControlStatusReason>,
    observed_at: i64,
) -> Result<ControlStatusSnapshot, StateError> {
    let prior = transaction.query_opt(
        "SELECT submission_id, receipt_id, status, reason_kind, reason_code,
                revision, observed_at
           FROM public.accordlock_control_status
          WHERE submission_id = $1
          FOR UPDATE",
        &[&stored.submission_id],
    )?;
    let revision = prior
        .as_ref()
        .map_or(1_i64, |row| row.get::<_, i64>("revision") + 1);
    let snapshot = ControlStatusSnapshot::new(
        stored.submission_id,
        stored.receipt_id,
        status,
        reason,
        u64::try_from(revision).map_err(|_| {
            StateError::InvalidRecord("control status revision overflow".to_owned())
        })?,
        observed_at,
    );
    let commitment = control_event_commitment(&snapshot)?.to_string();
    let (reason_kind, reason_code) = status_reason_columns(reason);
    transaction.execute(
        "INSERT INTO public.accordlock_control_events
                    (submission_id, revision, receipt_id, status, reason_kind,
                     reason_code, observed_at, event_commitment)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        &[
            &stored.submission_id,
            &revision,
            &stored.receipt_id,
            &status_sql(status),
            &reason_kind,
            &reason_code,
            &observed_at,
            &commitment,
        ],
    )?;
    if prior.is_some() {
        let updated = transaction.execute(
            "UPDATE public.accordlock_control_status
                SET status=$2, reason_kind=$3, reason_code=$4, revision=$5,
                    observed_at=$6, updated_at=clock_timestamp()
              WHERE submission_id=$1",
            &[
                &stored.submission_id,
                &status_sql(status),
                &reason_kind,
                &reason_code,
                &revision,
                &observed_at,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::RetryableConflict);
        }
    } else {
        transaction.execute(
            "INSERT INTO public.accordlock_control_status
                    (submission_id,receipt_id,tenant,environment,status,
                     reason_kind,reason_code,revision,observed_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &stored.submission_id,
                &stored.receipt_id,
                &stored.tenant,
                &stored.environment,
                &status_sql(status),
                &reason_kind,
                &reason_code,
                &revision,
                &observed_at,
            ],
        )?;
    }
    Ok(snapshot)
}

fn update_scope_high_water(
    transaction: &mut Transaction<'_>,
    scope: &Scope,
    observed: i64,
) -> Result<(), StateError> {
    let updated = transaction.execute(
        "UPDATE public.accordlock_time_high_water
            SET observed_unix_s=$3, updated_at=clock_timestamp()
          WHERE tenant=$1 AND environment=$2 AND observed_unix_s <= $3",
        &[&scope.tenant, &scope.environment, &observed],
    )?;
    if updated != 1 {
        return Err(StateError::ClockRollback {
            observed,
            high_water: PostgresStore::lock_or_create_high_water(transaction, scope)?,
        });
    }
    Ok(())
}

fn insert_submission(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
) -> Result<(), StateError> {
    let proposal_json = encode_json(&stored.proposal)?;
    let authority_json = encode_json(&stored.ingress_authority_domain)?;
    transaction.execute(
        "INSERT INTO public.accordlock_control_submissions
                    (submission_id,receipt_id,state_instance_id,replay_scope,key_id,nonce,
                     canonical_payload_commitment,first_wire_commitment,first_wire_json,
                     canonical_claims,cose_sign1,proposal_json,proposal_commitment,
                     request_id,tenant,environment,actor,audience,ingress_issued_at,
                     ingress_expires_at,accepted_at,key_public_key,key_not_before,
                     key_expires_at,maximum_lifetime_seconds,ingress_authority_json,
                     evaluation_nonce)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                     $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)",
        &[
            &stored.submission_id,
            &stored.receipt_id,
            &stored.state_instance_id,
            &stored.replay_scope,
            &stored.key_id,
            &stored.nonce,
            &stored.canonical_payload_commitment.to_string(),
            &stored.first_wire_commitment.to_string(),
            &stored.first_wire_json,
            &stored.canonical_claims,
            &stored.cose_sign1,
            &proposal_json,
            &stored.proposal_commitment.to_string(),
            &stored.proposal.request_id,
            &stored.tenant,
            &stored.environment,
            &stored.actor,
            &stored.audience,
            &stored.ingress_issued_at,
            &stored.ingress_expires_at,
            &stored.accepted_at,
            &&stored.key_public_key[..],
            &stored.key_not_before,
            &stored.key_expires_at,
            &stored.maximum_lifetime_seconds,
            &authority_json,
            &stored.evaluation_nonce,
        ],
    )?;
    Ok(())
}

impl PostgresStore {
    #[allow(clippy::too_many_lines)]
    fn accept_control_submission_once(
        &self,
        verified: &StaticallyVerifiedIngressSubmission,
    ) -> Result<ControlSubmissionIntakeOutcome, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        if let Some(stored) = load_submission_by_payload_commitment(
            &mut transaction,
            verified.canonical_payload_commitment(),
        )? {
            if stored.key_id != verified.key_id()
                || stored.nonce != verified.nonce()
                || stored.proposal != *verified.proposal()
            {
                return Err(StateError::ControlSubmissionMismatch);
            }
            let recovered = recovered_submission(&mut transaction, &stored)?;
            transaction.commit()?;
            return Ok(ControlSubmissionIntakeOutcome::Recovered(recovered));
        }

        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let scope = Scope::new(
            verified.caller().tenant(),
            &verified.proposal().template.environment,
        )?;
        let active_row = transaction
            .query_opt(
                "SELECT authority_json
                   FROM public.accordlock_authority_state
                  WHERE tenant=$1 AND environment=$2
                  FOR SHARE",
                &[&scope.tenant, &scope.environment],
            )?
            .ok_or(StateError::AuthorityNotInitialized)?;
        let active: AuthorityVector = decode_json(active_row.get("authority_json"))?;
        if &active.principal_registry != verified.authority_domain() {
            return Err(StateError::AuthorityMismatch);
        }

        let prospective_evaluation_nonce =
            StoredControlSubmission::prospective_evaluation_nonce(state_instance_id, verified);
        if transaction
            .query_opt(
                "SELECT 1
                   FROM public.accordlock_control_submissions
                  WHERE (tenant=$1 AND environment=$2 AND request_id=$3)
                     OR evaluation_nonce=$4
                  FOR SHARE",
                &[
                    &scope.tenant,
                    &scope.environment,
                    &verified.proposal().request_id,
                    &prospective_evaluation_nonce,
                ],
            )?
            .is_some()
            || transaction
                .query_opt(
                    "SELECT 1
                       FROM public.accordlock_issued_authorizations
                      WHERE issuance_profile_version=2
                        AND ((tenant=$1 AND environment=$2 AND request_id=$3)
                             OR evaluation_nonce=$4)
                      FOR SHARE",
                    &[
                        &scope.tenant,
                        &scope.environment,
                        &verified.proposal().request_id,
                        &prospective_evaluation_nonce,
                    ],
                )?
                .is_some()
        {
            return Err(StateError::ControlRequestConflict);
        }

        let replay_scope = IngressReplayScope::new(verified.replay_scope().as_str())?;
        let (_, ingress_high_water) =
            Self::lock_or_create_ingress_scope(&mut transaction, &replay_scope)?;
        let scope_high_water = Self::lock_or_create_high_water(&mut transaction, &scope)?;
        let observed = Self::sample_trusted_time(&mut transaction)?;
        let high_water = ingress_high_water.max(scope_high_water);
        if observed < high_water {
            return Err(StateError::ClockRollback {
                observed,
                high_water,
            });
        }
        let temporal_error =
            if observed < verified.key_not_before() || observed >= verified.key_expires_at() {
                Some(StateError::ControlIngressKeyNotCurrent { observed })
            } else if observed < verified.claims().issued_at {
                Some(StateError::ControlIngressNotYetValid {
                    observed,
                    not_before: verified.claims().issued_at,
                })
            } else if observed >= verified.expires_at() {
                Some(StateError::ControlIngressExpired {
                    observed,
                    expires_at: verified.expires_at(),
                })
            } else {
                None
            };
        if let Some(error) = temporal_error {
            Self::advance_ingress_high_water(
                &mut transaction,
                &replay_scope,
                observed,
                ingress_high_water,
            )?;
            update_scope_high_water(&mut transaction, &scope, observed)?;
            transaction.commit()?;
            return Err(error);
        }

        let nonce_row = transaction.query_opt(
            "SELECT nonce.expires_unix_s,
                    EXISTS (
                        SELECT 1 FROM public.accordlock_control_submissions AS submission
                         WHERE submission.replay_scope=nonce.replay_scope
                           AND submission.key_id=nonce.key_id
                           AND submission.nonce=nonce.nonce
                    ) AS control_owned
               FROM public.accordlock_ingress_replay_nonces AS nonce
              WHERE nonce.replay_scope=$1 AND nonce.key_id=$2 AND nonce.nonce=$3
              FOR UPDATE",
            &[
                &replay_scope.as_str(),
                &verified.key_id(),
                &verified.nonce(),
            ],
        )?;
        if nonce_row.as_ref().is_some_and(|row| {
            row.get::<_, bool>("control_owned") || row.get::<_, i64>("expires_unix_s") > observed
        }) {
            Self::advance_ingress_high_water(
                &mut transaction,
                &replay_scope,
                observed,
                ingress_high_water,
            )?;
            update_scope_high_water(&mut transaction, &scope, observed)?;
            transaction.commit()?;
            return Err(StateError::ControlNonceAlreadyUsed);
        }

        let stored = StoredControlSubmission::from_verified(state_instance_id, verified, observed)?;
        if stored.evaluation_nonce != prospective_evaluation_nonce {
            return Err(StateError::ControlSubmissionMismatch);
        }
        Self::advance_ingress_high_water(
            &mut transaction,
            &replay_scope,
            observed,
            ingress_high_water,
        )?;
        update_scope_high_water(&mut transaction, &scope, observed)?;
        if nonce_row.is_some() {
            let updated = transaction.execute(
                "UPDATE public.accordlock_ingress_replay_nonces
                    SET state_instance_id=$4, expires_unix_s=$5, consumed_unix_s=$6,
                        updated_at=clock_timestamp()
                  WHERE replay_scope=$1 AND key_id=$2 AND nonce=$3",
                &[
                    &replay_scope.as_str(),
                    &stored.key_id,
                    &stored.nonce,
                    &state_instance_id,
                    &stored.ingress_expires_at,
                    &observed,
                ],
            )?;
            if updated != 1 {
                return Err(StateError::RetryableConflict);
            }
        } else {
            transaction.execute(
                "INSERT INTO public.accordlock_ingress_replay_nonces
                        (replay_scope,state_instance_id,key_id,nonce,
                         expires_unix_s,consumed_unix_s)
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &replay_scope.as_str(),
                    &state_instance_id,
                    &stored.key_id,
                    &stored.nonce,
                    &stored.ingress_expires_at,
                    &observed,
                ],
            )?;
        }
        insert_submission(&mut transaction, &stored)?;
        insert_or_advance_control_status(
            &mut transaction,
            &stored,
            ControlStatusCode::Accepted,
            None,
            observed,
        )?;
        transaction.execute(
            "INSERT INTO public.accordlock_control_work_queue
                    (submission_id,phase,state,active_claim_id)
             VALUES ($1,'EVALUATE','READY',NULL)",
            &[&stored.submission_id],
        )?;
        let receipt = stored.receipt();
        let recovery_key = stored.recovery_key();
        match transaction.commit() {
            Ok(()) => Ok(ControlSubmissionIntakeOutcome::Fresh(receipt)),
            Err(_) => Ok(ControlSubmissionIntakeOutcome::OutcomeUnknown(recovery_key)),
        }
    }
}

impl ControlPlaneState for PostgresStore {
    fn control_recovery_verifier(
        &self,
        probe: &IngressRecoveryProbe,
    ) -> Result<Option<FrozenIngressVerifier>, StateError> {
        let mut client = self.connect()?;
        let Some(stored) = load_submission_by_payload_commitment(
            &mut client,
            probe.canonical_payload_commitment(),
        )?
        else {
            return Ok(None);
        };
        stored.reverify_frozen_wire()?;
        if probe.key_id() != stored.key_id
            || probe.claims().nonce != stored.nonce
            || probe.claims().proposal != stored.proposal
            || probe.claims().issued_at != stored.ingress_issued_at
            || probe.claims().expires_at != stored.ingress_expires_at
            || probe.claims().audience != stored.audience
        {
            return Err(StateError::ControlSubmissionMismatch);
        }
        stored.frozen_verifier().map(Some)
    }

    fn recover_control_submission(
        &self,
        verified: &VerifiedHistoricalIngress,
    ) -> Result<RecoveredSubmissionRef, StateError> {
        let mut client = self.connect()?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let stored = load_submission_by_payload_commitment(
            &mut transaction,
            verified.canonical_payload_commitment(),
        )?
        .ok_or(StateError::ControlSubmissionNotFound)?;
        stored.matches_historical(verified)?;
        let recovered = recovered_submission(&mut transaction, &stored)?;
        transaction.commit()?;
        Ok(recovered)
    }

    fn accept_control_submission_or_recover(
        &self,
        verified: StaticallyVerifiedIngressSubmission,
    ) -> Result<ControlSubmissionIntakeOutcome, StateError> {
        let recovery_key = ControlSubmissionRecoveryKey::new(
            verified.replay_scope().as_str().to_owned(),
            verified.key_id().to_owned(),
            verified.nonce(),
            verified.canonical_payload_commitment(),
        );
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.accept_control_submission_once(&verified) {
                Err(StateError::Database(error))
                    if is_retryable(&error) || is_unique_violation(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Ok(ControlSubmissionIntakeOutcome::OutcomeUnknown(recovery_key));
                    }
                }
                Err(StateError::Database(_)) => {
                    return Ok(ControlSubmissionIntakeOutcome::OutcomeUnknown(recovery_key));
                }
                result => return result,
            }
        }
        Ok(ControlSubmissionIntakeOutcome::OutcomeUnknown(recovery_key))
    }

    fn claim_next_control_work_or_recover(
        &self,
        request: &ControlWorkClaimRequest,
    ) -> Result<ControlWorkClaimOutcome, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.claim_control_work_once(request) {
                Err(StateError::RetryableConflict) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Ok(ControlWorkClaimOutcome::OutcomeUnknown(
                            ControlWorkClaimRecoveryKey::from_request(request),
                        ));
                    }
                }
                Err(StateError::Database(error))
                    if is_retryable(&error) || is_unique_violation(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Ok(ControlWorkClaimOutcome::OutcomeUnknown(
                            ControlWorkClaimRecoveryKey::from_request(request),
                        ));
                    }
                }
                Err(StateError::Database(_)) => {
                    return Ok(ControlWorkClaimOutcome::OutcomeUnknown(
                        ControlWorkClaimRecoveryKey::from_request(request),
                    ));
                }
                result => return result,
            }
        }
        Ok(ControlWorkClaimOutcome::OutcomeUnknown(
            ControlWorkClaimRecoveryKey::from_request(request),
        ))
    }

    fn record_control_evaluation(
        &self,
        work: ControlEvaluationWork,
        signed_evaluation: &SignedEvaluation,
        evaluator: &CoseVerifier,
    ) -> Result<ControlDecisionReceipt, StateError> {
        self.record_control_evaluation_once(work, signed_evaluation, evaluator)
    }

    fn control_issuance_snapshot(
        &self,
        work: &ControlIssuanceWork,
    ) -> Result<IssuanceSnapshot, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.control_issuance_snapshot_once(work) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn record_and_link_control_issuance_or_recover(
        &self,
        work: ControlIssuanceWork,
        issued: &IssuedAuthorizationRecord,
    ) -> Result<ControlIssuanceCommitOutcome, StateError> {
        let submission_id = work.lease.submission_id;
        match self.record_and_link_control_issuance_once(work, issued) {
            Err(StateError::Database(error))
                if is_retryable(&error) || is_unique_violation(&error) =>
            {
                Ok(ControlIssuanceCommitOutcome::OutcomeUnknown { submission_id })
            }
            Err(StateError::RetryableConflict | StateError::AuthorizationAlreadyExists) => {
                Ok(ControlIssuanceCommitOutcome::OutcomeUnknown { submission_id })
            }
            result => result,
        }
    }

    fn consume_and_link_control_or_recover(
        &self,
        work: ControlConsumptionWork,
    ) -> Result<ControlConsumptionCommitOutcome, StateError> {
        let submission_id = work.lease.submission_id;
        match self.consume_and_link_control_once(work) {
            Err(StateError::Database(error))
                if is_retryable(&error) || is_unique_violation(&error) =>
            {
                Ok(ControlConsumptionCommitOutcome::OutcomeUnknown { submission_id })
            }
            Err(StateError::RetryableConflict | StateError::AlreadyConsumed) => {
                Ok(ControlConsumptionCommitOutcome::OutcomeUnknown { submission_id })
            }
            result => result,
        }
    }

    fn control_status(
        &self,
        scope: &Scope,
        receipt_id: Uuid,
    ) -> Result<ControlStatusSnapshot, StateError> {
        scope.validate()?;
        if receipt_id.is_nil() {
            return Err(StateError::ControlStatusNotFound);
        }
        let mut client = self.connect()?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let sql = format!(
            "SELECT {SUBMISSION_COLUMNS}
               FROM public.accordlock_control_submissions
              WHERE tenant=$1 AND environment=$2 AND receipt_id=$3"
        );
        let stored = transaction
            .query_opt(&sql, &[&scope.tenant, &scope.environment, &receipt_id])?
            .map(|row| submission_from_row(&row))
            .transpose()?
            .ok_or(StateError::ControlStatusNotFound)?;
        // Status is an inert public projection, but it is returned only after
        // proving the immutable ingress and every phase artifact that the
        // current projection claims has committed.
        recovered_submission(&mut transaction, &stored)?;
        let status = load_status(&mut transaction, stored.submission_id)?;
        if status.receipt_id() != receipt_id {
            return Err(StateError::ControlStatusNotFound);
        }
        transaction.commit()?;
        Ok(status)
    }
}

impl ControlPlaneState for TlsPostgresStore {
    fn control_recovery_verifier(
        &self,
        probe: &IngressRecoveryProbe,
    ) -> Result<Option<FrozenIngressVerifier>, StateError> {
        self.inner.control_recovery_verifier(probe)
    }

    fn recover_control_submission(
        &self,
        verified: &VerifiedHistoricalIngress,
    ) -> Result<RecoveredSubmissionRef, StateError> {
        self.inner.recover_control_submission(verified)
    }

    fn accept_control_submission_or_recover(
        &self,
        verified: StaticallyVerifiedIngressSubmission,
    ) -> Result<ControlSubmissionIntakeOutcome, StateError> {
        self.inner.accept_control_submission_or_recover(verified)
    }

    fn claim_next_control_work_or_recover(
        &self,
        request: &ControlWorkClaimRequest,
    ) -> Result<ControlWorkClaimOutcome, StateError> {
        self.inner.claim_next_control_work_or_recover(request)
    }

    fn record_control_evaluation(
        &self,
        work: ControlEvaluationWork,
        signed_evaluation: &SignedEvaluation,
        evaluator: &CoseVerifier,
    ) -> Result<ControlDecisionReceipt, StateError> {
        self.inner
            .record_control_evaluation(work, signed_evaluation, evaluator)
    }

    fn control_issuance_snapshot(
        &self,
        work: &ControlIssuanceWork,
    ) -> Result<IssuanceSnapshot, StateError> {
        self.inner.control_issuance_snapshot(work)
    }

    fn record_and_link_control_issuance_or_recover(
        &self,
        work: ControlIssuanceWork,
        issued: &IssuedAuthorizationRecord,
    ) -> Result<ControlIssuanceCommitOutcome, StateError> {
        self.inner
            .record_and_link_control_issuance_or_recover(work, issued)
    }

    fn consume_and_link_control_or_recover(
        &self,
        work: ControlConsumptionWork,
    ) -> Result<ControlConsumptionCommitOutcome, StateError> {
        self.inner.consume_and_link_control_or_recover(work)
    }

    fn control_status(
        &self,
        scope: &Scope,
        receipt_id: Uuid,
    ) -> Result<ControlStatusSnapshot, StateError> {
        self.inner.control_status(scope, receipt_id)
    }
}

fn load_completed_control_consumption<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    expected_key: &ConsumeKey,
) -> Result<ConsumeSuccess, StateError> {
    let (key, issued) = load_control_issued(client, stored)?;
    if &key != expected_key {
        return Err(StateError::ControlWorkMismatch);
    }
    let row = client
        .query_opt(
            "SELECT receipt.receipt_json,receipt.consumed_unix_s,
                    receipt.dispatch_deadline AS receipt_deadline,
                    outbox.entry_json,outbox.dispatch_deadline AS outbox_deadline,
                    outbox.status AS outbox_status,issued.state AS authorization_state
               FROM public.accordlock_consumptions AS receipt
               JOIN public.accordlock_execution_outbox AS outbox
                 ON outbox.tenant=receipt.tenant
                AND outbox.environment=receipt.environment
                AND outbox.authorization_id=receipt.authorization_id
                AND outbox.transaction_id=receipt.transaction_id
               JOIN public.accordlock_issued_authorizations AS issued
                 ON issued.tenant=receipt.tenant
                AND issued.environment=receipt.environment
                AND issued.authorization_id=receipt.authorization_id
                AND issued.transaction_id=receipt.transaction_id
              WHERE receipt.tenant=$1 AND receipt.environment=$2
                AND receipt.authorization_id=$3 AND receipt.transaction_id=$4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )?
        .ok_or(StateError::ConsumptionNotFound)?;
    let receipt: ConsumptionReceipt = decode_json(row.get("receipt_json"))?;
    let outbox: OutboxEntry = decode_json(row.get("entry_json"))?;
    if row.get::<_, i64>("consumed_unix_s") != receipt.consumed_at
        || row.get::<_, i64>("receipt_deadline") != receipt.dispatch_deadline
        || row.get::<_, i64>("outbox_deadline") != outbox.dispatch_deadline
        || row.get::<_, String>("outbox_status") != "PENDING_WITNESS"
        || row.get::<_, String>("authorization_state") != "CONSUMED"
    {
        return Err(StateError::InvalidRecord(
            "completed control consumption columns disagree with JSON".to_owned(),
        ));
    }
    let success = validate_recovered_consumption(&key, &issued, &receipt, &outbox)?;
    validate_postgres_control_consumption_lineage_if_owned(client, &key, &issued, &receipt)?;
    Ok(success)
}

impl PostgresStore {
    // Taking the opaque work by value is the API's single-use capability gate.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    fn consume_and_link_control_once(
        &self,
        work: ControlConsumptionWork,
    ) -> Result<ControlConsumptionCommitOutcome, StateError> {
        work.consume_key.validate()?;
        let recovery_submission_id = work.lease.submission_id;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let claim_sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM public.accordlock_control_work_claims
              WHERE claim_id=$1 FOR SHARE"
        );
        if let Some(claim) = transaction.query_opt(&claim_sql, &[&work.lease.claim_id])? {
            if lease_from_claim_row(&claim, state_instance_id)? != work.lease {
                return Err(StateError::ControlWorkMismatch);
            }
            let stored = load_submission_for_update(&mut transaction, work.lease.submission_id)?;
            if let Some(history) =
                exact_claim_history(&mut transaction, &stored, work.lease.claim_id)?
            {
                return match history {
                    ControlWorkClaimOutcome::PhaseCompleted(receipt)
                        if receipt.phase() == ControlWorkPhase::Consume
                            && receipt.consume_key() == Some(&work.consume_key) =>
                    {
                        let success = load_completed_control_consumption(
                            &mut transaction,
                            &stored,
                            &work.consume_key,
                        )?;
                        transaction.commit()?;
                        Ok(ControlConsumptionCommitOutcome::Recovered(success))
                    }
                    ControlWorkClaimOutcome::WorkFinalized(receipt)
                        if receipt.phase() == ControlWorkPhase::Consume =>
                    {
                        transaction.commit()?;
                        Ok(ControlConsumptionCommitOutcome::Finalized(receipt))
                    }
                    _ => Err(StateError::ControlWorkMismatch),
                };
            }
        }
        let context =
            lock_exact_control_lease(&mut transaction, &work.lease, ControlWorkPhase::Consume)?;
        if let Some(expired) =
            persist_control_lease_expiry(&mut transaction, &context, &work.lease)?
        {
            return match transaction.commit() {
                Ok(()) => Err(expired),
                Err(_) => Ok(ControlConsumptionCommitOutcome::OutcomeUnknown {
                    submission_id: recovery_submission_id,
                }),
            };
        }
        advance_control_high_water(
            &mut transaction,
            &context.stored,
            &context.replay_scope,
            context.ingress_high_water,
            context.observed,
        )?;
        match preflight_claim(
            &mut transaction,
            &context.stored,
            &context.active,
            &work.lease,
            context.observed,
        )? {
            ClaimPreflight::Ready => {}
            ClaimPreflight::WorkFinalized(receipt) => {
                return match transaction.commit() {
                    Ok(()) => Ok(ControlConsumptionCommitOutcome::Finalized(receipt)),
                    Err(_) => Ok(ControlConsumptionCommitOutcome::OutcomeUnknown {
                        submission_id: recovery_submission_id,
                    }),
                };
            }
            ClaimPreflight::DecisionFinalized(_) => {
                return Err(StateError::ControlWorkMismatch);
            }
        }
        let decision = load_decision(&mut transaction, &context.stored)?;
        if decision.receipt.control_outcome() != ControlOutcome::Allow
            || decision.receipt.reason() != ControlDecisionReason::ControlAllow
            || decision.signed_evaluation.is_none()
        {
            return Err(StateError::ControlDecisionMismatch);
        }
        let (key, issued) = load_control_issued(&mut transaction, &context.stored)?;
        if key != work.consume_key {
            return Err(StateError::ControlWorkMismatch);
        }
        let active = context.active.clone();
        let grant = load_grant(
            &mut transaction,
            &context.stored.scope(),
            issued.authorization().grant_id,
        )?;
        let dispatch_deadline = validate_consumption(
            &active,
            &grant,
            &issued,
            context.observed,
            Some(context.observed),
        )?;
        let receipt = ConsumptionReceipt {
            schema_version: issued.authorization().schema_version,
            transaction_id: issued.transaction_id,
            authorization_id: issued.authorization().authorization_id,
            consumed_at: context.observed,
            dispatch_deadline,
            authority: active,
            authorization_hash: issued.authorization_hash,
        };
        let outbox = OutboxEntry {
            scope: key.scope.clone(),
            transaction_id: key.transaction_id,
            authorization_id: key.authorization_id,
            dispatch_deadline,
            status: OutboxStatus::PendingWitness,
            receipt: receipt.clone(),
        };
        let receipt_json = encode_json(&receipt)?;
        let outbox_json = encode_json(&outbox)?;
        let updated_grant = transaction.execute(
            "UPDATE public.accordlock_grants
                SET uses=uses+1,updated_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2 AND grant_id=$3
                AND revoked=FALSE AND uses<maximum_uses",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &issued.authorization().grant_id,
            ],
        )?;
        if updated_grant != 1 {
            return Err(StateError::GrantExhausted);
        }
        let updated_authorization = transaction.execute(
            "UPDATE public.accordlock_issued_authorizations
                SET state='CONSUMED',consumed_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4 AND state='ISSUED'",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )?;
        if updated_authorization != 1 {
            return Err(StateError::AlreadyConsumed);
        }
        transaction.execute(
            "INSERT INTO public.accordlock_consumptions
                    (tenant,environment,authorization_id,transaction_id,receipt_json,
                     consumed_unix_s,dispatch_deadline)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &receipt_json,
                &context.observed,
                &dispatch_deadline,
            ],
        )?;
        transaction.execute(
            "INSERT INTO public.accordlock_execution_outbox
                    (tenant,environment,authorization_id,transaction_id,
                     dispatch_deadline,status,entry_json)
             VALUES ($1,$2,$3,$4,$5,'PENDING_WITNESS',$6)",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &dispatch_deadline,
                &outbox_json,
            ],
        )?;
        transaction.execute(
            "INSERT INTO public.accordlock_control_consumptions
                    (submission_id,claim_id,claim_phase,tenant,environment,
                     authorization_id,transaction_id,linked_at,dispatch_deadline)
             VALUES ($1,$2,'CONSUME',$3,$4,$5,$6,$7,$8)",
            &[
                &context.stored.submission_id,
                &work.lease.claim_id,
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &context.observed,
                &dispatch_deadline,
            ],
        )?;
        insert_phase_completion(
            &mut transaction,
            &context.stored,
            &work.lease,
            decision.receipt.decision_id(),
            None,
            context.observed,
            Some(&key),
        )?;
        insert_or_advance_control_status(
            &mut transaction,
            &context.stored,
            ControlStatusCode::DispatchPending,
            Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            )),
            context.observed,
        )?;
        let updated_queue = transaction.execute(
            "UPDATE public.accordlock_control_work_queue
                SET phase='DONE',state='DONE',active_claim_id=NULL,
                    updated_at=clock_timestamp()
              WHERE submission_id=$1 AND phase='CONSUME' AND state='LEASED'
                AND active_claim_id=$2",
            &[&context.stored.submission_id, &work.lease.claim_id],
        )?;
        if updated_queue != 1 {
            return Err(StateError::ControlWorkMismatch);
        }
        let success = ConsumeSuccess::new(receipt, outbox, issued);
        match transaction.commit() {
            Ok(()) => Ok(ControlConsumptionCommitOutcome::Committed(success)),
            Err(_) => Ok(ControlConsumptionCommitOutcome::OutcomeUnknown {
                submission_id: recovery_submission_id,
            }),
        }
    }
}

fn derive_authorization_uuid(
    domain: &[u8],
    scope: &Scope,
    request_id: Uuid,
    evaluation_nonce: Uuid,
    grant_id: Uuid,
) -> Uuid {
    let mut bytes = Vec::new();
    for component in [
        domain,
        scope.tenant.as_bytes(),
        scope.environment.as_bytes(),
    ] {
        bytes.extend_from_slice(
            &u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(component);
    }
    bytes.extend_from_slice(request_id.as_bytes());
    bytes.extend_from_slice(evaluation_nonce.as_bytes());
    bytes.extend_from_slice(grant_id.as_bytes());
    let digest = Digest32::sha256(&bytes);
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest.as_bytes()[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Uuid::from_bytes(uuid)
}

fn validate_control_issuance_record(
    stored: &StoredControlSubmission,
    work: &ControlIssuanceWork,
    decision: &StoredControlDecision,
    grant: &GrantSnapshot,
    issued: &IssuedAuthorizationRecord,
) -> Result<(), StateError> {
    issued.validate()?;
    let evaluation = &work.signed_evaluation.attestation;
    let authorization = issued.authorization();
    let expected_authorization_id = derive_authorization_uuid(
        b"accordlock:v1:authorization-id",
        &stored.scope(),
        stored.proposal.request_id,
        stored.evaluation_nonce,
        work.selected_grant_id,
    );
    let expected_transaction_id = derive_authorization_uuid(
        b"accordlock:v1:authorization-transaction",
        &stored.scope(),
        stored.proposal.request_id,
        stored.evaluation_nonce,
        work.selected_grant_id,
    );
    if decision.receipt.decision_id() != work.decision_id
        || decision.receipt.control_outcome() != ControlOutcome::Allow
        || decision.receipt.reason() != ControlDecisionReason::ControlAllow
        || decision.receipt.selected_grant_id() != Some(work.selected_grant_id)
        || decision.signed_evaluation.as_ref() != Some(&work.signed_evaluation)
        || work.scope != stored.scope()
        || work.proposal != stored.proposal
        || issued.scope() != stored.scope()
        || issued.transaction_id != expected_transaction_id
        || authorization.authorization_id != expected_authorization_id
        || authorization.request_id != stored.proposal.request_id
        || authorization.evaluation_nonce != stored.evaluation_nonce
        || authorization.tenant != stored.tenant
        || authorization.holder != stored.actor
        || authorization.template != stored.proposal.template
        || authorization.grant_id != work.selected_grant_id
        || authorization.issued_at != work.lease.claimed_at
        || authorization.not_before != work.lease.claimed_at
        || authorization.consume_before
            != evaluation
                .consume_before
                .min(grant.registration.grant.expires_at)
        || authorization.template_hash != evaluation.template_hash
        || authorization.evidence_root != evaluation.evidence_root
        || authorization.principals != evaluation.principals
        || authorization.policy_root != evaluation.policy_root
        || authorization.authority != evaluation.authority
        || authorization.dispatch_deadline_policy != grant.registration.dispatch_deadline_policy
    {
        return Err(StateError::ControlWorkMismatch);
    }
    validate_grant_for_authorization(&grant.registration, authorization)
}

impl PostgresStore {
    fn control_issuance_snapshot_once(
        &self,
        work: &ControlIssuanceWork,
    ) -> Result<IssuanceSnapshot, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let context =
            lock_exact_control_lease(&mut transaction, &work.lease, ControlWorkPhase::Issue)?;
        if let Some(expired) =
            persist_control_lease_expiry(&mut transaction, &context, &work.lease)?
        {
            transaction.commit()?;
            return Err(expired);
        }
        let decision = load_decision(&mut transaction, &context.stored)?;
        if decision.receipt.decision_id() != work.decision_id
            || decision.receipt.control_outcome() != ControlOutcome::Allow
            || decision.receipt.reason() != ControlDecisionReason::ControlAllow
            || decision.receipt.selected_grant_id() != Some(work.selected_grant_id)
            || decision.signed_evaluation.as_ref() != Some(&work.signed_evaluation)
            || work.scope != context.stored.scope()
            || work.proposal != context.stored.proposal
        {
            return Err(StateError::ControlWorkMismatch);
        }
        let active = context.active.clone();
        if active != work.signed_evaluation.attestation.authority
            || active.principal_registry != context.stored.ingress_authority_domain
        {
            return Err(StateError::AuthorityMismatch);
        }
        if context.observed >= context.stored.ingress_expires_at
            || context.observed >= work.signed_evaluation.attestation.consume_before
        {
            advance_control_high_water(
                &mut transaction,
                &context.stored,
                &context.replay_scope,
                context.ingress_high_water,
                context.observed,
            )?;
            let error = StateError::AuthorizationExpired {
                observed: context.observed,
                consume_before: work.signed_evaluation.attestation.consume_before,
            };
            transaction.commit()?;
            return Err(error);
        }
        let grant = load_grant(
            &mut transaction,
            &context.stored.scope(),
            work.selected_grant_id,
        )?;
        match validate_current_grant(&active, &grant, context.observed) {
            Ok(()) => {}
            Err(error) if is_temporal_rejection_for_sample(&error, context.observed) => {
                advance_control_high_water(
                    &mut transaction,
                    &context.stored,
                    &context.replay_scope,
                    context.ingress_high_water,
                    context.observed,
                )?;
                transaction.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        if !control_grant_allows(&grant.registration.grant, &context.stored.proposal) {
            return Err(StateError::GrantMismatch);
        }
        advance_control_high_water(
            &mut transaction,
            &context.stored,
            &context.replay_scope,
            context.ingress_high_water,
            context.observed,
        )?;
        let snapshot = IssuanceSnapshot::new(
            context.stored.scope(),
            grant.registration,
            work.lease.claimed_at,
        );
        transaction.commit()?;
        Ok(snapshot)
    }

    // Taking the opaque work by value prevents a successful signer path from
    // reusing the same ISSUE capability.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    fn record_and_link_control_issuance_once(
        &self,
        work: ControlIssuanceWork,
        issued: &IssuedAuthorizationRecord,
    ) -> Result<ControlIssuanceCommitOutcome, StateError> {
        issued.validate()?;
        let recovery_key = work.lease.submission_id;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let claim_sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM public.accordlock_control_work_claims
              WHERE claim_id=$1 FOR SHARE"
        );
        if let Some(claim) = transaction.query_opt(&claim_sql, &[&work.lease.claim_id])? {
            if lease_from_claim_row(&claim, state_instance_id)? != work.lease {
                return Err(StateError::ControlWorkMismatch);
            }
            let stored = load_submission_for_update(&mut transaction, work.lease.submission_id)?;
            if let Some(history) =
                exact_claim_history(&mut transaction, &stored, work.lease.claim_id)?
            {
                return match history {
                    ControlWorkClaimOutcome::PhaseCompleted(receipt)
                        if receipt.phase() == ControlWorkPhase::Issue =>
                    {
                        let (_, existing) = load_control_issued(&mut transaction, &stored)?;
                        if &existing != issued {
                            return Err(StateError::InvalidRecord(
                                "completed ISSUE retry differs from durable authorization"
                                    .to_owned(),
                            ));
                        }
                        transaction.commit()?;
                        Ok(ControlIssuanceCommitOutcome::Recovered)
                    }
                    ControlWorkClaimOutcome::WorkFinalized(receipt)
                        if receipt.phase() == ControlWorkPhase::Issue =>
                    {
                        transaction.commit()?;
                        Ok(ControlIssuanceCommitOutcome::Finalized(receipt))
                    }
                    _ => Err(StateError::ControlWorkMismatch),
                };
            }
        }
        let context =
            lock_exact_control_lease(&mut transaction, &work.lease, ControlWorkPhase::Issue)?;
        if let Some(expired) =
            persist_control_lease_expiry(&mut transaction, &context, &work.lease)?
        {
            return match transaction.commit() {
                Ok(()) => Err(expired),
                Err(_) => Ok(ControlIssuanceCommitOutcome::OutcomeUnknown {
                    submission_id: recovery_key,
                }),
            };
        }
        advance_control_high_water(
            &mut transaction,
            &context.stored,
            &context.replay_scope,
            context.ingress_high_water,
            context.observed,
        )?;
        match preflight_claim(
            &mut transaction,
            &context.stored,
            &context.active,
            &work.lease,
            context.observed,
        )? {
            ClaimPreflight::Ready => {}
            ClaimPreflight::WorkFinalized(receipt) => {
                return match transaction.commit() {
                    Ok(()) => Ok(ControlIssuanceCommitOutcome::Finalized(receipt)),
                    Err(_) => Ok(ControlIssuanceCommitOutcome::OutcomeUnknown {
                        submission_id: recovery_key,
                    }),
                };
            }
            ClaimPreflight::DecisionFinalized(_) => {
                return Err(StateError::ControlWorkMismatch);
            }
        }
        let decision = load_decision(&mut transaction, &context.stored)?;
        let active = context.active.clone();
        let grant = load_grant(
            &mut transaction,
            &context.stored.scope(),
            work.selected_grant_id,
        )?;
        validate_current_grant(&active, &grant, context.observed)?;
        validate_control_issuance_record(&context.stored, &work, &decision, &grant, issued)?;
        let record_json = encode_json(issued)?;
        transaction.execute(
            "INSERT INTO public.accordlock_issued_authorizations
                    (tenant,environment,authorization_id,transaction_id,grant_id,record_json,
                     authorization_hash,consume_before,issuance_profile_version,
                     request_id,evaluation_nonce)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,2,$9,$10)",
            &[
                &context.stored.tenant,
                &context.stored.environment,
                &issued.authorization().authorization_id,
                &issued.transaction_id,
                &issued.authorization().grant_id,
                &record_json,
                &issued.authorization_hash.to_string(),
                &issued.authorization().consume_before,
                &issued.authorization().request_id,
                &issued.authorization().evaluation_nonce,
            ],
        )?;
        transaction.execute(
            "INSERT INTO public.accordlock_control_issuances
                    (submission_id,claim_id,claim_phase,decision_id,
                     decision_outcome,tenant,environment,grant_id,
                     issuance_profile_version,request_id,evaluation_nonce,
                     authorization_id,transaction_id,authorization_hash,linked_at)
             VALUES ($1,$2,'ISSUE',$3,'ALLOW',$4,$5,$6,2,$7,$8,$9,$10,$11,$12)",
            &[
                &context.stored.submission_id,
                &work.lease.claim_id,
                &work.decision_id,
                &context.stored.tenant,
                &context.stored.environment,
                &work.selected_grant_id,
                &context.stored.proposal.request_id,
                &context.stored.evaluation_nonce,
                &issued.authorization().authorization_id,
                &issued.transaction_id,
                &issued.authorization_hash.to_string(),
                &context.observed,
            ],
        )?;
        insert_phase_completion(
            &mut transaction,
            &context.stored,
            &work.lease,
            work.decision_id,
            None,
            context.observed,
            None,
        )?;
        insert_or_advance_control_status(
            &mut transaction,
            &context.stored,
            ControlStatusCode::AuthorizationIssued,
            Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            )),
            context.observed,
        )?;
        let updated = transaction.execute(
            "UPDATE public.accordlock_control_work_queue
                SET phase='CONSUME',state='READY',active_claim_id=NULL,
                    updated_at=clock_timestamp()
              WHERE submission_id=$1 AND phase='ISSUE' AND state='LEASED'
                AND active_claim_id=$2",
            &[&context.stored.submission_id, &work.lease.claim_id],
        )?;
        if updated != 1 {
            return Err(StateError::ControlWorkMismatch);
        }
        match transaction.commit() {
            Ok(()) => Ok(ControlIssuanceCommitOutcome::Committed),
            Err(_) => Ok(ControlIssuanceCommitOutcome::OutcomeUnknown {
                submission_id: recovery_key,
            }),
        }
    }
}

struct LockedControlLease {
    stored: StoredControlSubmission,
    active: AuthorityVector,
    replay_scope: IngressReplayScope,
    ingress_high_water: i64,
    observed: i64,
}

fn lock_exact_control_lease(
    transaction: &mut Transaction<'_>,
    lease: &ControlWorkLease,
    expected_phase: ControlWorkPhase,
) -> Result<LockedControlLease, StateError> {
    if lease.phase != expected_phase {
        return Err(StateError::ControlWorkMismatch);
    }
    let state_instance_id = PostgresStore::locked_state_instance(transaction)?;
    if lease.state_instance_id != state_instance_id {
        return Err(StateError::ControlWorkMismatch);
    }
    let sql = format!(
        "SELECT {CLAIM_COLUMNS} FROM public.accordlock_control_work_claims
          WHERE claim_id=$1 FOR SHARE"
    );
    let claim_row = transaction
        .query_opt(&sql, &[&lease.claim_id])?
        .ok_or(StateError::ControlWorkNotFound)?;
    let durable_lease = lease_from_claim_row(&claim_row, state_instance_id)?;
    if &durable_lease != lease
        || claim_row.get::<_, String>("role")
            != role_sql(match expected_phase {
                ControlWorkPhase::Evaluate => ControlWorkerRole::Evaluator,
                ControlWorkPhase::Issue => ControlWorkerRole::Issuer,
                ControlWorkPhase::Consume => ControlWorkerRole::Consumer,
                ControlWorkPhase::Done => return Err(StateError::ControlWorkMismatch),
            })
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let stored = load_submission_for_update(transaction, lease.submission_id)?;
    if stored.state_instance_id != state_instance_id {
        return Err(StateError::ControlSubmissionMismatch);
    }
    validate_ready_phase_shape(transaction, &stored, expected_phase)?;
    let active = load_active_authority(transaction, &stored.scope())?;
    let (replay_scope, ingress_high_water, scope_high_water) =
        lock_control_high_water(transaction, &stored)?;
    let queue = transaction
        .query_opt(
            "SELECT phase,state,active_claim_id
               FROM public.accordlock_control_work_queue
              WHERE submission_id=$1
              FOR UPDATE",
            &[&stored.submission_id],
        )?
        .ok_or(StateError::ControlWorkNotFound)?;
    if queue.get::<_, String>("phase") != phase_sql(expected_phase)
        || queue.get::<_, String>("state") != "LEASED"
        || queue.get::<_, Option<Uuid>>("active_claim_id") != Some(lease.claim_id)
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let observed = PostgresStore::sample_trusted_time(transaction)?;
    let high_water = ingress_high_water
        .max(scope_high_water)
        .max(stored.accepted_at);
    if observed < high_water {
        return Err(StateError::ClockRollback {
            observed,
            high_water,
        });
    }
    Ok(LockedControlLease {
        stored,
        active,
        replay_scope,
        ingress_high_water,
        observed,
    })
}

fn persist_control_lease_expiry(
    transaction: &mut Transaction<'_>,
    context: &LockedControlLease,
    lease: &ControlWorkLease,
) -> Result<Option<StateError>, StateError> {
    if context.observed < lease.lease_until {
        return Ok(None);
    }
    advance_control_high_water(
        transaction,
        &context.stored,
        &context.replay_scope,
        context.ingress_high_water,
        context.observed,
    )?;
    Ok(Some(StateError::ControlWorkLeaseExpired {
        observed: context.observed,
        lease_until: lease.lease_until,
    }))
}

impl PostgresStore {
    // Taking the opaque work by value prevents evaluation authority reuse.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    fn record_control_evaluation_once(
        &self,
        work: ControlEvaluationWork,
        signed_evaluation: &SignedEvaluation,
        evaluator: &CoseVerifier,
    ) -> Result<ControlDecisionReceipt, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let context =
            lock_exact_control_lease(&mut transaction, &work.lease, ControlWorkPhase::Evaluate)?;
        if let Some(expired) =
            persist_control_lease_expiry(&mut transaction, &context, &work.lease)?
        {
            transaction.commit()?;
            return Err(expired);
        }
        advance_control_high_water(
            &mut transaction,
            &context.stored,
            &context.replay_scope,
            context.ingress_high_water,
            context.observed,
        )?;
        match preflight_claim(
            &mut transaction,
            &context.stored,
            &context.active,
            &work.lease,
            context.observed,
        )? {
            ClaimPreflight::DecisionFinalized(receipt) => {
                transaction.commit()?;
                return Ok(receipt);
            }
            ClaimPreflight::Ready => {}
            ClaimPreflight::WorkFinalized(_) => {
                return Err(StateError::ControlDecisionMismatch);
            }
        }
        let active = context.active.clone();
        if work.scope != context.stored.scope()
            || work.proposal != context.stored.proposal
            || work.caller_tenant != context.stored.tenant
            || work.caller_actor != context.stored.actor
            || work.accepted_at != context.stored.accepted_at
            || work.ingress_expires_at != context.stored.ingress_expires_at
            || work.ingress_authority_domain != context.stored.ingress_authority_domain
            || work.active_authority != active
            || work.evaluation_nonce != context.stored.evaluation_nonce
        {
            return Err(StateError::ControlWorkMismatch);
        }
        let evaluator_root =
            evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())
                .map_err(|error| StateError::InvalidRecord(error.to_string()))?;
        if evaluator_root != active.kernel_configuration.root {
            return Err(StateError::AuthorityMismatch);
        }
        let payload = verify_cose(&signed_evaluation.cose_sign1, EVALUATION_DOMAIN, evaluator)
            .map_err(|error| {
                StateError::InvalidRecord(format!("evaluation signature invalid: {error}"))
            })?;
        let evaluation = &signed_evaluation.attestation;
        let reasons_valid = match evaluation.outcome {
            DecisionOutcome::Allow => evaluation.reasons.as_slice() == [ReasonCode::Allowed],
            DecisionOutcome::Deny => {
                !evaluation.reasons.is_empty() && !evaluation.reasons.contains(&ReasonCode::Allowed)
            }
        };
        if payload != evaluation.canonical_bytes()?
            || evaluation.schema_version != EVALUATION_ATTESTATION_SCHEMA_VERSION
            || evaluation.evaluation_nonce != context.stored.evaluation_nonce
            || evaluation.request_id != context.stored.proposal.request_id
            || evaluation.tenant != context.stored.tenant
            || evaluation.actor != context.stored.actor
            || evaluation.evaluated_at != work.lease.claimed_at
            || evaluation.authority != active
            || evaluation.template_hash != canonical_hash(&context.stored.proposal.template)?
            || evaluation.policy_root != active.policy.root
            || evaluation.consume_before <= evaluation.evaluated_at
            || evaluation.consume_before > context.stored.ingress_expires_at
            || !reasons_valid
        {
            return Err(StateError::ControlDecisionMismatch);
        }

        let (kernel_outcome, control_outcome, reason, selected_grant_id) = match evaluation.outcome
        {
            DecisionOutcome::Deny => (
                ControlKernelOutcome::Deny,
                ControlOutcome::Deny,
                ControlDecisionReason::KernelDeny,
                None,
            ),
            DecisionOutcome::Allow => {
                let rows = transaction.query(
                    "SELECT registration_json,uses,maximum_uses,not_before,
                                expires_at,revoked,issuance_profile_version
                           FROM public.accordlock_grants
                          WHERE tenant=$1 AND environment=$2
                          FOR SHARE",
                    &[&context.stored.tenant, &context.stored.environment],
                )?;
                let mut matching = Vec::new();
                for row in &rows {
                    let grant = grant_from_row(row)?;
                    match validate_current_grant(&active, &grant, context.observed) {
                        Ok(()) => {
                            if control_grant_allows(
                                &grant.registration.grant,
                                &context.stored.proposal,
                            ) {
                                matching.push(grant.registration.grant.grant_id);
                            }
                        }
                        Err(StateError::GrantRevoked | StateError::GrantExhausted) => {}
                        Err(error)
                            if is_temporal_rejection_for_sample(&error, context.observed) => {}
                        Err(error) => return Err(error),
                    }
                }
                match matching.as_slice() {
                    [] => (
                        ControlKernelOutcome::Allow,
                        ControlOutcome::Deny,
                        ControlDecisionReason::GrantUnavailable,
                        None,
                    ),
                    [grant_id] => (
                        ControlKernelOutcome::Allow,
                        ControlOutcome::Allow,
                        ControlDecisionReason::ControlAllow,
                        Some(*grant_id),
                    ),
                    _ => {
                        return Err(StateError::InvalidRecord(
                            "multiple current grants exist in the mono-grant control profile"
                                .to_owned(),
                        ));
                    }
                }
            }
        };
        let evaluation_id = derive_control_evaluation_id(
            context.stored.state_instance_id,
            context.stored.submission_id,
            context.stored.evaluation_nonce,
        );
        let decision_id = derive_control_decision_id(
            context.stored.state_instance_id,
            context.stored.submission_id,
            context.stored.evaluation_nonce,
        );
        let receipt = ControlDecisionReceipt::new(
            decision_id,
            context.stored.submission_id,
            Some(kernel_outcome),
            control_outcome,
            reason,
            selected_grant_id,
            context.observed,
        );
        let evaluation_commitment = control_evaluation_commitment(
            evaluation_id,
            context.stored.submission_id,
            work.lease.claim_id,
            &context.stored.scope(),
            signed_evaluation,
            evaluator,
        )?;
        let decision_commitment =
            control_decision_commitment(work.lease.claim_id, &context.stored.scope(), &receipt)?;
        let signed_evaluation_json = encode_json(signed_evaluation)?;
        let evaluator_public_key = evaluator.public_key_bytes().to_vec();
        transaction.execute(
            "INSERT INTO public.accordlock_control_evaluations
                    (evaluation_id,submission_id,claim_id,claim_phase,
                     evaluation_nonce,kernel_outcome,signed_evaluation_json,
                     evaluator_key_id,evaluator_public_key,
                     evaluation_commitment,evaluated_at)
             VALUES ($1,$2,$3,'EVALUATE',$4,$5,$6,$7,$8,$9,$10)",
            &[
                &evaluation_id,
                &context.stored.submission_id,
                &work.lease.claim_id,
                &context.stored.evaluation_nonce,
                &control_outcome_sql(match kernel_outcome {
                    ControlKernelOutcome::Allow => ControlOutcome::Allow,
                    ControlKernelOutcome::Deny => ControlOutcome::Deny,
                }),
                &signed_evaluation_json,
                &evaluator.key_id(),
                &evaluator_public_key,
                &evaluation_commitment.to_string(),
                &work.lease.claimed_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO public.accordlock_control_decisions
                    (decision_id,submission_id,claim_id,claim_phase,evaluation_id,
                     kernel_outcome,control_outcome,reason,selected_grant_id,
                     tenant,environment,decided_at,decision_commitment)
             VALUES ($1,$2,$3,'EVALUATE',$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            &[
                &decision_id,
                &context.stored.submission_id,
                &work.lease.claim_id,
                &evaluation_id,
                &control_outcome_sql(match kernel_outcome {
                    ControlKernelOutcome::Allow => ControlOutcome::Allow,
                    ControlKernelOutcome::Deny => ControlOutcome::Deny,
                }),
                &control_outcome_sql(control_outcome),
                &decision_reason_sql(reason),
                &selected_grant_id,
                &context.stored.tenant,
                &context.stored.environment,
                &context.observed,
                &decision_commitment.to_string(),
            ],
        )?;
        insert_phase_completion(
            &mut transaction,
            &context.stored,
            &work.lease,
            decision_id,
            Some(evaluation_id),
            context.observed,
            None,
        )?;
        let next_status = if control_outcome == ControlOutcome::Allow {
            ControlStatusCode::Authorized
        } else {
            ControlStatusCode::ControlDenied
        };
        insert_or_advance_control_status(
            &mut transaction,
            &context.stored,
            next_status,
            Some(ControlStatusReason::Decision(reason)),
            context.observed,
        )?;
        let next_phase = if control_outcome == ControlOutcome::Allow {
            "ISSUE"
        } else {
            "DONE"
        };
        let next_state = if control_outcome == ControlOutcome::Allow {
            "READY"
        } else {
            "DONE"
        };
        let updated = transaction.execute(
            "UPDATE public.accordlock_control_work_queue
                SET phase=$2,state=$3,active_claim_id=NULL,updated_at=clock_timestamp()
              WHERE submission_id=$1 AND phase='EVALUATE' AND state='LEASED'
                AND active_claim_id=$4",
            &[
                &context.stored.submission_id,
                &next_phase,
                &next_state,
                &work.lease.claim_id,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::ControlWorkMismatch);
        }
        transaction.commit()?;
        Ok(receipt)
    }
}

fn load_active_authority<C: GenericClient>(
    client: &mut C,
    scope: &Scope,
) -> Result<AuthorityVector, StateError> {
    let row = client
        .query_opt(
            "SELECT authority_json FROM public.accordlock_authority_state
              WHERE tenant=$1 AND environment=$2 FOR SHARE",
            &[&scope.tenant, &scope.environment],
        )?
        .ok_or(StateError::AuthorityNotInitialized)?;
    decode_json(row.get("authority_json"))
}

fn control_grant_allows(
    grant: &accordlock_protocol::CapabilityGrant,
    proposal: &accordlock_protocol::AgentProposal,
) -> bool {
    grant.holder == proposal.actor
        && grant.tenant == proposal.tenant
        && grant.operation == proposal.template.operation
        && grant.repository == proposal.template.repository
        && grant.audience == proposal.template.audience
        && grant.cluster_identity == proposal.template.cluster_identity
        && grant.namespace == proposal.template.namespace
        && grant.deployment_uid == proposal.template.deployment_uid
        && grant.container == proposal.template.container
        && grant.image_repository == proposal.template.image_repository
}

fn grant_from_row(row: &Row) -> Result<GrantSnapshot, StateError> {
    let registration: GrantRegistration = decode_json(row.get("registration_json"))?;
    let uses_i64: i64 = row.get("uses");
    let uses = u32::try_from(uses_i64).map_err(|_| {
        StateError::InvalidRecord("stored grant uses are not representable".to_owned())
    })?;
    if row.get::<_, i16>("issuance_profile_version") != 2
        || row.get::<_, i64>("maximum_uses") != i64::from(registration.grant.maximum_uses)
        || row.get::<_, i64>("not_before") != registration.grant.not_before
        || row.get::<_, i64>("expires_at") != registration.grant.expires_at
    {
        return Err(StateError::InvalidRecord(
            "stored grant columns disagree with registration JSON".to_owned(),
        ));
    }
    Ok(GrantSnapshot {
        registration,
        uses,
        revoked: row.get("revoked"),
    })
}

fn load_grant<C: GenericClient>(
    client: &mut C,
    scope: &Scope,
    grant_id: Uuid,
) -> Result<GrantSnapshot, StateError> {
    let row = client
        .query_opt(
            "SELECT registration_json,uses,maximum_uses,not_before,expires_at,
                    revoked,issuance_profile_version
               FROM public.accordlock_grants
              WHERE tenant=$1 AND environment=$2 AND grant_id=$3
              FOR SHARE",
            &[&scope.tenant, &scope.environment, &grant_id],
        )?
        .ok_or(StateError::GrantNotFound)?;
    grant_from_row(&row)
}

#[allow(clippy::too_many_lines)]
fn decision_from_row(
    row: &Row,
    stored: &StoredControlSubmission,
) -> Result<StoredControlDecision, StateError> {
    let kernel_string: Option<String> = row.get("kernel_outcome");
    let control_string: String = row.get("control_outcome");
    let reason_string: String = row.get("reason");
    let evaluation_id: Option<Uuid> = row.get("evaluation_id");
    let receipt = ControlDecisionReceipt::new(
        row.get("decision_id"),
        row.get("submission_id"),
        parse_kernel_outcome(kernel_string.as_deref())?,
        parse_control_outcome(&control_string)?,
        parse_decision_reason(&reason_string)?,
        row.get("selected_grant_id"),
        row.get("decided_at"),
    );
    let claim_id: Uuid = row.get("claim_id");
    let expected_decision_id = derive_control_decision_id(
        stored.state_instance_id,
        stored.submission_id,
        stored.evaluation_nonce,
    );
    if receipt.decision_id() != expected_decision_id
        || receipt.submission_id() != stored.submission_id
    {
        return Err(StateError::ControlDecisionMismatch);
    }
    let decision_commitment = parse_digest(row.get("decision_commitment"), "decision")?;
    if decision_commitment != control_decision_commitment(claim_id, &stored.scope(), &receipt)? {
        return Err(StateError::ControlDecisionMismatch);
    }
    let signed_evaluation_json: Option<serde_json::Value> = row.get("signed_evaluation_json");
    let evaluator_key_id: Option<String> = row.get("evaluator_key_id");
    let evaluator_public_key: Option<Vec<u8>> = row.get("evaluator_public_key");
    let evaluation_commitment_string: Option<String> = row.get("evaluation_commitment");
    let (signed_evaluation, evaluator_public_key, evaluation_commitment) = match (
        evaluation_id,
        signed_evaluation_json,
        evaluator_key_id.as_ref(),
        evaluator_public_key,
        evaluation_commitment_string,
    ) {
        (None, None, None, None, None) => (None, None, None),
        (Some(id), Some(json), Some(key_id), Some(public_key), Some(commitment)) => {
            let signed: SignedEvaluation = decode_json(json)?;
            let public_key = fixed_public_key(public_key, "evaluator")?;
            let verifier = CoseVerifier::from_public_key(key_id.clone(), public_key)
                .map_err(|error| StateError::InvalidRecord(error.to_string()))?;
            let expected_evaluation_id = derive_control_evaluation_id(
                stored.state_instance_id,
                stored.submission_id,
                stored.evaluation_nonce,
            );
            let evaluator_root = evaluator_verifier_root(key_id, public_key)
                .map_err(|error| StateError::InvalidRecord(error.to_string()))?;
            let payload =
                verify_cose(&signed.cose_sign1, EVALUATION_DOMAIN, &verifier).map_err(|error| {
                    StateError::InvalidRecord(format!(
                        "stored evaluation signature is invalid: {error}"
                    ))
                })?;
            let canonical = signed.attestation.canonical_bytes()?;
            let reasons_valid = match signed.attestation.outcome {
                DecisionOutcome::Allow => {
                    signed.attestation.reasons.as_slice() == [ReasonCode::Allowed]
                }
                DecisionOutcome::Deny => {
                    !signed.attestation.reasons.is_empty()
                        && !signed.attestation.reasons.contains(&ReasonCode::Allowed)
                }
            };
            let expected_kernel = match signed.attestation.outcome {
                DecisionOutcome::Allow => ControlKernelOutcome::Allow,
                DecisionOutcome::Deny => ControlKernelOutcome::Deny,
            };
            let stored_kernel: String = row.get("stored_evaluation_kernel_outcome");
            if id != expected_evaluation_id
                || payload != canonical
                || signed.attestation.schema_version != EVALUATION_ATTESTATION_SCHEMA_VERSION
                || signed.attestation.evaluation_nonce != stored.evaluation_nonce
                || signed.attestation.request_id != stored.proposal.request_id
                || signed.attestation.tenant != stored.tenant
                || signed.attestation.actor != stored.actor
                || signed.attestation.evaluated_at != row.get::<_, i64>("evaluated_at")
                || signed.attestation.evaluated_at != row.get::<_, i64>("claim_claimed_at")
                || signed.attestation.authority.kernel_configuration.root != evaluator_root
                || signed.attestation.authority.principal_registry
                    != stored.ingress_authority_domain
                || signed.attestation.template_hash != canonical_hash(&stored.proposal.template)?
                || signed.attestation.policy_root != signed.attestation.authority.policy.root
                || signed.attestation.consume_before <= signed.attestation.evaluated_at
                || signed.attestation.consume_before > stored.ingress_expires_at
                || row.get::<_, Uuid>("stored_evaluation_nonce") != stored.evaluation_nonce
                || parse_kernel_outcome(Some(&stored_kernel))? != Some(expected_kernel)
                || receipt.kernel_outcome() != Some(expected_kernel)
                || !reasons_valid
            {
                return Err(StateError::ControlDecisionMismatch);
            }
            let commitment = parse_digest(&commitment, "evaluation")?;
            if commitment
                != control_evaluation_commitment(
                    id,
                    stored.submission_id,
                    claim_id,
                    &stored.scope(),
                    &signed,
                    &verifier,
                )?
            {
                return Err(StateError::ControlDecisionMismatch);
            }
            (Some(signed), Some(public_key), Some(commitment))
        }
        _ => return Err(StateError::ControlDecisionMismatch),
    };
    Ok(StoredControlDecision {
        receipt,
        evaluation_id,
        evaluation_commitment,
        decision_commitment,
        signed_evaluation,
        evaluator_key_id,
        evaluator_public_key,
    })
}

fn load_decision<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
) -> Result<StoredControlDecision, StateError> {
    let row = client
        .query_opt(
            "SELECT decision.decision_id,decision.submission_id,decision.claim_id,
                    decision.evaluation_id,decision.kernel_outcome,
                    decision.control_outcome,decision.reason,
                    decision.selected_grant_id,decision.decided_at,
                    decision.decision_commitment,
                    evaluation.signed_evaluation_json,evaluation.evaluator_key_id,
                    evaluation.evaluator_public_key,evaluation.evaluation_commitment,
                    evaluation.evaluation_nonce AS stored_evaluation_nonce,
                    evaluation.kernel_outcome AS stored_evaluation_kernel_outcome,
                    evaluation.evaluated_at,claim.claimed_at AS claim_claimed_at
               FROM public.accordlock_control_decisions AS decision
               LEFT JOIN public.accordlock_control_evaluations AS evaluation
                 ON evaluation.submission_id=decision.submission_id
                AND evaluation.claim_id=decision.claim_id
                AND evaluation.evaluation_id=decision.evaluation_id
               JOIN public.accordlock_control_work_claims AS claim
                 ON claim.submission_id=decision.submission_id
                AND claim.claim_id=decision.claim_id
              WHERE decision.submission_id=$1",
            &[&stored.submission_id],
        )?
        .ok_or(StateError::ControlDecisionMismatch)?;
    decision_from_row(&row, stored)
}

fn lease_from_claim_row(
    row: &Row,
    state_instance_id: Uuid,
) -> Result<ControlWorkLease, StateError> {
    let fence_i64: i64 = row.get("fence");
    let fence = u64::try_from(fence_i64).map_err(|_| {
        StateError::InvalidRecord("control work fence is not representable".to_owned())
    })?;
    Ok(ControlWorkLease {
        state_instance_id,
        submission_id: row.get("submission_id"),
        phase: parse_phase(row.get::<_, String>("phase").as_str())?,
        worker_id: row.get("worker_id"),
        claim_id: row.get("claim_id"),
        fence,
        claimed_at: row.get("claimed_at"),
        lease_until: row.get("lease_until"),
    })
}

fn completion_from_row(
    row: &Row,
    scope: &Scope,
) -> Result<ControlPhaseCompletionReceipt, StateError> {
    let phase = parse_phase(row.get::<_, String>("phase").as_str())?;
    let fence_i64: i64 = row.get("fence");
    let consume_authorization_id: Option<Uuid> = row.get("consume_authorization_id");
    let consume_transaction_id: Option<Uuid> = row.get("consume_transaction_id");
    let consume_key = match (consume_authorization_id, consume_transaction_id) {
        (None, None) => None,
        (Some(authorization_id), Some(transaction_id)) => Some(ConsumeKey {
            scope: scope.clone(),
            transaction_id,
            authorization_id,
        }),
        _ => return Err(StateError::ControlWorkMismatch),
    };
    ControlPhaseCompletionReceipt::new(
        row.get("submission_id"),
        row.get("claim_id"),
        u64::try_from(fence_i64).map_err(|_| {
            StateError::InvalidRecord("control completion fence is invalid".to_owned())
        })?,
        row.get("worker_id"),
        phase,
        row.get("completed_at"),
        row.get("decision_id"),
        consume_key,
    )
}

fn build_control_work(
    transaction: &mut Transaction<'_>,
    state_instance_id: Uuid,
    stored: &StoredControlSubmission,
    active: &AuthorityVector,
    claim_row: &Row,
) -> Result<ClaimedControlWork, StateError> {
    let lease = lease_from_claim_row(claim_row, state_instance_id)?;
    match lease.phase {
        ControlWorkPhase::Evaluate => Ok(ClaimedControlWork::Evaluate(ControlEvaluationWork {
            lease,
            scope: stored.scope(),
            proposal: stored.proposal.clone(),
            caller_tenant: stored.tenant.clone(),
            caller_actor: stored.actor.clone(),
            accepted_at: stored.accepted_at,
            ingress_expires_at: stored.ingress_expires_at,
            ingress_authority_domain: stored.ingress_authority_domain.clone(),
            active_authority: active.clone(),
            evaluation_nonce: stored.evaluation_nonce,
        })),
        ControlWorkPhase::Issue => {
            let decision = load_decision(transaction, stored)?;
            let signed_evaluation = decision
                .signed_evaluation
                .ok_or(StateError::ControlDecisionMismatch)?;
            let selected_grant_id = decision
                .receipt
                .selected_grant_id()
                .ok_or(StateError::ControlDecisionMismatch)?;
            if decision.receipt.control_outcome() != ControlOutcome::Allow {
                return Err(StateError::ControlDecisionMismatch);
            }
            Ok(ClaimedControlWork::Issue(ControlIssuanceWork {
                lease,
                scope: stored.scope(),
                proposal: stored.proposal.clone(),
                signed_evaluation,
                selected_grant_id,
                decision_id: decision.receipt.decision_id(),
            }))
        }
        ControlWorkPhase::Consume => {
            let row = transaction
                .query_opt(
                    "SELECT issued.transaction_id,issued.grant_id,issued.record_json,
                            issued.authorization_hash,issued.consume_before,
                            issued.issuance_profile_version,issued.request_id,
                            issued.evaluation_nonce,issued.authorization_id
              FROM public.accordlock_control_issuances AS issuance
              JOIN public.accordlock_issued_authorizations AS issued
                         ON issued.tenant=issuance.tenant
                        AND issued.environment=issuance.environment
                        AND issued.authorization_id=issuance.authorization_id
                        AND issued.transaction_id=issuance.transaction_id
                      WHERE issuance.submission_id=$1
                      FOR SHARE OF issuance,issued",
                    &[&stored.submission_id],
                )?
                .ok_or(StateError::AuthorizationNotFound)?;
            let key = ConsumeKey {
                scope: stored.scope(),
                transaction_id: row.get("transaction_id"),
                authorization_id: row.get("authorization_id"),
            };
            decode_stored_authorization_row(&row, &key)?;
            Ok(ClaimedControlWork::Consume(ControlConsumptionWork {
                lease,
                consume_key: key,
            }))
        }
        ControlWorkPhase::Done => Err(StateError::ControlWorkMismatch),
    }
}

#[allow(clippy::too_many_lines)]
fn validated_phase_completion<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    claim_id: Uuid,
) -> Result<Option<ControlPhaseCompletionReceipt>, StateError> {
    let row = client.query_opt(
        "SELECT completion.submission_id,completion.claim_id,completion.phase,
                completion.fence,completion.worker_id,completion.completed_at,
                completion.decision_id,completion.evaluation_id AS completion_evaluation_id,
                completion.consume_authorization_id,
                completion.consume_transaction_id,
                decision.control_outcome,
                queue.phase AS queue_phase,queue.state AS queue_state,
                queue.active_claim_id,status.status,status.reason_kind,
                status.reason_code,status.revision,status.observed_at,
                event.status AS event_status,event.reason_kind AS event_reason_kind,
                event.reason_code AS event_reason_code,event.observed_at AS event_observed_at
           FROM public.accordlock_control_phase_completions AS completion
           JOIN public.accordlock_control_decisions AS decision
             ON decision.submission_id=completion.submission_id
            AND decision.decision_id=completion.decision_id
           JOIN public.accordlock_control_work_queue AS queue
             ON queue.submission_id=completion.submission_id
           JOIN public.accordlock_control_status AS status
             ON status.submission_id=completion.submission_id
           JOIN public.accordlock_control_events AS event
             ON event.submission_id=status.submission_id
            AND event.revision=status.revision
          WHERE completion.claim_id=$1",
        &[&claim_id],
    )?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, Uuid>("submission_id") != stored.submission_id {
        return Err(StateError::ControlWorkMismatch);
    }
    let receipt = completion_from_row(&row, &stored.scope())?;
    let phase = receipt.phase();
    let decision = load_decision(client, stored)?;
    if decision.receipt.decision_id() != receipt.decision_id() {
        return Err(StateError::ControlDecisionMismatch);
    }
    match phase {
        ControlWorkPhase::Evaluate => {
            if decision.signed_evaluation.is_none()
                || decision.evaluation_id != row.get::<_, Option<Uuid>>("completion_evaluation_id")
            {
                return Err(StateError::ControlDecisionMismatch);
            }
        }
        ControlWorkPhase::Issue => {
            let (key, issued) = load_control_issued(client, stored)?;
            let issuance = client
                .query_opt(
                    "SELECT claim_id,decision_id,linked_at
                       FROM public.accordlock_control_issuances
                      WHERE submission_id=$1 AND authorization_id=$2 AND transaction_id=$3",
                    &[
                        &stored.submission_id,
                        &key.authorization_id,
                        &key.transaction_id,
                    ],
                )?
                .ok_or(StateError::AuthorizationNotFound)?;
            if issuance.get::<_, Uuid>("claim_id") != receipt.claim_id()
                || issuance.get::<_, Uuid>("decision_id") != receipt.decision_id()
                || issuance.get::<_, i64>("linked_at") != receipt.completed_at()
                || issued.authorization().evaluation_nonce != stored.evaluation_nonce
            {
                return Err(StateError::InvalidRecord(
                    "completed ISSUE lacks its exact issuance lineage".to_owned(),
                ));
            }
        }
        ControlWorkPhase::Consume => {
            let (key, issued) = load_control_issued(client, stored)?;
            if receipt.consume_key() != Some(&key) {
                return Err(StateError::InvalidRecord(
                    "completed CONSUME identity differs from its issuance".to_owned(),
                ));
            }
            let consumption = client
                .query_opt(
                    "SELECT link.claim_id,link.linked_at,link.dispatch_deadline,
                            receipt.receipt_json,outbox.entry_json
                       FROM public.accordlock_control_consumptions AS link
                       JOIN public.accordlock_consumptions AS receipt
                         ON receipt.tenant=link.tenant
                        AND receipt.environment=link.environment
                        AND receipt.authorization_id=link.authorization_id
                        AND receipt.transaction_id=link.transaction_id
                       JOIN public.accordlock_execution_outbox AS outbox
                         ON outbox.tenant=link.tenant
                        AND outbox.environment=link.environment
                        AND outbox.authorization_id=link.authorization_id
                        AND outbox.transaction_id=link.transaction_id
                      WHERE link.submission_id=$1",
                    &[&stored.submission_id],
                )?
                .ok_or(StateError::ConsumptionNotFound)?;
            let consumed: ConsumptionReceipt = decode_json(consumption.get("receipt_json"))?;
            let outbox: OutboxEntry = decode_json(consumption.get("entry_json"))?;
            if consumption.get::<_, Uuid>("claim_id") != receipt.claim_id()
                || consumption.get::<_, i64>("linked_at") != receipt.completed_at()
                || consumption.get::<_, i64>("dispatch_deadline") != consumed.dispatch_deadline
            {
                return Err(StateError::InvalidRecord(
                    "completed CONSUME lacks its exact receipt/outbox link".to_owned(),
                ));
            }
            validate_recovered_consumption(&key, &issued, &consumed, &outbox)?;
            validate_postgres_control_consumption_lineage_if_owned(
                client, &key, &issued, &consumed,
            )?;
        }
        ControlWorkPhase::Done => return Err(StateError::ControlWorkMismatch),
    }
    let control_outcome = parse_control_outcome(row.get::<_, String>("control_outcome").as_str())?;
    let (current, events) = validate_control_event_chain(client, stored)?;
    let expected_revision = match phase {
        ControlWorkPhase::Evaluate => 2_u64,
        ControlWorkPhase::Issue => 3,
        ControlWorkPhase::Consume => 4,
        ControlWorkPhase::Done => return Err(StateError::ControlWorkMismatch),
    };
    let expected_event = events
        .get(usize::try_from(expected_revision - 1).map_err(|_| {
            StateError::InvalidRecord("control event revision is not representable".to_owned())
        })?)
        .ok_or_else(|| {
            StateError::InvalidRecord("completed phase lacks its exact public event".to_owned())
        })?;
    let (expected_status, expected_reason) = match phase {
        ControlWorkPhase::Evaluate => {
            let status = match control_outcome {
                ControlOutcome::Allow => ControlStatusCode::Authorized,
                ControlOutcome::Deny => ControlStatusCode::ControlDenied,
                ControlOutcome::Manual => return Err(StateError::ControlDecisionMismatch),
            };
            (
                status,
                Some(ControlStatusReason::Decision(decision.receipt.reason())),
            )
        }
        ControlWorkPhase::Issue => (
            ControlStatusCode::AuthorizationIssued,
            Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            )),
        ),
        ControlWorkPhase::Consume => (
            ControlStatusCode::DispatchPending,
            Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            )),
        ),
        ControlWorkPhase::Done => unreachable!(),
    };
    if expected_event.status() != expected_status
        || expected_event.reason() != expected_reason
        || expected_event.observed_at() != receipt.completed_at()
    {
        return Err(StateError::InvalidRecord(
            "completed phase event does not match its exact artifact".to_owned(),
        ));
    }
    let queue_phase: String = row.get("queue_phase");
    let queue_state: String = row.get("queue_state");
    let active_claim: Option<Uuid> = row.get("active_claim_id");
    let projection_matches = match phase {
        ControlWorkPhase::Evaluate if control_outcome == ControlOutcome::Allow => {
            matches!(
                (queue_phase.as_str(), current.status()),
                ("ISSUE", ControlStatusCode::Authorized)
                    | ("CONSUME", ControlStatusCode::AuthorizationIssued)
                    | (
                        "DONE",
                        ControlStatusCode::DispatchPending | ControlStatusCode::FailedClosed
                    )
            )
        }
        ControlWorkPhase::Evaluate => {
            queue_phase == "DONE"
                && queue_state == "DONE"
                && current.status() == ControlStatusCode::ControlDenied
        }
        ControlWorkPhase::Issue => {
            matches!(
                (queue_phase.as_str(), current.status()),
                ("CONSUME", ControlStatusCode::AuthorizationIssued)
                    | (
                        "DONE",
                        ControlStatusCode::DispatchPending | ControlStatusCode::FailedClosed
                    )
            )
        }
        ControlWorkPhase::Consume => {
            queue_phase == "DONE"
                && queue_state == "DONE"
                && current.status() == ControlStatusCode::DispatchPending
        }
        ControlWorkPhase::Done => false,
    };
    let terminal = queue_phase == "DONE";
    if !projection_matches
        || (terminal && (queue_state != "DONE" || active_claim.is_some()))
        || (!terminal
            && (!matches!(queue_state.as_str(), "READY" | "LEASED")
                || (queue_state == "READY" && active_claim.is_some())
                || (queue_state == "LEASED" && active_claim.is_none())))
    {
        return Err(StateError::InvalidRecord(
            "completed control phase lacks its exact projection/event lineage".to_owned(),
        ));
    }

    // Older exact claim retries remain recoverable after downstream phases.
    // Prove those later artifacts recursively rather than requiring the
    // projection to remain frozen immediately after this phase.
    if phase == ControlWorkPhase::Evaluate
        && matches!(
            current.status(),
            ControlStatusCode::AuthorizationIssued | ControlStatusCode::DispatchPending
        )
    {
        validate_unique_completed_phase(client, stored, ControlWorkPhase::Issue)?;
    }
    if matches!(phase, ControlWorkPhase::Evaluate | ControlWorkPhase::Issue)
        && current.status() == ControlStatusCode::DispatchPending
    {
        validate_unique_completed_phase(client, stored, ControlWorkPhase::Consume)?;
    }
    if current.status() == ControlStatusCode::FailedClosed {
        let rows = client.query(
            "SELECT claim_id FROM public.accordlock_control_work_finalizations
              WHERE submission_id=$1",
            &[&stored.submission_id],
        )?;
        if rows.len() != 1
            || validated_finalization(client, stored, rows[0].get("claim_id"))?.is_none()
        {
            return Err(StateError::InvalidRecord(
                "FAILED_CLOSED projection lacks one exact finalization".to_owned(),
            ));
        }
        if phase == ControlWorkPhase::Evaluate
            && parse_phase(
                client
                    .query_one(
                        "SELECT phase FROM public.accordlock_control_work_finalizations
                          WHERE submission_id=$1",
                        &[&stored.submission_id],
                    )?
                    .get::<_, String>("phase")
                    .as_str(),
            )? == ControlWorkPhase::Consume
        {
            validate_unique_completed_phase(client, stored, ControlWorkPhase::Issue)?;
        }
    }
    Ok(Some(receipt))
}

fn validate_unique_completed_phase<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    phase: ControlWorkPhase,
) -> Result<ControlPhaseCompletionReceipt, StateError> {
    let rows = client.query(
        "SELECT claim_id FROM public.accordlock_control_phase_completions
          WHERE submission_id=$1 AND phase=$2",
        &[&stored.submission_id, &phase_sql(phase)],
    )?;
    if rows.len() != 1 {
        return Err(StateError::InvalidRecord(
            "control phase has missing or ambiguous completion history".to_owned(),
        ));
    }
    validated_phase_completion(client, stored, rows[0].get("claim_id"))?
        .ok_or_else(|| StateError::InvalidRecord("control phase completion disappeared".to_owned()))
}

#[allow(clippy::too_many_lines)]
fn validate_current_control_lineage<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    status: &ControlStatusSnapshot,
) -> Result<(), StateError> {
    match status.status() {
        ControlStatusCode::Accepted => {
            let row = client.query_one(
                "SELECT
                    EXISTS (SELECT 1 FROM public.accordlock_control_evaluations
                             WHERE submission_id=$1) AS has_evaluation,
                    EXISTS (SELECT 1 FROM public.accordlock_control_decisions
                             WHERE submission_id=$1) AS has_decision,
                    (EXISTS (SELECT 1 FROM public.accordlock_control_issuances
                              WHERE submission_id=$1)
                     OR EXISTS (
                         SELECT 1 FROM public.accordlock_issued_authorizations
                          WHERE issuance_profile_version=2
                            AND ((tenant=$2 AND environment=$3 AND request_id=$4)
                                 OR evaluation_nonce=$5)
                     )) AS has_issuance,
                    EXISTS (SELECT 1 FROM public.accordlock_control_consumptions
                             WHERE submission_id=$1) AS has_consumption,
                    EXISTS (SELECT 1 FROM public.accordlock_control_phase_completions
                             WHERE submission_id=$1) AS has_completion,
                    EXISTS (SELECT 1 FROM public.accordlock_control_work_finalizations
                             WHERE submission_id=$1) AS has_finalization",
                &[
                    &stored.submission_id,
                    &stored.tenant,
                    &stored.environment,
                    &stored.proposal.request_id,
                    &stored.evaluation_nonce,
                ],
            )?;
            if row.get::<_, bool>("has_evaluation")
                || row.get::<_, bool>("has_decision")
                || row.get::<_, bool>("has_issuance")
                || row.get::<_, bool>("has_consumption")
                || row.get::<_, bool>("has_completion")
                || row.get::<_, bool>("has_finalization")
            {
                return Err(StateError::InvalidRecord(
                    "ACCEPTED projection has a partial downstream control artifact".to_owned(),
                ));
            }
        }
        ControlStatusCode::Authorized => {
            let completion =
                validate_unique_completed_phase(client, stored, ControlWorkPhase::Evaluate)?;
            let decision = load_decision(client, stored)?;
            if decision.receipt.control_outcome() != ControlOutcome::Allow
                || completion.decision_id() != decision.receipt.decision_id()
            {
                return Err(StateError::ControlDecisionMismatch);
            }
            let partial = client.query_one(
                "SELECT
                    (EXISTS (SELECT 1 FROM public.accordlock_control_issuances
                              WHERE submission_id=$1)
                     OR EXISTS (
                         SELECT 1 FROM public.accordlock_issued_authorizations
                          WHERE issuance_profile_version=2
                            AND ((tenant=$2 AND environment=$3 AND request_id=$4)
                                 OR evaluation_nonce=$5)
                     )) AS has_issuance,
                    EXISTS (SELECT 1 FROM public.accordlock_control_consumptions
                             WHERE submission_id=$1) AS has_consumption,
                    EXISTS (SELECT 1 FROM public.accordlock_control_work_finalizations
                             WHERE submission_id=$1) AS has_finalization",
                &[
                    &stored.submission_id,
                    &stored.tenant,
                    &stored.environment,
                    &stored.proposal.request_id,
                    &stored.evaluation_nonce,
                ],
            )?;
            if partial.get::<_, bool>("has_issuance")
                || partial.get::<_, bool>("has_consumption")
                || partial.get::<_, bool>("has_finalization")
            {
                return Err(StateError::InvalidRecord(
                    "AUTHORIZED projection has a partial downstream control artifact".to_owned(),
                ));
            }
        }
        ControlStatusCode::AuthorizationIssued => {
            validate_unique_completed_phase(client, stored, ControlWorkPhase::Evaluate)?;
            validate_unique_completed_phase(client, stored, ControlWorkPhase::Issue)?;
            let (key, _) = load_control_issued(client, stored)?;
            let partial = client.query_one(
                "SELECT
                    issued.state,
                    EXISTS (SELECT 1 FROM public.accordlock_control_consumptions
                             WHERE submission_id=$1) AS has_control_consumption,
                    EXISTS (SELECT 1 FROM public.accordlock_consumptions
                             WHERE tenant=$2 AND environment=$3
                               AND authorization_id=$4 AND transaction_id=$5) AS has_receipt,
                    EXISTS (SELECT 1 FROM public.accordlock_execution_outbox
                             WHERE tenant=$2 AND environment=$3
                               AND authorization_id=$4 AND transaction_id=$5) AS has_outbox,
                    EXISTS (SELECT 1 FROM public.accordlock_control_work_finalizations
                             WHERE submission_id=$1) AS has_finalization
                   FROM public.accordlock_issued_authorizations AS issued
                  WHERE issued.tenant=$2 AND issued.environment=$3
                    AND issued.authorization_id=$4 AND issued.transaction_id=$5",
                &[
                    &stored.submission_id,
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )?;
            if partial.get::<_, String>("state") != "ISSUED"
                || partial.get::<_, bool>("has_control_consumption")
                || partial.get::<_, bool>("has_receipt")
                || partial.get::<_, bool>("has_outbox")
                || partial.get::<_, bool>("has_finalization")
            {
                return Err(StateError::InvalidRecord(
                    "AUTHORIZATION_ISSUED projection has a partial downstream control artifact"
                        .to_owned(),
                ));
            }
        }
        ControlStatusCode::DispatchPending => {
            validate_unique_completed_phase(client, stored, ControlWorkPhase::Evaluate)?;
            validate_unique_completed_phase(client, stored, ControlWorkPhase::Issue)?;
            validate_unique_completed_phase(client, stored, ControlWorkPhase::Consume)?;
        }
        ControlStatusCode::ControlDenied => {
            let row = client
                .query_opt(
                    "SELECT claim_id,evaluation_id
                       FROM public.accordlock_control_decisions
                      WHERE submission_id=$1",
                    &[&stored.submission_id],
                )?
                .ok_or(StateError::ControlDecisionMismatch)?;
            let claim_id: Uuid = row.get("claim_id");
            if row.get::<_, Option<Uuid>>("evaluation_id").is_some() {
                let completion =
                    validate_unique_completed_phase(client, stored, ControlWorkPhase::Evaluate)?;
                if completion.claim_id() != claim_id {
                    return Err(StateError::ControlDecisionMismatch);
                }
            } else if validated_prekernel_decision(client, stored, claim_id)?.is_none() {
                return Err(StateError::ControlDecisionMismatch);
            }
            let partial = client.query_one(
                "SELECT
                    (EXISTS (SELECT 1 FROM public.accordlock_control_issuances
                              WHERE submission_id=$1)
                     OR EXISTS (
                         SELECT 1 FROM public.accordlock_issued_authorizations
                          WHERE issuance_profile_version=2
                            AND ((tenant=$2 AND environment=$3 AND request_id=$4)
                                 OR evaluation_nonce=$5)
                     )) AS has_issuance,
                    EXISTS (SELECT 1 FROM public.accordlock_control_consumptions
                             WHERE submission_id=$1) AS has_consumption,
                    EXISTS (SELECT 1 FROM public.accordlock_control_work_finalizations
                             WHERE submission_id=$1) AS has_finalization",
                &[
                    &stored.submission_id,
                    &stored.tenant,
                    &stored.environment,
                    &stored.proposal.request_id,
                    &stored.evaluation_nonce,
                ],
            )?;
            if partial.get::<_, bool>("has_issuance")
                || partial.get::<_, bool>("has_consumption")
                || partial.get::<_, bool>("has_finalization")
            {
                return Err(StateError::InvalidRecord(
                    "CONTROL_DENIED projection has an impossible downstream artifact".to_owned(),
                ));
            }
        }
        ControlStatusCode::FailedClosed => {
            // Every post-decision finalization descends from one completed
            // signed EVALUATE. CONSUME additionally descends from ISSUE.
            validate_unique_completed_phase(client, stored, ControlWorkPhase::Evaluate)?;
            let rows = client.query(
                "SELECT claim_id,phase
                   FROM public.accordlock_control_work_finalizations
                  WHERE submission_id=$1",
                &[&stored.submission_id],
            )?;
            if rows.len() != 1 {
                return Err(StateError::InvalidRecord(
                    "FAILED_CLOSED projection lacks one exact finalization".to_owned(),
                ));
            }
            let phase = parse_phase(rows[0].get::<_, String>("phase").as_str())?;
            if validated_finalization(client, stored, rows[0].get("claim_id"))?.is_none() {
                return Err(StateError::InvalidRecord(
                    "FAILED_CLOSED projection finalization disappeared".to_owned(),
                ));
            }
            if phase == ControlWorkPhase::Consume {
                validate_unique_completed_phase(client, stored, ControlWorkPhase::Issue)?;
            }
        }
        ControlStatusCode::ManualResolutionRequired => {
            return Err(StateError::InvalidRecord(
                "manual control status is unreachable in the mono-grant profile".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Authenticates the complete immutable v13 lineage before v14 may expose a
/// dispatch authority or persist an expiry observation.
pub(super) fn validate_dispatch_pending_lineage<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    key: &ConsumeKey,
) -> Result<(), StateError> {
    stored.reverify_frozen_wire()?;
    let (status, _) = validate_control_event_chain(client, stored)?;
    if status.status() != ControlStatusCode::DispatchPending
        || status.reason()
            != Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            ))
        || status.submission_id() != stored.submission_id
        || status.receipt_id() != stored.receipt_id
    {
        return Err(StateError::ControlWorkMismatch);
    }
    validate_current_control_lineage(client, stored, &status)?;
    let consumption = client
        .query_opt(
            "SELECT tenant,environment,authorization_id,transaction_id
               FROM public.accordlock_control_consumptions
              WHERE submission_id=$1",
            &[&stored.submission_id],
        )?
        .ok_or(StateError::ConsumptionNotFound)?;
    if consumption.get::<_, String>("tenant") != key.scope.tenant
        || consumption.get::<_, String>("environment") != key.scope.environment
        || consumption.get::<_, Uuid>("authorization_id") != key.authorization_id
        || consumption.get::<_, Uuid>("transaction_id") != key.transaction_id
    {
        return Err(StateError::ControlWorkMismatch);
    }
    Ok(())
}

/// One-time v13 -> v14 upgrade audit. It reuses the production Rust decoders,
/// COSE verification, canonical commitments, full control event chain, and
/// immutable dispatch binding before SQL source-freeze triggers become the
/// durable post-upgrade barrier.
pub(super) fn validate_migrated_dispatch_source<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    key: &ConsumeKey,
) -> Result<(), StateError> {
    validate_dispatch_pending_lineage(client, stored, key)?;
    let success = load_completed_control_consumption(client, stored, key)?;
    let grant = load_grant(
        client,
        &key.scope,
        success.issued().authorization().grant_id,
    )?;
    validate_dispatch_immutable_facts(
        key,
        &grant,
        success.issued(),
        success.receipt(),
        success.outbox(),
    )
}

#[allow(clippy::too_many_lines)]
fn validated_finalization<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    claim_id: Uuid,
) -> Result<Option<ControlWorkFinalizationReceipt>, StateError> {
    let row = client.query_opt(
        "SELECT finalization.submission_id,finalization.phase,finalization.reason,
                finalization.decision_id,finalization.issuance_authorization_id,
                finalization.issuance_transaction_id,
                finalization.finalized_at,queue.phase AS queue_phase,
                queue.state AS queue_state,queue.active_claim_id,
                status.status,status.reason_kind,status.reason_code,
                status.observed_at,event.status AS event_status,
                event.reason_kind AS event_reason_kind,
                event.reason_code AS event_reason_code,
                event.observed_at AS event_observed_at
           FROM public.accordlock_control_work_finalizations AS finalization
           JOIN public.accordlock_control_work_queue AS queue
             ON queue.submission_id=finalization.submission_id
           JOIN public.accordlock_control_status AS status
             ON status.submission_id=finalization.submission_id
           JOIN public.accordlock_control_events AS event
             ON event.submission_id=status.submission_id
            AND event.revision=status.revision
          WHERE finalization.claim_id=$1",
        &[&claim_id],
    )?;
    let Some(row) = row else {
        return Ok(None);
    };
    let (current, _) = validate_control_event_chain(client, stored)?;
    let decision = load_decision(client, stored)?;
    let phase = parse_phase(row.get::<_, String>("phase").as_str())?;
    if decision.receipt.control_outcome() != ControlOutcome::Allow
        || decision.signed_evaluation.is_none()
        || row.get::<_, Uuid>("decision_id") != decision.receipt.decision_id()
    {
        return Err(StateError::ControlDecisionMismatch);
    }
    match phase {
        ControlWorkPhase::Issue => {
            let partial = client.query_one(
                "SELECT
                    EXISTS (SELECT 1 FROM public.accordlock_control_issuances
                             WHERE submission_id=$1) AS has_control_issuance,
                    EXISTS (
                        SELECT 1 FROM public.accordlock_issued_authorizations
                         WHERE issuance_profile_version=2
                           AND ((tenant=$2 AND environment=$3 AND request_id=$4)
                                OR evaluation_nonce=$5)
                    ) AS has_authorization",
                &[
                    &stored.submission_id,
                    &stored.tenant,
                    &stored.environment,
                    &stored.proposal.request_id,
                    &stored.evaluation_nonce,
                ],
            )?;
            if partial.get::<_, bool>("has_control_issuance")
                || partial.get::<_, bool>("has_authorization")
            {
                return Err(StateError::InvalidRecord(
                    "fail-closed ISSUE history coexists with authorization material".to_owned(),
                ));
            }
        }
        ControlWorkPhase::Consume => {
            let (key, _) = load_control_issued(client, stored)?;
            if row.get::<_, Option<Uuid>>("issuance_authorization_id") != Some(key.authorization_id)
                || row.get::<_, Option<Uuid>>("issuance_transaction_id") != Some(key.transaction_id)
            {
                return Err(StateError::InvalidRecord(
                    "CONSUME finalization lacks its exact issuance lineage".to_owned(),
                ));
            }
            let partial = client.query_one(
                "SELECT
                    issued.state,
                    EXISTS (SELECT 1 FROM public.accordlock_control_consumptions
                             WHERE submission_id=$1) AS has_control_consumption,
                    EXISTS (SELECT 1 FROM public.accordlock_consumptions
                             WHERE tenant=$2 AND environment=$3
                               AND authorization_id=$4 AND transaction_id=$5) AS has_receipt,
                    EXISTS (SELECT 1 FROM public.accordlock_execution_outbox
                             WHERE tenant=$2 AND environment=$3
                               AND authorization_id=$4 AND transaction_id=$5) AS has_outbox
                   FROM public.accordlock_issued_authorizations AS issued
                  WHERE issued.tenant=$2 AND issued.environment=$3
                    AND issued.authorization_id=$4 AND issued.transaction_id=$5",
                &[
                    &stored.submission_id,
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )?;
            if partial.get::<_, String>("state") != "ISSUED"
                || partial.get::<_, bool>("has_control_consumption")
                || partial.get::<_, bool>("has_receipt")
                || partial.get::<_, bool>("has_outbox")
            {
                return Err(StateError::InvalidRecord(
                    "fail-closed CONSUME history coexists with consumption material".to_owned(),
                ));
            }
        }
        ControlWorkPhase::Evaluate | ControlWorkPhase::Done => {
            return Err(StateError::ControlWorkMismatch);
        }
    }
    if row.get::<_, Uuid>("submission_id") != stored.submission_id
        || row.get::<_, String>("queue_phase") != "DONE"
        || row.get::<_, String>("queue_state") != "DONE"
        || row.get::<_, Option<Uuid>>("active_claim_id").is_some()
        || current.status() != ControlStatusCode::FailedClosed
        || current.reason()
            != Some(ControlStatusReason::Finalization(
                parse_finalization_reason(row.get::<_, String>("reason").as_str())?,
            ))
        || current.observed_at() != row.get::<_, i64>("finalized_at")
        || row.get::<_, String>("status") != "FAILED_CLOSED"
        || row.get::<_, Option<String>>("reason_kind").as_deref() != Some("FINALIZATION")
        || row.get::<_, Option<String>>("reason_code") != Some(row.get::<_, String>("reason"))
        || row.get::<_, String>("event_status") != "FAILED_CLOSED"
        || row.get::<_, Option<String>>("event_reason_kind").as_deref() != Some("FINALIZATION")
        || row.get::<_, Option<String>>("event_reason_code") != Some(row.get::<_, String>("reason"))
        || row.get::<_, i64>("observed_at") != row.get::<_, i64>("finalized_at")
        || row.get::<_, i64>("event_observed_at") != row.get::<_, i64>("finalized_at")
    {
        return Err(StateError::InvalidRecord(
            "control work finalization lacks exact terminal projection lineage".to_owned(),
        ));
    }
    Ok(Some(ControlWorkFinalizationReceipt::new(
        stored.submission_id,
        phase,
        parse_finalization_reason(row.get::<_, String>("reason").as_str())?,
        row.get("finalized_at"),
    )))
}

fn validated_prekernel_decision<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
    claim_id: Uuid,
) -> Result<Option<ControlDecisionReceipt>, StateError> {
    let decision = client.query_opt(
        "SELECT decision_id FROM public.accordlock_control_decisions
          WHERE submission_id=$1 AND claim_id=$2 AND evaluation_id IS NULL",
        &[&stored.submission_id, &claim_id],
    )?;
    if decision.is_none() {
        return Ok(None);
    }
    let impossible_history = client.query_one(
        "SELECT
            EXISTS (SELECT 1 FROM public.accordlock_control_evaluations
                     WHERE submission_id=$1) AS has_evaluation,
            EXISTS (SELECT 1 FROM public.accordlock_control_phase_completions
                     WHERE submission_id=$1 AND phase='EVALUATE') AS has_completion",
        &[&stored.submission_id],
    )?;
    if impossible_history.get::<_, bool>("has_evaluation")
        || impossible_history.get::<_, bool>("has_completion")
    {
        return Err(StateError::InvalidRecord(
            "pre-kernel decision has an impossible signed-evaluation history".to_owned(),
        ));
    }
    let stored_decision = load_decision(client, stored)?;
    let (status, _) = validate_control_event_chain(client, stored)?;
    let queue = client.query_one(
        "SELECT phase,state,active_claim_id FROM public.accordlock_control_work_queue
          WHERE submission_id=$1",
        &[&stored.submission_id],
    )?;
    if stored_decision.evaluation_id.is_some()
        || stored_decision.receipt.control_outcome() != ControlOutcome::Deny
        || status.status() != ControlStatusCode::ControlDenied
        || status.reason()
            != Some(ControlStatusReason::Decision(
                stored_decision.receipt.reason(),
            ))
        || status.observed_at() != stored_decision.receipt.decided_at()
        || queue.get::<_, String>("phase") != "DONE"
        || queue.get::<_, String>("state") != "DONE"
        || queue.get::<_, Option<Uuid>>("active_claim_id").is_some()
    {
        return Err(StateError::ControlDecisionMismatch);
    }
    Ok(Some(stored_decision.receipt))
}

fn insert_phase_completion(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    lease: &ControlWorkLease,
    decision_id: Uuid,
    evaluation_id: Option<Uuid>,
    completed_at: i64,
    consume_key: Option<&ConsumeKey>,
) -> Result<(), StateError> {
    let fence = i64::try_from(lease.fence).map_err(|_| StateError::ControlWorkFenceExhausted)?;
    let evaluation_artifact_at =
        (lease.phase == ControlWorkPhase::Evaluate).then_some(completed_at);
    let issuance_artifact_at = (lease.phase == ControlWorkPhase::Issue).then_some(completed_at);
    let consumption_artifact_at =
        (lease.phase == ControlWorkPhase::Consume).then_some(completed_at);
    let consume_authorization_id = consume_key.map(|key| key.authorization_id);
    let consume_transaction_id = consume_key.map(|key| key.transaction_id);
    transaction.execute(
        "INSERT INTO public.accordlock_control_phase_completions
                    (claim_id,submission_id,phase,fence,worker_id,completed_at,
                     decision_id,evaluation_id,evaluation_artifact_at,
                     issuance_artifact_at,consumption_artifact_at,tenant,environment,
                     consume_authorization_id,consume_transaction_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        &[
            &lease.claim_id,
            &stored.submission_id,
            &phase_sql(lease.phase),
            &fence,
            &lease.worker_id,
            &completed_at,
            &decision_id,
            &evaluation_id,
            &evaluation_artifact_at,
            &issuance_artifact_at,
            &consumption_artifact_at,
            &stored.tenant,
            &stored.environment,
            &consume_authorization_id,
            &consume_transaction_id,
        ],
    )?;
    Ok(())
}

fn finalize_pre_kernel(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    lease: &ControlWorkLease,
    reason: ControlDecisionReason,
    now: i64,
) -> Result<ControlDecisionReceipt, StateError> {
    let decision_id = derive_control_decision_id(
        stored.state_instance_id,
        stored.submission_id,
        stored.evaluation_nonce,
    );
    let receipt = ControlDecisionReceipt::new(
        decision_id,
        stored.submission_id,
        None,
        ControlOutcome::Deny,
        reason,
        None,
        now,
    );
    let commitment = control_decision_commitment(lease.claim_id, &stored.scope(), &receipt)?;
    transaction.execute(
        "INSERT INTO public.accordlock_control_decisions
                    (decision_id,submission_id,claim_id,claim_phase,evaluation_id,
                     kernel_outcome,control_outcome,reason,selected_grant_id,
                     tenant,environment,decided_at,decision_commitment)
             VALUES ($1,$2,$3,'EVALUATE',NULL,NULL,'DENY',$4,NULL,$5,$6,$7,$8)",
        &[
            &decision_id,
            &stored.submission_id,
            &lease.claim_id,
            &decision_reason_sql(reason),
            &stored.tenant,
            &stored.environment,
            &now,
            &commitment.to_string(),
        ],
    )?;
    insert_or_advance_control_status(
        transaction,
        stored,
        ControlStatusCode::ControlDenied,
        Some(ControlStatusReason::Decision(reason)),
        now,
    )?;
    let updated = transaction.execute(
        "UPDATE public.accordlock_control_work_queue
            SET phase='DONE',state='DONE',active_claim_id=NULL,
                updated_at=clock_timestamp()
          WHERE submission_id=$1 AND phase='EVALUATE' AND state='LEASED'
            AND active_claim_id=$2",
        &[&stored.submission_id, &lease.claim_id],
    )?;
    if updated != 1 {
        return Err(StateError::ControlWorkMismatch);
    }
    Ok(receipt)
}

fn finalize_post_decision(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    lease: &ControlWorkLease,
    decision: &StoredControlDecision,
    reason: ControlWorkFinalizationReason,
    now: i64,
) -> Result<ControlWorkFinalizationReceipt, StateError> {
    if decision.receipt.control_outcome() != ControlOutcome::Allow {
        return Err(StateError::ControlDecisionMismatch);
    }
    let issuance = if lease.phase == ControlWorkPhase::Consume {
        let row = transaction
            .query_opt(
                "SELECT authorization_id,transaction_id FROM public.accordlock_control_issuances
                  WHERE submission_id=$1 FOR SHARE",
                &[&stored.submission_id],
            )?
            .ok_or(StateError::AuthorizationNotFound)?;
        Some((
            row.get::<_, Uuid>("authorization_id"),
            row.get::<_, Uuid>("transaction_id"),
        ))
    } else {
        None
    };
    let (issuance_authorization_id, issuance_transaction_id) = issuance
        .map_or((None, None), |(authorization_id, transaction_id)| {
            (Some(authorization_id), Some(transaction_id))
        });
    transaction.execute(
        "INSERT INTO public.accordlock_control_work_finalizations
                    (submission_id,claim_id,phase,decision_id,decision_outcome,
                     tenant,environment,issuance_authorization_id,issuance_transaction_id,
                     reason,finalized_at)
             VALUES ($1,$2,$3,$4,'ALLOW',$5,$6,$7,$8,$9,$10)",
        &[
            &stored.submission_id,
            &lease.claim_id,
            &phase_sql(lease.phase),
            &decision.receipt.decision_id(),
            &stored.tenant,
            &stored.environment,
            &issuance_authorization_id,
            &issuance_transaction_id,
            &finalization_reason_sql(reason),
            &now,
        ],
    )?;
    insert_or_advance_control_status(
        transaction,
        stored,
        ControlStatusCode::FailedClosed,
        Some(ControlStatusReason::Finalization(reason)),
        now,
    )?;
    let updated = transaction.execute(
        "UPDATE public.accordlock_control_work_queue
            SET phase='DONE',state='DONE',active_claim_id=NULL,
                updated_at=clock_timestamp()
          WHERE submission_id=$1 AND phase=$2 AND state='LEASED'
            AND active_claim_id=$3",
        &[
            &stored.submission_id,
            &phase_sql(lease.phase),
            &lease.claim_id,
        ],
    )?;
    if updated != 1 {
        return Err(StateError::ControlWorkMismatch);
    }
    Ok(ControlWorkFinalizationReceipt::new(
        stored.submission_id,
        lease.phase,
        reason,
        now,
    ))
}

fn load_control_issued<C: GenericClient>(
    client: &mut C,
    stored: &StoredControlSubmission,
) -> Result<(ConsumeKey, IssuedAuthorizationRecord), StateError> {
    let row = client
        .query_opt(
            "SELECT issued.transaction_id,issued.grant_id,issued.record_json,
                    issued.authorization_hash,issued.consume_before,
                    issued.issuance_profile_version,issued.request_id,
                    issued.evaluation_nonce,issued.authorization_id,
                    issuance.request_id AS linked_request_id,
                    issuance.evaluation_nonce AS linked_evaluation_nonce,
                    issuance.authorization_hash AS linked_authorization_hash,
                    issuance.grant_id AS linked_grant_id
               FROM public.accordlock_control_issuances AS issuance
               JOIN public.accordlock_issued_authorizations AS issued
                 ON issued.tenant=issuance.tenant
                AND issued.environment=issuance.environment
                AND issued.authorization_id=issuance.authorization_id
                AND issued.transaction_id=issuance.transaction_id
              WHERE issuance.submission_id=$1",
            &[&stored.submission_id],
        )?
        .ok_or(StateError::AuthorizationNotFound)?;
    let key = ConsumeKey {
        scope: stored.scope(),
        transaction_id: row.get("transaction_id"),
        authorization_id: row.get("authorization_id"),
    };
    let issued = decode_stored_authorization_row(&row, &key)?;
    if row.get::<_, Uuid>("linked_request_id") != issued.authorization().request_id
        || row.get::<_, Uuid>("linked_evaluation_nonce") != issued.authorization().evaluation_nonce
        || row.get::<_, String>("linked_authorization_hash")
            != issued.authorization_hash.to_string()
        || row.get::<_, Uuid>("linked_grant_id") != issued.authorization().grant_id
        || issued.authorization().request_id != stored.proposal.request_id
        || issued.authorization().evaluation_nonce != stored.evaluation_nonce
    {
        return Err(StateError::InvalidRecord(
            "control issuance columns disagree with signed authorization lineage".to_owned(),
        ));
    }
    Ok((key, issued))
}

enum ClaimPreflight {
    Ready,
    DecisionFinalized(ControlDecisionReceipt),
    WorkFinalized(ControlWorkFinalizationReceipt),
}

#[allow(clippy::too_many_lines)]
fn validate_ready_phase_shape(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    phase: ControlWorkPhase,
) -> Result<(), StateError> {
    stored.reverify_frozen_wire()?;
    let status = load_status(transaction, stored.submission_id)?;
    let expected_status = match phase {
        ControlWorkPhase::Evaluate => ControlStatusCode::Accepted,
        ControlWorkPhase::Issue => ControlStatusCode::Authorized,
        ControlWorkPhase::Consume => ControlStatusCode::AuthorizationIssued,
        ControlWorkPhase::Done => return Err(StateError::ControlWorkMismatch),
    };
    if status.status() != expected_status {
        return Err(StateError::ControlWorkMismatch);
    }
    // A terminal row is part of the same atomic phase commit as the DONE
    // queue/status projection. Seeing one while work is still claimable is a
    // partial/corrupt tuple, never permission to mint another capability.
    if transaction
        .query_opt(
            "SELECT 1 FROM public.accordlock_control_work_finalizations
              WHERE submission_id=$1
              LIMIT 1",
            &[&stored.submission_id],
        )?
        .is_some()
    {
        return Err(StateError::InvalidRecord(
            "claimable control work has a partial finalization tuple".to_owned(),
        ));
    }
    match phase {
        ControlWorkPhase::Evaluate => {
            if transaction
                .query_opt(
                    "SELECT 1 FROM public.accordlock_control_evaluations
                      WHERE submission_id=$1
                     UNION ALL
                     SELECT 1 FROM public.accordlock_control_decisions
                      WHERE submission_id=$1
                     LIMIT 1",
                    &[&stored.submission_id],
                )?
                .is_some()
            {
                return Err(StateError::InvalidRecord(
                    "EVALUATE work already has a partial evaluation/decision tuple".to_owned(),
                ));
            }
        }
        ControlWorkPhase::Issue => {
            let decision = load_decision(transaction, stored)?;
            if decision.receipt.control_outcome() != ControlOutcome::Allow
                || decision.signed_evaluation.is_none()
            {
                return Err(StateError::ControlDecisionMismatch);
            }
            if transaction
                .query_opt(
                    "SELECT 1 FROM public.accordlock_control_issuances
                      WHERE submission_id=$1
                      UNION ALL
                     SELECT 1 FROM public.accordlock_issued_authorizations
                      WHERE issuance_profile_version=2
                        AND ((tenant=$2 AND environment=$3 AND request_id=$4)
                             OR evaluation_nonce=$5)
                      LIMIT 1",
                    &[
                        &stored.submission_id,
                        &stored.tenant,
                        &stored.environment,
                        &stored.proposal.request_id,
                        &stored.evaluation_nonce,
                    ],
                )?
                .is_some()
            {
                return Err(StateError::InvalidRecord(
                    "ISSUE work has a pre-existing authorization/control tuple".to_owned(),
                ));
            }
        }
        ControlWorkPhase::Consume => {
            let (key, issued) = load_control_issued(transaction, stored)?;
            let state = transaction.query_one(
                "SELECT state FROM public.accordlock_issued_authorizations
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3 AND transaction_id=$4
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )?;
            if state.get::<_, String>("state") != "ISSUED"
                || issued.authorization().request_id != stored.proposal.request_id
                || transaction
                    .query_opt(
                        "SELECT 1 FROM public.accordlock_control_consumptions
                          WHERE submission_id=$1
                          UNION ALL
                         SELECT 1 FROM public.accordlock_consumptions
                          WHERE tenant=$2 AND environment=$3 AND authorization_id=$4
                            AND transaction_id=$5
                          UNION ALL
                         SELECT 1 FROM public.accordlock_execution_outbox
                          WHERE tenant=$2 AND environment=$3 AND authorization_id=$4
                            AND transaction_id=$5
                          LIMIT 1",
                        &[
                            &stored.submission_id,
                            &key.scope.tenant,
                            &key.scope.environment,
                            &key.authorization_id,
                            &key.transaction_id,
                        ],
                    )?
                    .is_some()
            {
                return Err(StateError::InvalidRecord(
                    "CONSUME work has a pre-existing or partial consumption tuple".to_owned(),
                ));
            }
        }
        ControlWorkPhase::Done => unreachable!(),
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn preflight_claim(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    active: &AuthorityVector,
    lease: &ControlWorkLease,
    now: i64,
) -> Result<ClaimPreflight, StateError> {
    stored.reverify_frozen_wire()?;
    if lease.phase == ControlWorkPhase::Evaluate {
        // Frozen by the TLA RecordBoundaryDeny ordering: authority loss wins
        // when authority and ingress freshness disappear at the same sample.
        if active.principal_registry != stored.ingress_authority_domain {
            return finalize_pre_kernel(
                transaction,
                stored,
                lease,
                ControlDecisionReason::AuthorityChanged,
                now,
            )
            .map(ClaimPreflight::DecisionFinalized);
        }
        if now >= stored.ingress_expires_at {
            return finalize_pre_kernel(
                transaction,
                stored,
                lease,
                ControlDecisionReason::IngressExpired,
                now,
            )
            .map(ClaimPreflight::DecisionFinalized);
        }
        return Ok(ClaimPreflight::Ready);
    }

    let decision = load_decision(transaction, stored)?;
    let evaluation = decision
        .signed_evaluation
        .as_ref()
        .ok_or(StateError::ControlDecisionMismatch)?;
    if decision.receipt.control_outcome() != ControlOutcome::Allow
        || decision.receipt.selected_grant_id().is_none()
    {
        return Err(StateError::ControlDecisionMismatch);
    }
    if active != &evaluation.attestation.authority
        || active.principal_registry != stored.ingress_authority_domain
    {
        return finalize_post_decision(
            transaction,
            stored,
            lease,
            &decision,
            ControlWorkFinalizationReason::AuthorityChanged,
            now,
        )
        .map(ClaimPreflight::WorkFinalized);
    }
    if now >= stored.ingress_expires_at {
        return finalize_post_decision(
            transaction,
            stored,
            lease,
            &decision,
            ControlWorkFinalizationReason::IngressExpired,
            now,
        )
        .map(ClaimPreflight::WorkFinalized);
    }
    if now >= evaluation.attestation.consume_before {
        return finalize_post_decision(
            transaction,
            stored,
            lease,
            &decision,
            ControlWorkFinalizationReason::AuthorizationExpired,
            now,
        )
        .map(ClaimPreflight::WorkFinalized);
    }
    let grant_id = decision
        .receipt
        .selected_grant_id()
        .ok_or(StateError::ControlDecisionMismatch)?;
    // A durable ALLOW decision commits to one exact server-side grant. Its
    // disappearance or payload substitution is structural corruption, not a
    // historical "unavailable" business outcome.
    let grant = load_grant(transaction, &stored.scope(), grant_id)?;
    if !control_grant_allows(&grant.registration.grant, &stored.proposal) {
        return Err(StateError::GrantMismatch);
    }
    if let Err(error) = validate_current_grant(active, &grant, now) {
        let legitimate_loss =
            matches!(error, StateError::GrantRevoked | StateError::GrantExhausted)
                || is_temporal_rejection_for_sample(&error, now);
        if !legitimate_loss {
            return Err(error);
        }
        let reason = if lease.phase == ControlWorkPhase::Consume
            && is_temporal_rejection_for_sample(&error, now)
        {
            ControlWorkFinalizationReason::DispatchWindowExpired
        } else {
            ControlWorkFinalizationReason::GrantUnavailable
        };
        return finalize_post_decision(transaction, stored, lease, &decision, reason, now)
            .map(ClaimPreflight::WorkFinalized);
    }
    if lease.phase == ControlWorkPhase::Consume {
        let (_, issued) = load_control_issued(transaction, stored)?;
        let high_water = PostgresStore::lock_or_create_high_water(transaction, &stored.scope())?;
        if let Err(error) = validate_consumption(active, &grant, &issued, now, Some(high_water)) {
            let reason = match error {
                StateError::AuthorizationExpired { observed, .. } if observed == now => {
                    ControlWorkFinalizationReason::AuthorizationExpired
                }
                ref temporal if is_temporal_rejection_for_sample(temporal, now) => {
                    ControlWorkFinalizationReason::DispatchWindowExpired
                }
                StateError::GrantRevoked | StateError::GrantExhausted => {
                    ControlWorkFinalizationReason::GrantUnavailable
                }
                other => return Err(other),
            };
            return finalize_post_decision(transaction, stored, lease, &decision, reason, now)
                .map(ClaimPreflight::WorkFinalized);
        }
    }
    Ok(ClaimPreflight::Ready)
}

const CLAIM_COLUMNS: &str =
    "claim_id,submission_id,role,phase,worker_id,fence,claimed_at,lease_until";

pub(super) fn lock_control_high_water(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
) -> Result<(IngressReplayScope, i64, i64), StateError> {
    let replay_scope = IngressReplayScope::new(&stored.replay_scope)?;
    let (ingress_state_instance, ingress_high_water) =
        PostgresStore::lock_or_create_ingress_scope(transaction, &replay_scope)?;
    if ingress_state_instance != stored.state_instance_id {
        return Err(StateError::InvalidRecord(
            "control submission and ingress HWM have different state lineage".to_owned(),
        ));
    }
    let scope_high_water = PostgresStore::lock_or_create_high_water(transaction, &stored.scope())?;
    Ok((replay_scope, ingress_high_water, scope_high_water))
}

pub(super) fn advance_control_high_water(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    replay_scope: &IngressReplayScope,
    ingress_high_water: i64,
    observed: i64,
) -> Result<(), StateError> {
    PostgresStore::advance_ingress_high_water(
        transaction,
        replay_scope,
        observed,
        ingress_high_water,
    )?;
    update_scope_high_water(transaction, &stored.scope(), observed)
}

fn exact_claim_history(
    transaction: &mut Transaction<'_>,
    stored: &StoredControlSubmission,
    claim_id: Uuid,
) -> Result<Option<ControlWorkClaimOutcome>, StateError> {
    // Historical claim recovery is time/currentness inert, but never skips
    // authentication of the immutable ingress envelope that created it.
    stored.reverify_frozen_wire()?;
    let completion = validated_phase_completion(transaction, stored, claim_id)?;
    let finalization = validated_finalization(transaction, stored, claim_id)?;
    let prekernel = validated_prekernel_decision(transaction, stored, claim_id)?;
    let historical_count = usize::from(completion.is_some())
        + usize::from(finalization.is_some())
        + usize::from(prekernel.is_some());
    if historical_count > 1 {
        return Err(StateError::InvalidRecord(
            "control claim has conflicting terminal histories".to_owned(),
        ));
    }
    Ok(if let Some(receipt) = completion {
        Some(ControlWorkClaimOutcome::PhaseCompleted(receipt))
    } else if let Some(receipt) = finalization {
        Some(ControlWorkClaimOutcome::WorkFinalized(receipt))
    } else {
        prekernel.map(ControlWorkClaimOutcome::DecisionFinalized)
    })
}

impl PostgresStore {
    #[allow(clippy::too_many_lines)]
    fn claim_control_work_once(
        &self,
        request: &ControlWorkClaimRequest,
    ) -> Result<ControlWorkClaimOutcome, StateError> {
        let recovery_key = ControlWorkClaimRecoveryKey::from_request(request);
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let existing_sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM public.accordlock_control_work_claims \
              WHERE claim_id=$1 FOR SHARE"
        );
        if let Some(claim_row) = transaction.query_opt(&existing_sql, &[&request.claim_id()])? {
            if claim_row.get::<_, String>("worker_id") != request.worker_id()
                || claim_row.get::<_, String>("role") != role_sql(request.role())
                || parse_phase(claim_row.get::<_, String>("phase").as_str())?
                    != request.role().phase()
            {
                return Err(StateError::ControlWorkMismatch);
            }
            let submission_id: Uuid = claim_row.get("submission_id");
            let stored = load_submission_for_update(&mut transaction, submission_id)?;
            if stored.state_instance_id != state_instance_id {
                return Err(StateError::ControlSubmissionMismatch);
            }
            if let Some(history) =
                exact_claim_history(&mut transaction, &stored, request.claim_id())?
            {
                transaction.commit()?;
                return Ok(history);
            }

            let active = load_active_authority(&mut transaction, &stored.scope())?;
            let (replay_scope, ingress_high_water, scope_high_water) =
                lock_control_high_water(&mut transaction, &stored)?;
            let queue = transaction
                .query_opt(
                    "SELECT phase,state,active_claim_id
                       FROM public.accordlock_control_work_queue
                      WHERE submission_id=$1
                      FOR UPDATE",
                    &[&submission_id],
                )?
                .ok_or(StateError::ControlWorkNotFound)?;
            let lease = lease_from_claim_row(&claim_row, state_instance_id)?;
            if queue.get::<_, String>("phase") != phase_sql(lease.phase)
                || queue.get::<_, String>("state") != "LEASED"
                || queue.get::<_, Option<Uuid>>("active_claim_id") != Some(lease.claim_id)
            {
                return Err(StateError::ControlWorkMismatch);
            }
            validate_ready_phase_shape(&mut transaction, &stored, lease.phase)?;
            let observed = Self::sample_trusted_time(&mut transaction)?;
            let high_water = ingress_high_water
                .max(scope_high_water)
                .max(stored.accepted_at);
            if observed < high_water {
                return Err(StateError::ClockRollback {
                    observed,
                    high_water,
                });
            }
            if observed >= lease.lease_until {
                advance_control_high_water(
                    &mut transaction,
                    &stored,
                    &replay_scope,
                    ingress_high_water,
                    observed,
                )?;
                return match transaction.commit() {
                    Ok(()) => Err(StateError::ControlWorkLeaseExpired {
                        observed,
                        lease_until: lease.lease_until,
                    }),
                    Err(_) => Ok(ControlWorkClaimOutcome::OutcomeUnknown(recovery_key)),
                };
            }
            advance_control_high_water(
                &mut transaction,
                &stored,
                &replay_scope,
                ingress_high_water,
                observed,
            )?;
            let outcome =
                match preflight_claim(&mut transaction, &stored, &active, &lease, observed)? {
                    ClaimPreflight::Ready => {
                        ControlWorkClaimOutcome::Recovered(build_control_work(
                            &mut transaction,
                            state_instance_id,
                            &stored,
                            &active,
                            &claim_row,
                        )?)
                    }
                    ClaimPreflight::DecisionFinalized(receipt) => {
                        ControlWorkClaimOutcome::DecisionFinalized(receipt)
                    }
                    ClaimPreflight::WorkFinalized(receipt) => {
                        ControlWorkClaimOutcome::WorkFinalized(receipt)
                    }
                };
            return match transaction.commit() {
                Ok(()) => Ok(outcome),
                Err(_) => Ok(ControlWorkClaimOutcome::OutcomeUnknown(recovery_key)),
            };
        }

        let desired_phase = request.role().phase();
        // Lock the immutable submission root first. Queue triggers take the
        // same root lock, so the subsequent queue/HWM locks cannot observe a
        // phase transition racing this claim.
        let candidate = transaction.query_opt(
            "SELECT submission.submission_id
               FROM public.accordlock_control_submissions AS submission
              WHERE EXISTS (
                    SELECT 1
                      FROM public.accordlock_control_work_queue AS queue
                      LEFT JOIN public.accordlock_control_work_claims AS active
                        ON active.submission_id=queue.submission_id
                       AND active.claim_id=queue.active_claim_id
                     WHERE queue.submission_id=submission.submission_id
                       AND queue.phase=$1
                       AND (
                            queue.state='READY'
                            OR queue.state='LEASED'
                           AND active.lease_until <=
                               floor(extract(epoch FROM clock_timestamp()))::bigint
                       )
              )
              ORDER BY submission.accepted_at,submission.submission_id
              FOR NO KEY UPDATE SKIP LOCKED
              LIMIT 1",
            &[&phase_sql(desired_phase)],
        )?;
        let Some(candidate) = candidate else {
            transaction.commit()?;
            return Ok(ControlWorkClaimOutcome::NoWork);
        };
        let submission_id: Uuid = candidate.get("submission_id");
        let stored = load_submission_for_update(&mut transaction, submission_id)?;
        if stored.state_instance_id != state_instance_id {
            return Err(StateError::ControlSubmissionMismatch);
        }
        validate_ready_phase_shape(&mut transaction, &stored, desired_phase)?;
        let active = load_active_authority(&mut transaction, &stored.scope())?;
        let (replay_scope, ingress_high_water, scope_high_water) =
            lock_control_high_water(&mut transaction, &stored)?;
        let queue = transaction.query_one(
            "SELECT phase,state,active_claim_id
               FROM public.accordlock_control_work_queue
              WHERE submission_id=$1
              FOR UPDATE",
            &[&submission_id],
        )?;
        if queue.get::<_, String>("phase") != phase_sql(desired_phase) {
            return Err(StateError::RetryableConflict);
        }
        let prior_state: String = queue.get("state");
        let prior_claim: Option<Uuid> = queue.get("active_claim_id");
        let prior_lease_until = if prior_state == "LEASED" {
            let prior_claim = prior_claim.ok_or(StateError::ControlWorkMismatch)?;
            Some(
                transaction
                    .query_opt(
                        "SELECT lease_until FROM public.accordlock_control_work_claims
                          WHERE submission_id=$1 AND claim_id=$2 AND phase=$3",
                        &[&submission_id, &prior_claim, &phase_sql(desired_phase)],
                    )?
                    .ok_or(StateError::ControlWorkMismatch)?
                    .get::<_, i64>("lease_until"),
            )
        } else if prior_state == "READY" && prior_claim.is_none() {
            None
        } else {
            return Err(StateError::ControlWorkMismatch);
        };
        let observed = Self::sample_trusted_time(&mut transaction)?;
        let high_water = ingress_high_water
            .max(scope_high_water)
            .max(stored.accepted_at);
        if observed < high_water {
            return Err(StateError::ClockRollback {
                observed,
                high_water,
            });
        }
        if prior_lease_until.is_some_and(|lease_until| observed < lease_until) {
            return Err(StateError::RetryableConflict);
        }
        let lease_until = observed
            .checked_add(CONTROL_WORK_LEASE_SECONDS)
            .ok_or(StateError::DeadlineOverflow)?;
        advance_control_high_water(
            &mut transaction,
            &stored,
            &replay_scope,
            ingress_high_water,
            observed,
        )?;
        let insert_sql = format!(
            "INSERT INTO public.accordlock_control_work_claims
                    (claim_id,submission_id,role,phase,worker_id,claimed_at,lease_until)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             RETURNING {CLAIM_COLUMNS}"
        );
        let claim_row = transaction.query_one(
            &insert_sql,
            &[
                &request.claim_id(),
                &submission_id,
                &role_sql(request.role()),
                &phase_sql(desired_phase),
                &request.worker_id(),
                &observed,
                &lease_until,
            ],
        )?;
        let updated = transaction.execute(
            "UPDATE public.accordlock_control_work_queue
                SET state='LEASED',active_claim_id=$2,updated_at=clock_timestamp()
              WHERE submission_id=$1 AND phase=$3
                AND ((state='READY' AND active_claim_id IS NULL)
                     OR (state='LEASED' AND active_claim_id=$4))",
            &[
                &submission_id,
                &request.claim_id(),
                &phase_sql(desired_phase),
                &prior_claim,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::RetryableConflict);
        }
        let lease = lease_from_claim_row(&claim_row, state_instance_id)?;
        let outcome = match preflight_claim(&mut transaction, &stored, &active, &lease, observed)? {
            ClaimPreflight::Ready => ControlWorkClaimOutcome::Claimed(build_control_work(
                &mut transaction,
                state_instance_id,
                &stored,
                &active,
                &claim_row,
            )?),
            ClaimPreflight::DecisionFinalized(receipt) => {
                ControlWorkClaimOutcome::DecisionFinalized(receipt)
            }
            ClaimPreflight::WorkFinalized(receipt) => {
                ControlWorkClaimOutcome::WorkFinalized(receipt)
            }
        };
        match transaction.commit() {
            Ok(()) => Ok(outcome),
            Err(_) => Ok(ControlWorkClaimOutcome::OutcomeUnknown(recovery_key)),
        }
    }
}
