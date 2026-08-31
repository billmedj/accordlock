use crate::{
    AuthenticatedObserver, AuthorityVersion, BoundObjectObservation, ConsumptionBinding,
    CredentialClaims, CredentialInvalidationEvidence, CredentialProfile, DispatchBounds,
    DispatchClaim, DispatchError, DispatchMachine, EffectBinding, EffectTemplate,
    ExactEffectEvidence, LifecyclePhase, LogicalOwner, NonIssuanceEvidence, PhysicalResourceId,
    PreparedExecution, ProviderOutcome, ReconciliationOutcome,
};
use uuid::Uuid;

const START: i64 = 1_000;

fn authority(epoch: u64) -> AuthorityVersion {
    AuthorityVersion {
        root: [u8::try_from(epoch).unwrap_or(0); 32],
        epoch,
    }
}

fn bounds() -> DispatchBounds {
    DispatchBounds {
        max_dispatch_delay_s: 50,
        token_lifetime_upper_bound_s: 60,
        clock_uncertainty_s: 5,
        minimum_remaining_lifetime_s: 10,
        lease_ttl_s: 10,
    }
}

fn owner(tenant: &str) -> LogicalOwner {
    LogicalOwner {
        tenant: tenant.to_owned(),
        environment: "prod".to_owned(),
    }
}

fn physical() -> PhysicalResourceId {
    PhysicalResourceId {
        cluster_trust_domain: "spiffe://cluster-a".to_owned(),
        api_server_identity: "sha256:api-a".to_owned(),
        namespace: "payments".to_owned(),
        deployment_uid: "opaque-k8s-uid".to_owned(),
    }
}

fn effect_template() -> EffectTemplate {
    EffectTemplate {
        template_hash: [0x31; 32],
        operation_hash: [0x32; 32],
        execution_command_commitment: [0x42; 32],
        final_wire_commitment: [0x43; 32],
    }
}

fn credential_profile() -> CredentialProfile {
    CredentialProfile {
        token_subject: "system:serviceaccount:payments:accordlock-attempt".to_owned(),
        token_audience: "https://kubernetes.default.svc".to_owned(),
        effective_rbac_commitment: [0x41; 32],
    }
}

fn consumption_binding(transaction: Uuid) -> ConsumptionBinding {
    let marker = transaction.as_bytes()[15];
    ConsumptionBinding {
        authorization_id: Uuid::from_u128(transaction.as_u128().saturating_add(0x700)),
        authorization_hash: [marker.wrapping_add(0x33); 32],
        receipt_commitment: [marker.wrapping_add(0x34); 32],
        effect: effect_template(),
    }
}

fn prepared_execution(uid: &str) -> Box<PreparedExecution> {
    Box::new(PreparedExecution {
        bound_object_uid: uid.to_owned(),
        template_hash: effect_template().template_hash,
        operation_hash: effect_template().operation_hash,
        token_subject: "system:serviceaccount:payments:accordlock-attempt".to_owned(),
        token_audience: "https://kubernetes.default.svc".to_owned(),
        effective_rbac_commitment: [0x41; 32],
        execution_command_commitment: effect_template().execution_command_commitment,
        final_wire_commitment: effect_template().final_wire_commitment,
    })
}

fn credential_claims(
    uid: &str,
    token_digest: [u8; 32],
    not_before: i64,
    expires_at: i64,
) -> CredentialClaims {
    CredentialClaims {
        token_digest,
        subject: "system:serviceaccount:payments:accordlock-attempt".to_owned(),
        audience: "https://kubernetes.default.svc".to_owned(),
        service_account_uid: "service-account-uid".to_owned(),
        credential_id: "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc".to_owned(),
        bound_object_uid: uid.to_owned(),
        not_before,
        expires_at,
    }
}

fn effect_binding() -> EffectBinding {
    EffectBinding {
        template_hash: effect_template().template_hash,
        operation_hash: effect_template().operation_hash,
        execution_command_commitment: effect_template().execution_command_commitment,
        final_wire_commitment: effect_template().final_wire_commitment,
        effective_rbac_commitment: credential_profile().effective_rbac_commitment,
        token_digest: [9; 32],
    }
}

fn exact_effect_evidence(transaction: Uuid, observed_at: i64) -> ExactEffectEvidence {
    ExactEffectEvidence {
        transaction_id: transaction,
        physical: physical(),
        binding: effect_binding(),
        response_commitment: [0x61; 32],
        post_state_commitment: [0x62; 32],
        observed_resource_uid: physical().deployment_uid,
        observed_resource_version: "1002".to_owned(),
        observed_at,
        observer: AuthenticatedObserver {
            identity: "spiffe://audit.example/workload/accordlock-observer".to_owned(),
            authentication_commitment: [0x63; 32],
        },
    }
}

fn non_issuance_evidence(transaction: Uuid, bound_object_uid: Option<&str>) -> NonIssuanceEvidence {
    NonIssuanceEvidence {
        transaction_id: transaction,
        physical: physical(),
        bound_object_name: format!("accordlock-{}", transaction.simple()),
        bound_object_uid: bound_object_uid.map(str::to_owned),
        template_hash: effect_template().template_hash,
        operation_hash: effect_template().operation_hash,
        evidence_commitment: [0x51; 32],
    }
}

fn invalidation_evidence(
    transaction: Uuid,
    uid: &str,
    token_digest: Option<[u8; 32]>,
) -> CredentialInvalidationEvidence {
    CredentialInvalidationEvidence {
        transaction_id: transaction,
        physical: physical(),
        bound_object_name: format!("accordlock-{}", transaction.simple()),
        bound_object_uid: uid.to_owned(),
        token_digest,
        template_hash: effect_template().template_hash,
        operation_hash: effect_template().operation_hash,
        execution_command_commitment: effect_template().execution_command_commitment,
        final_wire_commitment: effect_template().final_wire_commitment,
        effective_rbac_commitment: credential_profile().effective_rbac_commitment,
        evidence_commitment: [0x52; 32],
    }
}

fn machine() -> Result<DispatchMachine, DispatchError> {
    let mut machine = DispatchMachine::new(bounds(), authority(1), START)?;
    machine.register_destination(physical(), owner("tenant-a"), credential_profile())?;
    Ok(machine)
}

fn record_consumed(
    machine: &mut DispatchMachine,
    transaction: Uuid,
    consumed_at: i64,
) -> Result<(), DispatchError> {
    machine.record_consumption(
        transaction,
        owner("tenant-a"),
        physical(),
        authority(1),
        consumption_binding(transaction),
        consumed_at,
        START + 50,
    )
}

fn prepared(
    machine: &mut DispatchMachine,
    transaction: Uuid,
) -> Result<DispatchClaim, DispatchError> {
    record_consumed(machine, transaction, START)?;
    machine.prepare_dispatch(transaction, "worker-a", START + 1)
}

fn credential_ready(
    machine: &mut DispatchMachine,
    transaction: Uuid,
) -> Result<DispatchClaim, DispatchError> {
    let claim = prepared(machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("server-uid")),
    )?;
    machine.begin_credential_issue(transaction, &claim, START + 3)?;
    machine.record_credential_ready(
        transaction,
        &claim,
        START + 4,
        &credential_claims("server-uid", [9; 32], START + 3, START + 40),
    )?;
    Ok(claim)
}

fn executing(
    machine: &mut DispatchMachine,
    transaction: Uuid,
) -> Result<DispatchClaim, DispatchError> {
    let claim = credential_ready(machine, transaction)?;
    machine.release_effect(transaction, &claim, &effect_binding(), START + 5)?;
    machine.begin_provider_attempt(transaction, &claim, &effect_binding(), START + 6)?;
    Ok(claim)
}

fn assert_provider_evidence_rejected(
    machine: &mut DispatchMachine,
    transaction: Uuid,
    claim: &DispatchClaim,
    evidence: ExactEffectEvidence,
    expected: DispatchError,
) -> Result<(), DispatchError> {
    assert_eq!(
        machine.record_provider_outcome(
            transaction,
            claim,
            START + 7,
            ProviderOutcome::Success {
                evidence: Box::new(evidence),
            },
        ),
        Err(expected)
    );
    assert_eq!(machine.phase(transaction)?, LifecyclePhase::Executing);
    assert_eq!(
        machine
            .effect_evidence_snapshot(transaction)?
            .evidence_commitment,
        None
    );
    Ok(())
}

#[test]
fn logical_alias_cannot_split_one_physical_resource() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let result = machine.register_destination(physical(), owner("tenant-b"), credential_profile());
    assert_eq!(result, Err(DispatchError::AliasConflict));
    Ok(())
}

#[test]
fn malformed_physical_identity_is_rejected() -> Result<(), DispatchError> {
    let mut machine = DispatchMachine::new(bounds(), authority(1), START)?;
    let mut malformed = physical();
    malformed.deployment_uid = "  ".to_owned();
    assert_eq!(
        machine.register_destination(malformed, owner("tenant-a"), credential_profile()),
        Err(DispatchError::InvalidIdentity)
    );
    Ok(())
}

#[test]
fn only_one_transaction_reserves_a_physical_resource() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    let _claim = prepared(&mut machine, first)?;
    record_consumed(&mut machine, second, START + 1)?;
    let result = machine.prepare_dispatch(second, "worker-b", START + 2);
    assert_eq!(result, Err(DispatchError::ResourceBusy));
    assert_eq!(
        machine.phase(second)?,
        LifecyclePhase::DispatchWaitingResource
    );
    Ok(())
}

#[test]
fn stale_fence_cannot_advance_credential_state() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(3);
    let stale = prepared(&mut machine, transaction)?;
    let current = machine.take_over_expired_lease(transaction, "worker-b", START + 11)?;
    machine.begin_bound_object_create(transaction, &current, START + 11)?;
    let stale_result = machine.resolve_bound_object(
        transaction,
        &stale,
        START + 11,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    );
    assert_eq!(stale_result, Err(DispatchError::StaleLease));
    machine.resolve_bound_object(
        transaction,
        &current,
        START + 11,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    Ok(())
}

#[test]
fn authority_change_cancels_final_release() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(4);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.activate_authority(authority(2))?;
    let result = machine.release_effect(transaction, &claim, &effect_binding(), START + 5);
    assert_eq!(result, Err(DispatchError::AuthorityChanged));
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ReleaseCancelled
    );
    assert!(machine.resource_is_reserved(&physical()));
    Ok(())
}

#[test]
fn emergency_stop_cancels_final_release() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(5);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.set_emergency_stop(true)?;
    let result = machine.release_effect(transaction, &claim, &effect_binding(), START + 5);
    assert_eq!(result, Err(DispatchError::EmergencyStop));
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ReleaseCancelled
    );
    Ok(())
}

#[test]
fn clearing_emergency_stop_does_not_resurrect_pre_stop_attempt() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(18);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.set_emergency_stop(true)?;
    machine.set_emergency_stop(false)?;
    assert_eq!(
        machine.release_effect(transaction, &claim, &effect_binding(), START + 5),
        Err(DispatchError::EmergencyStop)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ReleaseCancelled
    );
    Ok(())
}

#[test]
fn server_extended_token_lifetime_is_rejected() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(6);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.begin_credential_issue(transaction, &claim, START + 3)?;
    let result = machine.record_credential_ready(
        transaction,
        &claim,
        START + 4,
        &credential_claims("uid", [1; 32], START + 3, START + 69),
    );
    assert_eq!(result, Err(DispatchError::InvalidCredential));
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialInvalidating
    );
    Ok(())
}

#[test]
fn unknown_token_issue_cannot_retry_and_holds_reservation() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(7);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.begin_credential_issue(transaction, &claim, START + 3)?;
    machine.mark_credential_issue_unknown(transaction, &claim, START + 4)?;
    assert_eq!(
        machine.begin_credential_issue(transaction, &claim, START + 5),
        Err(DispatchError::InvalidTransition)
    );
    machine.confirm_credential_invalidation(
        transaction,
        &invalidation_evidence(transaction, "uid", None),
        START + 5,
    )?;
    assert_eq!(
        machine.finish_quarantined_credential(transaction, START + 68),
        Err(DispatchError::CredentialStillLive)
    );
    assert!(machine.resource_is_reserved(&physical()));
    machine.finish_quarantined_credential(transaction, START + 69)?;
    assert!(!machine.resource_is_reserved(&physical()));
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::TransactionFinal
    );
    Ok(())
}

#[test]
fn ambiguous_provider_result_never_allows_a_second_attempt() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(8);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.release_effect(transaction, &claim, &effect_binding(), START + 5)?;
    machine.begin_provider_attempt(transaction, &claim, &effect_binding(), START + 6)?;
    machine.record_provider_outcome(transaction, &claim, START + 7, ProviderOutcome::Unknown)?;
    assert_eq!(
        machine.begin_provider_attempt(transaction, &claim, &effect_binding(), START + 8),
        Err(DispatchError::InvalidTransition)
    );
    machine.begin_effect_reconciliation(transaction, START + 8)?;
    assert_eq!(
        machine.resolve_effect_reconciliation(
            transaction,
            ReconciliationOutcome::NoEffectNotEstablished,
            START + 9,
        ),
        Ok(())
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ManualResolutionRequired
    );
    assert!(machine.resource_is_reserved(&physical()));
    Ok(())
}

#[test]
fn exact_reconciled_effect_finalizes_only_after_credential_retirement() -> Result<(), DispatchError>
{
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(9);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.release_effect(transaction, &claim, &effect_binding(), START + 5)?;
    machine.begin_provider_attempt(transaction, &claim, &effect_binding(), START + 6)?;
    machine.record_provider_outcome(transaction, &claim, START + 7, ProviderOutcome::Unknown)?;
    machine.begin_effect_reconciliation(transaction, START + 8)?;
    machine.resolve_effect_reconciliation(
        transaction,
        ReconciliationOutcome::ExactEffect {
            evidence: Box::new(exact_effect_evidence(transaction, START + 9)),
        },
        START + 9,
    )?;
    machine.confirm_credential_invalidation(
        transaction,
        &invalidation_evidence(transaction, "server-uid", Some([9; 32])),
        START + 10,
    )?;
    assert_eq!(
        machine.finalize_terminal_effect(transaction, START + 67),
        Err(DispatchError::CredentialStillLive)
    );
    machine.finalize_terminal_effect(transaction, START + 68)?;
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::TransactionFinal
    );
    Ok(())
}

#[test]
fn trusted_time_rollback_is_rejected_across_phases() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(10);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.begin_credential_issue(transaction, &claim, START + 5)?;
    assert_eq!(
        machine.mark_credential_issue_unknown(transaction, &claim, START + 4),
        Err(DispatchError::InvalidTime)
    );
    Ok(())
}

#[test]
fn authority_activation_and_consumption_are_monotone() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    machine.activate_authority(authority(2))?;
    assert_eq!(
        machine.activate_authority(authority(1)),
        Err(DispatchError::AuthorityRollback)
    );
    assert_eq!(
        machine.record_consumption(
            Uuid::from_u128(11),
            owner("tenant-a"),
            physical(),
            authority(1),
            consumption_binding(Uuid::from_u128(11)),
            START,
            START + 50,
        ),
        Err(DispatchError::AuthorityChanged)
    );
    Ok(())
}

#[test]
fn caller_cannot_widen_the_dispatch_deadline() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    assert_eq!(
        machine.record_consumption(
            Uuid::from_u128(17),
            owner("tenant-a"),
            physical(),
            authority(1),
            consumption_binding(Uuid::from_u128(17)),
            START,
            START + 51,
        ),
        Err(DispatchError::DeadlineExpired)
    );
    Ok(())
}

#[test]
fn lease_loss_after_effect_release_becomes_unknown_without_takeover() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(12);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.release_effect(transaction, &claim, &effect_binding(), START + 5)?;
    assert_eq!(
        machine.take_over_expired_lease(transaction, "worker-b", START + 11),
        Err(DispatchError::InvalidTransition)
    );
    machine.recover_expired_lease(transaction, START + 11)?;
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ExecutionUnknown
    );
    assert_eq!(
        machine.begin_provider_attempt(transaction, &claim, &effect_binding(), START + 11),
        Err(DispatchError::StaleLease)
    );
    Ok(())
}

#[test]
fn lease_loss_with_ready_token_requires_invalidation() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(13);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.recover_expired_lease(transaction, START + 11)?;
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialInvalidating
    );
    assert_eq!(
        machine.release_effect(transaction, &claim, &effect_binding(), START + 11),
        Err(DispatchError::StaleLease)
    );
    machine.confirm_credential_invalidation(
        transaction,
        &invalidation_evidence(transaction, "server-uid", Some([9; 32])),
        START + 12,
    )?;
    assert_eq!(
        machine.finish_quarantined_credential(transaction, START + 67),
        Err(DispatchError::CredentialStillLive)
    );
    machine.finish_quarantined_credential(transaction, START + 68)?;
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::TransactionFinal
    );
    Ok(())
}

#[test]
fn crash_after_create_send_can_only_reconcile_not_send_again() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(14);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    assert_eq!(
        machine.take_over_expired_lease(transaction, "worker-b", START + 11),
        Err(DispatchError::InvalidTransition)
    );
    machine.recover_expired_lease(transaction, START + 11)?;
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::BoundObjectCreateUnknown
    );
    let recovery = machine.take_over_expired_lease(transaction, "worker-b", START + 11)?;
    machine.begin_bound_object_reconciliation(transaction, &recovery, START + 11)?;
    machine.resolve_bound_object(
        transaction,
        &recovery,
        START + 11,
        BoundObjectObservation::Matching(prepared_execution("reconciled-uid")),
    )?;
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialPrepared
    );
    Ok(())
}

#[test]
fn authority_change_prevents_credential_issuance() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(15);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.activate_authority(authority(2))?;
    assert_eq!(
        machine.begin_credential_issue(transaction, &claim, START + 3),
        Err(DispatchError::AuthorityChanged)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ReleaseCancelled
    );
    machine.finalize_confirmed_non_issuance(
        transaction,
        &non_issuance_evidence(transaction, Some("uid")),
        START + 4,
    )?;
    assert!(!machine.resource_is_reserved(&physical()));
    Ok(())
}

#[test]
fn token_response_after_deadline_enters_invalidation() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(16);
    machine.record_consumption(
        transaction,
        owner("tenant-a"),
        physical(),
        authority(1),
        consumption_binding(transaction),
        START,
        START + 5,
    )?;
    let claim = machine.prepare_dispatch(transaction, "worker-a", START + 1)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.begin_credential_issue(transaction, &claim, START + 3)?;
    assert_eq!(
        machine.record_credential_ready(
            transaction,
            &claim,
            START + 5,
            &credential_claims("uid", [2; 32], START + 3, START + 40),
        ),
        Err(DispatchError::DeadlineExpired)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialInvalidating
    );
    assert!(machine.resource_is_reserved(&physical()));
    Ok(())
}

#[test]
fn zero_operation_commitment_is_rejected_at_consumption() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let mut invalid = consumption_binding(Uuid::from_u128(19));
    invalid.effect.operation_hash = [0; 32];
    assert_eq!(
        machine.record_consumption(
            Uuid::from_u128(19),
            owner("tenant-a"),
            physical(),
            authority(1),
            invalid,
            START,
            START + 50,
        ),
        Err(DispatchError::InvalidCommitment)
    );
    Ok(())
}

#[test]
fn consumed_authorization_or_receipt_cannot_replay_under_a_new_transaction()
-> Result<(), DispatchError> {
    let mut machine = machine()?;
    let first = Uuid::from_u128(26);
    let second = Uuid::from_u128(27);
    let consumed = consumption_binding(first);
    machine.record_consumption(
        first,
        owner("tenant-a"),
        physical(),
        authority(1),
        consumed,
        START,
        START + 50,
    )?;
    assert_eq!(
        machine.record_consumption(
            second,
            owner("tenant-a"),
            physical(),
            authority(1),
            consumed,
            START,
            START + 50,
        ),
        Err(DispatchError::ConsumptionReplay)
    );
    Ok(())
}

#[test]
fn same_authorization_hash_cannot_replay_with_new_authorization_id_and_receipt()
-> Result<(), DispatchError> {
    let mut machine = machine()?;
    let first = Uuid::from_u128(35);
    let second = Uuid::from_u128(36);
    let first_consumption = consumption_binding(first);
    let mut second_consumption = consumption_binding(second);
    second_consumption.authorization_hash = first_consumption.authorization_hash;

    assert_ne!(
        first_consumption.authorization_id,
        second_consumption.authorization_id
    );
    assert_ne!(
        first_consumption.receipt_commitment,
        second_consumption.receipt_commitment
    );
    machine.record_consumption(
        first,
        owner("tenant-a"),
        physical(),
        authority(1),
        first_consumption,
        START,
        START + 50,
    )?;
    assert_eq!(
        machine.record_consumption(
            second,
            owner("tenant-a"),
            physical(),
            authority(1),
            second_consumption,
            START,
            START + 50,
        ),
        Err(DispatchError::ConsumptionReplay)
    );
    Ok(())
}

#[test]
fn authority_change_before_create_prevents_external_create() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(20);
    let claim = prepared(&mut machine, transaction)?;
    machine.activate_authority(authority(2))?;
    assert_eq!(
        machine.begin_bound_object_create(transaction, &claim, START + 2),
        Err(DispatchError::AuthorityChanged)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ReleaseCancelled
    );
    Ok(())
}

#[test]
fn credential_subject_swap_enters_invalidation() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(21);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.begin_credential_issue(transaction, &claim, START + 3)?;
    let mut claims = credential_claims("uid", [7; 32], START + 3, START + 40);
    claims.subject = "system:serviceaccount:payments:attacker".to_owned();
    assert_eq!(
        machine.record_credential_ready(transaction, &claim, START + 4, &claims),
        Err(DispatchError::InvalidCredential)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialInvalidating
    );
    Ok(())
}

#[test]
fn token_predating_issue_window_enters_invalidation() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(37);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.begin_credential_issue(transaction, &claim, START + 3)?;

    let earliest_valid_not_before = START + 3 - bounds().clock_uncertainty_s;
    let stale_claims = credential_claims("uid", [8; 32], earliest_valid_not_before - 1, START + 40);
    assert_eq!(
        machine.record_credential_ready(transaction, &claim, START + 4, &stale_claims),
        Err(DispatchError::InvalidCredential)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialInvalidating
    );
    Ok(())
}

#[test]
fn operation_or_wire_swap_cannot_cross_effect_release() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(22);
    let claim = credential_ready(&mut machine, transaction)?;
    let mut swapped = effect_binding();
    swapped.final_wire_commitment = [0x99; 32];
    assert_eq!(
        machine.release_effect(transaction, &claim, &swapped, START + 5),
        Err(DispatchError::InvalidCommitment)
    );
    assert_eq!(machine.phase(transaction)?, LifecyclePhase::CredentialReady);
    machine.release_effect(transaction, &claim, &effect_binding(), START + 5)?;
    Ok(())
}

#[test]
fn provider_success_must_name_the_released_effect() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(23);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.release_effect(transaction, &claim, &effect_binding(), START + 5)?;
    machine.begin_provider_attempt(transaction, &claim, &effect_binding(), START + 6)?;
    let mut evidence = exact_effect_evidence(transaction, START + 7);
    evidence.binding.operation_hash = [0x99; 32];
    assert_eq!(
        machine.record_provider_outcome(
            transaction,
            &claim,
            START + 7,
            ProviderOutcome::Success {
                evidence: Box::new(evidence),
            },
        ),
        Err(DispatchError::InvalidCommitment)
    );
    assert_eq!(machine.phase(transaction)?, LifecyclePhase::Executing);
    Ok(())
}

#[test]
fn dispatch_claim_cannot_be_retargeted_to_another_transaction_or_receipt()
-> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(24);
    let mut claim = prepared(&mut machine, transaction)?;
    let original = claim.clone();
    claim.transaction_id = Uuid::from_u128(25);
    assert_eq!(
        machine.begin_bound_object_create(transaction, &claim, START + 2),
        Err(DispatchError::StaleLease)
    );
    claim = original;
    claim.consumption.receipt_commitment = [0x99; 32];
    assert_eq!(
        machine.begin_bound_object_create(transaction, &claim, START + 2),
        Err(DispatchError::StaleLease)
    );
    Ok(())
}

#[test]
fn rejected_future_time_for_unknown_transaction_cannot_poison_clock() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(28);
    record_consumed(&mut machine, transaction, START)?;

    assert_eq!(
        machine.begin_effect_reconciliation(Uuid::from_u128(0xdead), i64::MAX),
        Err(DispatchError::UnknownTransaction)
    );

    let claim = machine.prepare_dispatch(transaction, "worker-a", START + 1)?;
    assert_eq!(claim.transaction_id, transaction);
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::BoundObjectCreatePending
    );
    Ok(())
}

#[test]
fn error_that_cancels_release_commits_its_observation_time() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(33);
    let claim = credential_ready(&mut machine, transaction)?;
    machine.activate_authority(authority(2))?;

    assert_eq!(
        machine.release_effect(transaction, &claim, &effect_binding(), START + 7),
        Err(DispatchError::AuthorityChanged)
    );
    assert_eq!(
        machine.recover_expired_lease(transaction, START + 6),
        Err(DispatchError::InvalidTime)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::ReleaseCancelled
    );
    Ok(())
}

#[test]
fn observed_command_cannot_replace_preconsumption_commitment() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(29);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    let mut substituted = prepared_execution("uid");
    substituted.execution_command_commitment = [0x99; 32];

    assert_eq!(
        machine.resolve_bound_object(
            transaction,
            &claim,
            START + 2,
            BoundObjectObservation::Matching(substituted),
        ),
        Err(DispatchError::InvalidCommitment)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::BoundObjectCreateInFlight
    );

    let mut substituted_wire = prepared_execution("uid");
    substituted_wire.final_wire_commitment = [0x98; 32];
    assert_eq!(
        machine.resolve_bound_object(
            transaction,
            &claim,
            START + 2,
            BoundObjectObservation::Matching(substituted_wire),
        ),
        Err(DispatchError::InvalidCommitment)
    );
    Ok(())
}

#[test]
fn nonissuance_evidence_for_another_route_cannot_release_reservation() -> Result<(), DispatchError>
{
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(30);
    let claim = prepared(&mut machine, transaction)?;
    machine.begin_bound_object_create(transaction, &claim, START + 2)?;
    machine.resolve_bound_object(
        transaction,
        &claim,
        START + 2,
        BoundObjectObservation::Matching(prepared_execution("uid")),
    )?;
    machine.activate_authority(authority(2))?;
    assert_eq!(
        machine.begin_credential_issue(transaction, &claim, START + 3),
        Err(DispatchError::AuthorityChanged)
    );

    let mut misrouted = non_issuance_evidence(transaction, Some("uid"));
    misrouted.transaction_id = Uuid::from_u128(31);
    assert_eq!(
        machine.finalize_confirmed_non_issuance(transaction, &misrouted, START + 4),
        Err(DispatchError::InvalidEvidence)
    );
    assert!(machine.resource_is_reserved(&physical()));

    machine.finalize_confirmed_non_issuance(
        transaction,
        &non_issuance_evidence(transaction, Some("uid")),
        START + 4,
    )?;
    assert!(!machine.resource_is_reserved(&physical()));
    Ok(())
}

#[test]
fn invalidation_evidence_for_another_token_cannot_retire_credential() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(32);
    let _claim = credential_ready(&mut machine, transaction)?;
    machine.recover_expired_lease(transaction, START + 11)?;

    let mut misrouted = invalidation_evidence(transaction, "server-uid", Some([9; 32]));
    misrouted.token_digest = Some([0x99; 32]);
    assert_eq!(
        machine.confirm_credential_invalidation(transaction, &misrouted, START + 12),
        Err(DispatchError::InvalidEvidence)
    );
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialInvalidating
    );

    machine.confirm_credential_invalidation(
        transaction,
        &invalidation_evidence(transaction, "server-uid", Some([9; 32])),
        START + 12,
    )?;
    assert_eq!(
        machine.phase(transaction)?,
        LifecyclePhase::CredentialQuarantined
    );
    Ok(())
}

#[test]
fn provider_success_requires_fresh_bound_observation_and_retains_its_commitment()
-> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(40);
    let claim = executing(&mut machine, transaction)?;
    let evidence = exact_effect_evidence(transaction, START + 7);
    let expected_commitment = evidence.commitment();

    machine.record_provider_outcome(
        transaction,
        &claim,
        START + 7,
        ProviderOutcome::Success {
            evidence: Box::new(evidence),
        },
    )?;

    assert_eq!(machine.phase(transaction)?, LifecyclePhase::Executed);
    let snapshot = machine.effect_evidence_snapshot(transaction)?;
    assert_eq!(snapshot.transaction_id, transaction);
    assert_eq!(snapshot.physical, physical());
    assert_eq!(snapshot.phase, LifecyclePhase::Executed);
    assert_eq!(snapshot.evidence_commitment, Some(expected_commitment));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn provider_success_rejects_empty_misrouted_or_unbound_evidence() -> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(41);
    let claim = executing(&mut machine, transaction)?;
    let valid = exact_effect_evidence(transaction, START + 7);

    let mut wrong_transaction = valid.clone();
    wrong_transaction.transaction_id = Uuid::from_u128(42);
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        wrong_transaction,
        DispatchError::InvalidEvidence,
    )?;

    let mut wrong_resource = valid.clone();
    wrong_resource.physical.namespace = "other".to_owned();
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        wrong_resource,
        DispatchError::InvalidEvidence,
    )?;

    let mut wrong_uid = valid.clone();
    wrong_uid.observed_resource_uid = "other-uid".to_owned();
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        wrong_uid,
        DispatchError::InvalidEvidence,
    )?;

    let mut wrong_command = valid.clone();
    wrong_command.binding.execution_command_commitment = [0x91; 32];
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        wrong_command,
        DispatchError::InvalidCommitment,
    )?;

    let mut wrong_wire = valid.clone();
    wrong_wire.binding.final_wire_commitment = [0x92; 32];
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        wrong_wire,
        DispatchError::InvalidCommitment,
    )?;

    let mut wrong_token = valid.clone();
    wrong_token.binding.token_digest = [0x93; 32];
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        wrong_token,
        DispatchError::InvalidCommitment,
    )?;

    let mut empty_response = valid.clone();
    empty_response.response_commitment = [0; 32];
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        empty_response,
        DispatchError::InvalidEvidence,
    )?;

    let mut empty_post_state = valid.clone();
    empty_post_state.post_state_commitment = [0; 32];
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        empty_post_state,
        DispatchError::InvalidEvidence,
    )?;

    let mut noncanonical_observer = valid.clone();
    noncanonical_observer.observer.identity = "SPIFFE://AUDIT.EXAMPLE/Observer".to_owned();
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        noncanonical_observer,
        DispatchError::InvalidEvidence,
    )?;

    let mut unauthenticated_observer = valid.clone();
    unauthenticated_observer.observer.authentication_commitment = [0; 32];
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        unauthenticated_observer,
        DispatchError::InvalidEvidence,
    )?;

    let mut empty_resource_version = valid.clone();
    empty_resource_version.observed_resource_version.clear();
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        empty_resource_version,
        DispatchError::InvalidEvidence,
    )?;

    let mut stale_observation = valid.clone();
    stale_observation.observed_at = START + 6;
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        stale_observation,
        DispatchError::InvalidEvidence,
    )?;

    let mut future_observation = valid.clone();
    future_observation.observed_at = START + 8;
    assert_provider_evidence_rejected(
        &mut machine,
        transaction,
        &claim,
        future_observation,
        DispatchError::InvalidEvidence,
    )?;

    machine.record_provider_outcome(
        transaction,
        &claim,
        START + 7,
        ProviderOutcome::Success {
            evidence: Box::new(valid),
        },
    )?;
    assert_eq!(machine.phase(transaction)?, LifecyclePhase::Executed);
    Ok(())
}

#[test]
fn reconciliation_requires_an_observation_newer_than_reconciliation_start()
-> Result<(), DispatchError> {
    let mut machine = machine()?;
    let transaction = Uuid::from_u128(43);
    let claim = executing(&mut machine, transaction)?;
    machine.record_provider_outcome(transaction, &claim, START + 7, ProviderOutcome::Unknown)?;
    machine.begin_effect_reconciliation(transaction, START + 8)?;

    assert_eq!(
        machine.resolve_effect_reconciliation(
            transaction,
            ReconciliationOutcome::ExactEffect {
                evidence: Box::new(exact_effect_evidence(transaction, START + 8)),
            },
            START + 9,
        ),
        Err(DispatchError::InvalidEvidence)
    );
    assert_eq!(machine.phase(transaction)?, LifecyclePhase::Reconciling);
    assert_eq!(
        machine
            .effect_evidence_snapshot(transaction)?
            .evidence_commitment,
        None
    );

    let evidence = exact_effect_evidence(transaction, START + 9);
    let commitment = evidence.commitment();
    machine.resolve_effect_reconciliation(
        transaction,
        ReconciliationOutcome::ExactEffect {
            evidence: Box::new(evidence),
        },
        START + 9,
    )?;
    assert_eq!(machine.phase(transaction)?, LifecyclePhase::Executed);
    assert_eq!(
        machine
            .effect_evidence_snapshot(transaction)?
            .evidence_commitment,
        Some(commitment)
    );
    Ok(())
}
