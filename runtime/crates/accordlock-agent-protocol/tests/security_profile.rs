use accordlock_agent_protocol::{
    AUTHORIZATION_DECISION_SCHEMA_VERSION, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationStoreError, BindingError, EXECUTION_PROTOCOL_SCHEMA_VERSION,
    EXECUTION_RECORD_SCHEMA_VERSION, EXECUTION_REQUEST_SCHEMA_VERSION, ExecutionAuthorization,
    ExecutionOutcome, ExecutionRecord, ExecutionRequest, MemoryAuthorizationStore,
    canonical_args_hash,
};
use accordlock_protocol::Digest32;
use serde_json::{Value, json};
use uuid::Uuid;

fn request() -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
    Ok(ExecutionRequest {
        schema_version: EXECUTION_REQUEST_SCHEMA_VERSION,
        request_id: Uuid::from_u128(0x11),
        session_id: "session-a".to_owned(),
        run_id: "run-a".to_owned(),
        tool_call_id: "call-a".to_owned(),
        workspace: "C:\\work\\payments".to_owned(),
        extension: "developer".to_owned(),
        tool: "shell".to_owned(),
        canonical_args_hash: canonical_args_hash(&json!({
            "command": "cargo test",
            "timeout": 60
        }))?,
        policy_epoch: 7,
        task_policy_hash: Digest32::from_bytes([0x22; 32]),
        created_at: 1_000,
        expires_at: 1_600,
    })
}

fn decision(
    request: &ExecutionRequest,
) -> Result<AuthorizationDecision, Box<dyn std::error::Error>> {
    Ok(AuthorizationDecision {
        schema_version: AUTHORIZATION_DECISION_SCHEMA_VERSION,
        request_hash: request.digest()?,
        session_id: request.session_id.clone(),
        run_id: request.run_id.clone(),
        tool_call_id: request.tool_call_id.clone(),
        workspace: request.workspace.clone(),
        extension: request.extension.clone(),
        tool: request.tool.clone(),
        canonical_args_hash: request.canonical_args_hash,
        policy_epoch: request.policy_epoch,
        task_policy_hash: request.task_policy_hash,
        policy_decision_hash: Digest32::sha256(b"policy-decision"),
        conformance_evaluation_hashes: vec![Digest32::sha256(b"conformance-evaluation")],
        intent_evaluation_hash: Digest32::sha256(b"pre-execution-intent-evaluation"),
        outcome: AuthorizationOutcome::Allow,
        reason_code: "policy.allow".to_owned(),
        approval_evidence_hash: None,
        decided_at: 1_010,
        expires_at: 1_310,
    })
}

fn authorization(
    request: &ExecutionRequest,
    decision: &AuthorizationDecision,
) -> Result<ExecutionAuthorization, Box<dyn std::error::Error>> {
    Ok(ExecutionAuthorization {
        schema_version: EXECUTION_PROTOCOL_SCHEMA_VERSION,
        authorization_id: Uuid::from_u128(0x33),
        request_hash: request.digest()?,
        authorization_decision_hash: decision.digest()?,
        session_id: request.session_id.clone(),
        run_id: request.run_id.clone(),
        tool_call_id: request.tool_call_id.clone(),
        workspace: request.workspace.clone(),
        extension: request.extension.clone(),
        tool: request.tool.clone(),
        canonical_args_hash: request.canonical_args_hash,
        policy_epoch: request.policy_epoch,
        task_policy_hash: request.task_policy_hash,
        issued_at: 1_020,
        not_before: 1_020,
        expires_at: 1_300,
    })
}

#[test]
fn canonical_arguments_ignore_object_insertion_order_and_bind_values()
-> Result<(), Box<dyn std::error::Error>> {
    let first: Value = serde_json::from_str(r#"{"b":[true,2],"a":{"z":"x","y":null}}"#)?;
    let second: Value = serde_json::from_str(r#"{"a":{"y":null,"z":"x"},"b":[true,2]}"#)?;
    let changed: Value = serde_json::from_str(r#"{"a":{"y":null,"z":"x"},"b":[true,3]}"#)?;

    assert_eq!(canonical_args_hash(&first)?, canonical_args_hash(&second)?);
    assert_ne!(canonical_args_hash(&first)?, canonical_args_hash(&changed)?);
    Ok(())
}

#[test]
fn canonical_chain_has_a_stable_golden_commitment() -> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let decision = decision(&request)?;
    let authorization = authorization(&request, &decision)?;
    let record = record(&request, &authorization)?;
    let actual = [
        request.canonical_args_hash.to_string(),
        request.digest()?.to_string(),
        decision.digest()?.to_string(),
        authorization.digest()?.to_string(),
        record.digest()?.to_string(),
    ];
    assert_eq!(
        actual,
        [
            "sha256:e011142abf39d87342cfe3e4046c3d71910ca70947818bf347f200a062a44c97",
            "sha256:967405ae9367c2976bf1709ba9ae8e056f278f73dcf88d835fdb01a83233973d",
            "sha256:13a9c3b736e01ece2e613c720c882242e84ebb677949680895578209c8334ea4",
            "sha256:c422e0080be73c17003bccb41a09614389d2e78b72e40724aafd8b8ca2db2f3a",
            "sha256:526cd5d363bb13610f478e7f4a6be3806447bcf80417dfd116b31b4abc072834",
        ]
    );
    Ok(())
}

#[test]
fn strict_json_records_reject_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let decision = decision(&request)?;
    let authorization = authorization(&request, &decision)?;
    let record = record(&request, &authorization)?;

    for serialized in [
        serde_json::to_value(request)?,
        serde_json::to_value(decision)?,
        serde_json::to_value(authorization)?,
        serde_json::to_value(record)?,
    ] {
        let mut object = serialized
            .as_object()
            .cloned()
            .ok_or("record did not serialize as an object")?;
        object.insert("unexpected".to_owned(), json!(true));
        let encoded = serde_json::to_string(&object)?;
        let rejected_intent = serde_json::from_str::<ExecutionRequest>(&encoded).is_err();
        let rejected_decision = serde_json::from_str::<AuthorizationDecision>(&encoded).is_err();
        let rejected_authorization =
            serde_json::from_str::<ExecutionAuthorization>(&encoded).is_err();
        let rejected_receipt = serde_json::from_str::<ExecutionRecord>(&encoded).is_err();
        assert!(
            rejected_intent && rejected_decision && rejected_authorization && rejected_receipt,
            "every incompatible target type must reject this unknown-field record"
        );
    }
    Ok(())
}

#[test]
fn authorization_repeats_and_verifies_every_security_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let decision = decision(&request)?;
    let authorization = authorization(&request, &decision)?;
    authorization.verify_for(&request, &decision)?;

    let mutations = [
        ("/session_id", json!("session-b")),
        ("/run_id", json!("run-b")),
        ("/tool_call_id", json!("call-b")),
        ("/workspace", json!("C:\\work\\other")),
        ("/extension", json!("other")),
        ("/tool", json!("write_file")),
        (
            "/canonical_args_hash",
            json!(Digest32::from_bytes([0x44; 32])),
        ),
        ("/policy_epoch", json!(8)),
        ("/task_policy_hash", json!(Digest32::from_bytes([0x55; 32]))),
    ];
    let baseline = serde_json::to_value(&authorization)?;
    for (pointer, replacement) in mutations {
        let mut changed = baseline.clone();
        let field = changed
            .pointer_mut(pointer)
            .ok_or("missing authorization field in mutation test")?;
        *field = replacement;
        let changed: ExecutionAuthorization = serde_json::from_value(changed)?;
        assert!(
            matches!(
                changed.verify_for(&request, &decision),
                Err(BindingError::Mismatch(_))
            ),
            "mutation {pointer} must fail exact verification"
        );
    }
    Ok(())
}

#[test]
fn decision_digest_binds_the_pre_execution_intent_evaluation()
-> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let decision = decision(&request)?;
    let baseline = decision.digest()?;

    let mut substituted = decision.clone();
    substituted.intent_evaluation_hash = Digest32::sha256(b"substituted-intent-evaluation");
    assert_ne!(substituted.digest()?, baseline);

    let authorization = authorization(&request, &decision)?;
    assert!(authorization.verify_for(&request, &substituted).is_err());

    let mut missing = decision;
    missing.intent_evaluation_hash = Digest32::from_bytes([0; 32]);
    assert!(missing.validate().is_err());
    Ok(())
}

#[test]
fn legacy_v3_decision_remains_readable_but_cannot_carry_current_intent_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let current = decision(&request)?;
    let mut encoded = serde_json::to_value(&current)?;
    encoded["schema_version"] = json!(3);
    encoded
        .as_object_mut()
        .ok_or("decision did not serialize as an object")?
        .remove("intent_evaluation_hash");
    let legacy: AuthorizationDecision = serde_json::from_value(encoded)?;
    legacy.validate()?;
    assert_eq!(
        legacy.digest()?.to_string(),
        "sha256:84b11ba0778a75ebbb6f5b38d551e7414eb8be67d9bd3568d6d6533fdb6238ca"
    );
    assert!(
        serde_json::to_value(&legacy)?
            .get("intent_evaluation_hash")
            .is_none()
    );

    let mut invalid = legacy;
    invalid.intent_evaluation_hash = Digest32::sha256(b"not valid in legacy schema");
    assert!(invalid.validate().is_err());
    Ok(())
}

#[test]
fn non_authorizing_decision_cannot_create_a_usable_authorization()
-> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let mut decision = decision(&request)?;
    decision.outcome = AuthorizationOutcome::Deny;
    decision.reason_code = "policy.deny".to_owned();
    decision.conformance_evaluation_hashes.clear();
    let mut authorization = authorization(&request, &decision)?;
    authorization.authorization_decision_hash = decision.digest()?;
    assert_eq!(
        authorization.verify_for(&request, &decision),
        Err(BindingError::DecisionDoesNotAuthorize)
    );
    Ok(())
}

#[test]
fn memory_store_is_atomic_one_shot_and_preserves_replay_tombstone()
-> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let decision = decision(&request)?;
    let authorization = authorization(&request, &decision)?;
    let store = MemoryAuthorizationStore::new();

    store.insert(&request, &decision, authorization.clone(), 1_020)?;
    assert_eq!(store.len()?, 1);
    let consumed = store.consume(&request, authorization.authorization_id, 1_021)?;
    assert_eq!(consumed.authorization, authorization);
    assert_eq!(consumed.consumed_at, 1_021);
    assert_eq!(
        store.consume(&request, authorization.authorization_id, 1_022),
        Err(AuthorizationStoreError::Replay)
    );
    assert_eq!(
        store.consume(&request, authorization.authorization_id, 2_000),
        Err(AuthorizationStoreError::Replay),
        "replay remains explicit even after the validity window"
    );
    Ok(())
}

#[test]
fn memory_store_rejects_expiration_and_clock_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let decision = decision(&request)?;
    let authorization = authorization(&request, &decision)?;
    let store = MemoryAuthorizationStore::new();
    store.insert(&request, &decision, authorization.clone(), 1_020)?;

    assert_eq!(
        store.consume(
            &request,
            authorization.authorization_id,
            authorization.expires_at
        ),
        Err(AuthorizationStoreError::Expired)
    );
    assert_eq!(
        store.consume(&request, authorization.authorization_id, 1_100),
        Err(AuthorizationStoreError::ClockRollback),
        "an expired authorization cannot be resurrected by moving time backwards"
    );
    Ok(())
}

fn record(
    request: &ExecutionRequest,
    authorization: &ExecutionAuthorization,
) -> Result<ExecutionRecord, Box<dyn std::error::Error>> {
    Ok(ExecutionRecord {
        schema_version: EXECUTION_RECORD_SCHEMA_VERSION,
        record_id: Uuid::from_u128(0x66),
        authorization_id: authorization.authorization_id,
        request_hash: request.digest()?,
        authorization_hash: authorization.digest()?,
        session_id: request.session_id.clone(),
        run_id: request.run_id.clone(),
        tool_call_id: request.tool_call_id.clone(),
        workspace: request.workspace.clone(),
        extension: request.extension.clone(),
        tool: request.tool.clone(),
        canonical_args_hash: request.canonical_args_hash,
        policy_epoch: request.policy_epoch,
        task_policy_hash: request.task_policy_hash,
        consumed_at: 1_021,
        completed_at: 1_030,
        outcome: ExecutionOutcome::Succeeded,
        result_hash: Digest32::from_bytes([0x77; 32]),
    })
}

#[test]
fn execution_record_closes_the_exact_chain() -> Result<(), Box<dyn std::error::Error>> {
    let request = request()?;
    let decision = decision(&request)?;
    let authorization = authorization(&request, &decision)?;
    let record = record(&request, &authorization)?;
    record.verify_for(&request, &authorization)?;

    let mut changed = record;
    changed.tool = "other".to_owned();
    assert_eq!(
        changed.verify_for(&request, &authorization),
        Err(BindingError::Mismatch("tool"))
    );
    Ok(())
}

#[test]
fn profile_bounds_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = request()?;
    request.session_id = format!(" {}", request.session_id);
    assert!(request.validate().is_err());

    let mut deep = json!(null);
    for _ in 0..=65 {
        deep = json!([deep]);
    }
    assert!(canonical_args_hash(&deep).is_err());
    Ok(())
}
