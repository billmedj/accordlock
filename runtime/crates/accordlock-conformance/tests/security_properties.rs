use accordlock_kernel::{
    ExplicitAuthorizationVerificationContext, verify_authorization_in_explicit_context,
    verify_authorization_signature,
};
use accordlock_protocol::{
    AgentProposal, AttesterScope, AuthorityDomainState, AuthorityVector,
    CONSUMPTION_RECEIPT_DOMAIN, CanonicalEncode, DeploymentTemplate, Digest32,
    DispatchDeadlinePolicy, EVALUATION_DOMAIN, EVIDENCE_ASSERTION_SCHEMA_VERSION,
    EXECUTION_AUTHORIZATION_DOMAIN, EvidenceAssertion, EvidenceKind, EvidencePayload,
    ExecutionAuthorization, REPLAY_RESULT_DOMAIN, SignedAuthorization, SigningIdentity,
    authorization_signer_root, canonical_hash, sign_cose, verify_cose,
};
use uuid::Uuid;

fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn domain(seed: u8, epoch: u64) -> AuthorityDomainState {
    AuthorityDomainState {
        root: Digest32::from_bytes([seed; 32]),
        epoch,
        activation_id: uuid(u128::from(seed) + 100),
    }
}

fn authority() -> AuthorityVector {
    AuthorityVector {
        policy: domain(1, 1),
        registry: domain(2, 2),
        revocation: domain(3, 3),
        connector: domain(4, 4),
        resource: domain(5, 5),
        signer: domain(6, 6),
        mediation: domain(7, 7),
        grant_registry: domain(8, 8),
        office_act_registry: domain(9, 9),
        principal_registry: domain(10, 10),
        workload_build_allowlist: domain(11, 11),
        kernel_configuration: domain(12, 12),
    }
}

fn template() -> DeploymentTemplate {
    DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: "prod".to_owned(),
        audience: "https://kubernetes.default.svc".to_owned(),
        repository: "acme/payments".to_owned(),
        commit_sha: "1111111111111111111111111111111111111111".to_owned(),
        image_repository: "111122223333.dkr.ecr.us-east-1.amazonaws.com/acme/payments".to_owned(),
        image_digest: Digest32::from_bytes([0xaa; 32]),
        cluster_identity: "eks:us-east-1:111122223333:cluster/prod-1".to_owned(),
        namespace: "payments-prod".to_owned(),
        deployment: "payments".to_owned(),
        deployment_uid: "11111111-2222-4333-8444-555555555555".to_owned(),
        container: "app".to_owned(),
        container_index: 0,
        prior_image_digest: Digest32::from_bytes([0; 32]),
        resource_version: "1001".to_owned(),
        prior_projection_hash: Digest32::from_bytes([0x44; 32]),
        prior_transaction_annotation: Some("unset".to_owned()),
        prior_authorization_annotation: Some("unset".to_owned()),
        prior_operation_hash_annotation: Some("unset".to_owned()),
    }
}

fn authorization() -> ExecutionAuthorization {
    ExecutionAuthorization {
        schema_version: accordlock_protocol::EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id: uuid(1),
        evaluation_nonce: uuid(2),
        request_id: uuid(3),
        tenant: "acme".to_owned(),
        holder: "spiffe://acme.example/agent/release-bot".to_owned(),
        audience: "https://kubernetes.default.svc".to_owned(),
        issued_at: 1_786_752_000,
        not_before: 1_786_752_000,
        consume_before: 1_786_752_120,
        dispatch_deadline_policy: DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 30,
            profile_hard_cap: 1_786_752_120,
            immutable_dependency_expiries: vec![1_786_752_110],
        },
        grant_id: uuid(4),
        template: template(),
        template_hash: Digest32::from_bytes([0x31; 32]),
        evidence_root: Digest32::from_bytes([0x32; 32]),
        principals: vec![
            "principal:builder".to_owned(),
            "principal:reviewer".to_owned(),
        ],
        policy_root: Digest32::from_bytes([0x33; 32]),
        authority: authority(),
    }
}

fn signed_authorization(
    value: ExecutionAuthorization,
    signer: &SigningIdentity,
) -> Result<SignedAuthorization, Box<dyn std::error::Error>> {
    let cose_sign1 = sign_cose(
        &value.canonical_bytes()?,
        EXECUTION_AUTHORIZATION_DOMAIN,
        signer,
    )?;
    Ok(SignedAuthorization {
        authorization: value,
        cose_sign1,
    })
}

fn contextual_authorization(
    signer: &SigningIdentity,
) -> Result<ExecutionAuthorization, Box<dyn std::error::Error>> {
    let mut value = authorization();
    value.template.prior_image_digest = Digest32::from_bytes([0x30; 32]);
    value.template_hash = canonical_hash(&value.template)?;
    value.authority.policy.root = value.policy_root;
    value.authority.signer.root =
        authorization_signer_root(signer.key_id(), signer.public_key_bytes())?;
    Ok(value)
}

#[test]
fn contextual_profile_rejects_resigned_template_schema_domain_and_interval_mismatches()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = SigningIdentity::from_seed("strict-authorization-key", [0x49; 32]);
    let value = contextual_authorization(&signer)?;
    let active_authority = value.authority.clone();
    let context = ExplicitAuthorizationVerificationContext::new(
        value.issued_at + 1,
        &value.audience,
        &active_authority,
    )?;
    let original = signed_authorization(value.clone(), &signer)?;
    verify_authorization_in_explicit_context(&original, &signer.verifier(), &context)?;

    let mut wrong_hash = value.clone();
    wrong_hash.template_hash = Digest32::from_bytes([0x91; 32]);
    assert!(
        verify_authorization_in_explicit_context(
            &signed_authorization(wrong_hash, &signer)?,
            &signer.verifier(),
            &context,
        )
        .is_err()
    );

    let mut wrong_schema = value.clone();
    wrong_schema.schema_version -= 1;
    assert!(
        verify_authorization_in_explicit_context(
            &signed_authorization(wrong_schema, &signer)?,
            &signer.verifier(),
            &context,
        )
        .is_err()
    );

    let wrong_domain = SignedAuthorization {
        cose_sign1: sign_cose(
            &value.canonical_bytes()?,
            "accordlock:v1:execution-authorization",
            &signer,
        )?,
        authorization: value.clone(),
    };
    assert!(
        verify_authorization_in_explicit_context(&wrong_domain, &signer.verifier(), &context)
            .is_err()
    );

    let mut invalid_interval = value.clone();
    invalid_interval.not_before = invalid_interval.issued_at - 1;
    assert!(
        verify_authorization_in_explicit_context(
            &signed_authorization(invalid_interval, &signer)?,
            &signer.verifier(),
            &context,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn legacy_v1_execution_authorization_domain_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let signer = SigningIdentity::from_seed("authorization-key", [0x50; 32]);
    let value = authorization();
    let legacy = SignedAuthorization {
        cose_sign1: sign_cose(
            &value.canonical_bytes()?,
            "accordlock:v1:execution-authorization",
            &signer,
        )?,
        authorization: value,
    };
    assert!(verify_authorization_signature(&legacy, &signer.verifier()).is_err());
    Ok(())
}

#[test]
fn noncanonical_or_oversized_dependency_expiries_are_rejected() {
    let mut duplicate = authorization();
    duplicate
        .dispatch_deadline_policy
        .immutable_dependency_expiries = vec![10, 10];
    assert!(duplicate.canonical_bytes().is_err());

    let mut oversized = authorization();
    oversized
        .dispatch_deadline_policy
        .immutable_dependency_expiries = (0_i64..=64).collect();
    assert!(oversized.canonical_bytes().is_err());
}

fn mutate_string(value: &mut String) {
    value.push_str("#mutated");
}

#[test]
#[allow(clippy::too_many_lines)] // The explicit mutation inventory is easier to audit in one test.
fn all_bound_authorization_fields_detect_membership_or_value_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = SigningIdentity::from_seed("authorization-key", [0x51; 32]);
    let original = signed_authorization(authorization(), &signer)?;
    verify_authorization_signature(&original, &signer.verifier())?;

    let mut cases: Vec<(&str, ExecutionAuthorization)> = Vec::new();
    macro_rules! mutation {
        ($name:literal, $body:expr) => {{
            let mut value = original.authorization.clone();
            $body(&mut value);
            cases.push(($name, value));
        }};
    }

    mutation!("schema_version", |v: &mut ExecutionAuthorization| v
        .schema_version +=
        1);
    mutation!("authorization_id", |v: &mut ExecutionAuthorization| v
        .authorization_id =
        uuid(101));
    mutation!("evaluation_nonce", |v: &mut ExecutionAuthorization| v
        .evaluation_nonce =
        uuid(102));
    mutation!("request_id", |v: &mut ExecutionAuthorization| v
        .request_id =
        uuid(103));
    mutation!("tenant", |v: &mut ExecutionAuthorization| mutate_string(
        &mut v.tenant
    ));
    mutation!("holder", |v: &mut ExecutionAuthorization| mutate_string(
        &mut v.holder
    ));
    mutation!("audience", |v: &mut ExecutionAuthorization| mutate_string(
        &mut v.audience
    ));
    mutation!("issued_at", |v: &mut ExecutionAuthorization| v.issued_at +=
        1);
    mutation!("not_before", |v: &mut ExecutionAuthorization| v
        .not_before +=
        1);
    mutation!("consume_before", |v: &mut ExecutionAuthorization| v
        .consume_before +=
        1);
    mutation!(
        "dispatch_deadline_policy.max_dispatch_delay_seconds",
        |v: &mut ExecutionAuthorization| v.dispatch_deadline_policy.max_dispatch_delay_seconds += 1
    );
    mutation!(
        "dispatch_deadline_policy.profile_hard_cap",
        |v: &mut ExecutionAuthorization| v.dispatch_deadline_policy.profile_hard_cap += 1
    );
    mutation!(
        "dispatch_deadline_policy.immutable_dependency_expiries",
        |v: &mut ExecutionAuthorization| v
            .dispatch_deadline_policy
            .immutable_dependency_expiries[0] += 1
    );
    mutation!("grant_id", |v: &mut ExecutionAuthorization| v.grant_id =
        uuid(104));
    mutation!("template.operation", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.operation);
    });
    mutation!("template.environment", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.environment);
    });
    mutation!("template.audience", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.audience);
    });
    mutation!("template.repository", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.repository);
    });
    mutation!("template.commit_sha", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.commit_sha);
    });
    mutation!(
        "template.image_repository",
        |v: &mut ExecutionAuthorization| {
            mutate_string(&mut v.template.image_repository);
        }
    );
    mutation!("template.image_digest", |v: &mut ExecutionAuthorization| {
        v.template.image_digest = Digest32::from_bytes([0xab; 32]);
    });
    mutation!(
        "template.cluster_identity",
        |v: &mut ExecutionAuthorization| {
            mutate_string(&mut v.template.cluster_identity);
        }
    );
    mutation!("template.namespace", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.namespace);
    });
    mutation!("template.deployment", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.deployment);
    });
    mutation!(
        "template.deployment_uid",
        |v: &mut ExecutionAuthorization| {
            mutate_string(&mut v.template.deployment_uid);
        }
    );
    mutation!("template.container", |v: &mut ExecutionAuthorization| {
        mutate_string(&mut v.template.container);
    });
    mutation!(
        "template.container_index",
        |v: &mut ExecutionAuthorization| v.template.container_index += 1
    );
    mutation!(
        "template.prior_image_digest",
        |v: &mut ExecutionAuthorization| v.template.prior_image_digest =
            Digest32::from_bytes([1; 32])
    );
    mutation!(
        "template.resource_version",
        |v: &mut ExecutionAuthorization| {
            mutate_string(&mut v.template.resource_version);
        }
    );
    mutation!(
        "template.prior_projection_hash",
        |v: &mut ExecutionAuthorization| v.template.prior_projection_hash =
            Digest32::from_bytes([0x45; 32])
    );
    mutation!(
        "template.prior_transaction_annotation",
        |v: &mut ExecutionAuthorization| v.template.prior_transaction_annotation = None
    );
    mutation!(
        "template.prior_authorization_annotation",
        |v: &mut ExecutionAuthorization| v.template.prior_authorization_annotation = None
    );
    mutation!(
        "template.prior_operation_hash_annotation",
        |v: &mut ExecutionAuthorization| v.template.prior_operation_hash_annotation = None
    );
    mutation!("template_hash", |v: &mut ExecutionAuthorization| v
        .template_hash =
        Digest32::from_bytes([0x41; 32]));
    mutation!("evidence_root", |v: &mut ExecutionAuthorization| v
        .evidence_root =
        Digest32::from_bytes([0x42; 32]));
    mutation!("principals.membership", |v: &mut ExecutionAuthorization| v
        .principals
        .push("principal:attacker".to_owned()));
    mutation!("policy_root", |v: &mut ExecutionAuthorization| v
        .policy_root =
        Digest32::from_bytes([0x43; 32]));

    macro_rules! authority_mutation {
        ($name:literal, $field:ident) => {
            mutation!($name, |v: &mut ExecutionAuthorization| v
                .authority
                .$field
                .epoch += 1);
        };
    }
    authority_mutation!("authority.policy", policy);
    authority_mutation!("authority.registry", registry);
    authority_mutation!("authority.revocation", revocation);
    authority_mutation!("authority.connector", connector);
    authority_mutation!("authority.resource", resource);
    authority_mutation!("authority.signer", signer);
    authority_mutation!("authority.mediation", mediation);
    authority_mutation!("authority.grant_registry", grant_registry);
    authority_mutation!("authority.office_act_registry", office_act_registry);
    authority_mutation!("authority.principal_registry", principal_registry);
    authority_mutation!(
        "authority.workload_build_allowlist",
        workload_build_allowlist
    );
    authority_mutation!("authority.kernel_configuration", kernel_configuration);

    assert_eq!(cases.len(), 49, "the explicit binding inventory changed");
    for (name, mutated_authorization) in cases {
        let mutated_wrapper = SignedAuthorization {
            authorization: mutated_authorization,
            cose_sign1: original.cose_sign1.clone(),
        };
        assert!(
            verify_authorization_signature(&mutated_wrapper, &signer.verifier()).is_err(),
            "mutating {name} preserved authorization verification"
        );
    }
    Ok(())
}

#[test]
fn authorization_wrapper_rejects_noncanonical_principal_order_and_duplicates()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = SigningIdentity::from_seed("authorization-key", [0x52; 32]);
    let original = signed_authorization(authorization(), &signer)?;

    let mut reordered = original.clone();
    reordered.authorization.principals.swap(0, 1);
    assert!(verify_authorization_signature(&reordered, &signer.verifier()).is_err());

    let mut duplicated = original;
    duplicated
        .authorization
        .principals
        .push("principal:reviewer".to_owned());
    assert!(verify_authorization_signature(&duplicated, &signer.verifier()).is_err());
    Ok(())
}

#[test]
fn cryptographic_domains_are_pairwise_separated() -> Result<(), Box<dyn std::error::Error>> {
    let signer = SigningIdentity::from_seed("multi-route-test-key", [0x61; 32]);
    let domains = [
        EXECUTION_AUTHORIZATION_DOMAIN,
        EVALUATION_DOMAIN,
        CONSUMPTION_RECEIPT_DOMAIN,
        REPLAY_RESULT_DOMAIN,
        EvidenceKind::Review.domain(),
        EvidenceKind::Build.domain(),
        EvidenceKind::Artifact.domain(),
        EvidenceKind::Target.domain(),
    ];
    for signing_domain in domains {
        let encoded = sign_cose(b"same-payload", signing_domain, &signer)?;
        for verifying_domain in domains {
            let result = verify_cose(&encoded, verifying_domain, &signer.verifier());
            assert_eq!(
                result.is_ok(),
                signing_domain == verifying_domain,
                "domain separation mismatch: signed={signing_domain}, verified={verifying_domain}"
            );
        }
    }
    Ok(())
}

#[test]
fn legacy_v1_evidence_domains_do_not_verify_as_current_v2() -> Result<(), Box<dyn std::error::Error>>
{
    let signer = SigningIdentity::from_seed("legacy-evidence-domain-test", [0x62; 32]);
    let routes = [
        ("accordlock:v1:evidence:review", EvidenceKind::Review),
        ("accordlock:v1:evidence:build", EvidenceKind::Build),
        ("accordlock:v1:evidence:artifact", EvidenceKind::Artifact),
        ("accordlock:v1:evidence:target", EvidenceKind::Target),
    ];
    for (legacy_domain, current_kind) in routes {
        let encoded = sign_cose(b"legacy-v1-payload", legacy_domain, &signer)?;
        assert!(verify_cose(&encoded, current_kind.domain(), &signer.verifier()).is_err());
    }
    Ok(())
}

#[test]
fn legacy_v1_assertion_without_signed_request_id_is_not_current_wire()
-> Result<(), Box<dyn std::error::Error>> {
    let assertion = EvidenceAssertion {
        schema_version: EVIDENCE_ASSERTION_SCHEMA_VERSION,
        request_id: uuid(0x6201),
        evidence_id: uuid(0x6202),
        issuer: "review.example".to_owned(),
        key_id: "review-key-v2".to_owned(),
        source_uri: "https://review.example/records/6202".to_owned(),
        observed_at: 100,
        valid_until: 200,
        authority: authority(),
        payload: EvidencePayload::Review {
            repository: "acme/payments".to_owned(),
            commit_sha: "1".repeat(40),
            approved: true,
            review_state_id: "review-state-6202".to_owned(),
        },
    };
    let mut legacy = serde_json::to_value(assertion)?;
    let object = legacy
        .as_object_mut()
        .ok_or("assertion did not serialize as an object")?;
    object.insert("schema_version".to_owned(), serde_json::json!(1));
    object.remove("request_id");

    assert!(serde_json::from_value::<EvidenceAssertion>(legacy).is_err());
    Ok(())
}

#[test]
fn public_proposal_and_authorization_json_reject_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = AgentProposal {
        schema_version: 1,
        request_id: uuid(20),
        tenant: "acme".to_owned(),
        actor: "spiffe://acme.example/agent/release-bot".to_owned(),
        template: template(),
    };
    let mut proposal_json = serde_json::to_value(proposal)?;
    let proposal_object = proposal_json
        .as_object_mut()
        .ok_or("proposal was not an object")?;
    proposal_object.insert("grade".to_owned(), serde_json::json!(4));
    assert!(serde_json::from_value::<AgentProposal>(proposal_json).is_err());

    let mut nested_json = serde_json::to_value(AgentProposal {
        schema_version: 1,
        request_id: uuid(21),
        tenant: "acme".to_owned(),
        actor: "spiffe://acme.example/agent/release-bot".to_owned(),
        template: template(),
    })?;
    let template_object = nested_json
        .get_mut("template")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("template was not an object")?;
    template_object.insert("approved".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<AgentProposal>(nested_json).is_err());

    let mut authorization_json = serde_json::to_value(authorization())?;
    let authorization_object = authorization_json
        .as_object_mut()
        .ok_or("authorization was not an object")?;
    authorization_object.insert("policy_override".to_owned(), serde_json::json!("allow"));
    assert!(serde_json::from_value::<ExecutionAuthorization>(authorization_json).is_err());
    Ok(())
}

#[test]
fn evidence_payload_unknown_field_must_fail_closed() {
    let payload = serde_json::json!({
        "kind": "REVIEW",
        "repository": "acme/payments",
        "commit_sha": "1111111111111111111111111111111111111111",
        "approved": true,
        "review_state_id": "github-pr-42-v17",
        "caller_grade": 4
    });
    assert!(serde_json::from_value::<EvidencePayload>(payload).is_err());
}

#[test]
fn attester_scope_unknown_field_must_fail_closed() {
    let scope = serde_json::json!({
        "kind": "REVIEW",
        "repository": "acme/payments",
        "caller_grade": 4
    });
    assert!(serde_json::from_value::<AttesterScope>(scope).is_err());
}
