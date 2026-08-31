#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use accordlock_dispatch::{
    CredentialProfile, DispatchBounds, LogicalOwner, PhysicalResourceId,
    authority_version_from_vector,
};
use accordlock_eks_profile::{CaTrustCommitment, EksRouteProfileInput, PinnedSocketTarget};
use accordlock_executor::{
    ExecutorConfig, NativeEksResponse, NativeGetRequest, NativePatchRequest,
    NativePreWriteAuthorization, TransportFailure,
};
use accordlock_k8s::prepare_patch;
use accordlock_protocol::{
    AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant, Digest32,
    DispatchDeadlinePolicy, EXECUTION_AUTHORIZATION_DOMAIN, EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
    ExecutionAuthorization, SignedAuthorization, SigningIdentity, authorization_signer_root,
    canonical_hash, sign_cose,
};
use accordlock_state::{
    BrokerIoAuthority, BrokerJournalState, BrokerReconciliationAuthority,
    BrokerReconciliationResult, BrokerSecretObservation, BrokerTokenIssueObservation, ConsumeKey,
    GrantRegistration, InMemoryStore, IssuedAuthorizationRecord, Scope, StateError,
    grant_revocation_root,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::*;

const BEARER: &[u8] = b"opaque-bound-attempt-token";
const SUBSTITUTE_BEARER: &[u8] = b"substituted-bound-attempt-token";

#[derive(Debug)]
struct StateClock(std::sync::atomic::AtomicI64);

impl StateClock {
    fn new(now: i64) -> Self {
        Self(std::sync::atomic::AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, std::sync::atomic::Ordering::SeqCst);
    }
}

impl accordlock_state::TrustedClock for StateClock {
    fn now_unix_seconds(&self) -> Result<i64, StateError> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[derive(Debug)]
struct SequenceClock(Mutex<VecDeque<i64>>);

impl SequenceClock {
    fn new(values: impl IntoIterator<Item = i64>) -> Self {
        Self(Mutex::new(values.into_iter().collect()))
    }
}

impl TrustedClock for SequenceClock {
    fn unix_seconds(&self) -> Result<i64, String> {
        self.0
            .lock()
            .map_err(|_| "test clock poisoned".to_owned())?
            .pop_front()
            .ok_or_else(|| "test clock exhausted".to_owned())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PatchMode {
    Success,
    OutcomeUnknown,
}

#[derive(Debug)]
struct TransportState {
    before: Vec<u8>,
    after: Vec<u8>,
    api_server_identity: String,
    mode: PatchMode,
    get_count: usize,
    patch_count: usize,
    attempt_was_durable_at_patch: bool,
}

#[derive(Clone, Debug)]
struct CheckingTransport {
    route_profile: EksRouteProfile,
    state: Arc<Mutex<TransportState>>,
    store: InMemoryStore,
    key: ConsumeKey,
}

impl CheckingTransport {
    fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (state.get_count, state.patch_count)
    }

    fn durable_at_patch(&self) -> bool {
        self.state.lock().unwrap().attempt_was_durable_at_patch
    }
}

impl NativeEksTransport for CheckingTransport {
    fn route_profile(&self) -> &EksRouteProfile {
        &self.route_profile
    }

    fn operation_timeout_upper_bound(&self) -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    fn get_deployment(
        &self,
        request: NativeGetRequest<'_>,
    ) -> Result<NativeEksResponse, TransportFailure> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.api_server_identity(), state.api_server_identity);
        state.get_count += 1;
        Ok(NativeEksResponse::new(
            200,
            state.api_server_identity.clone(),
            [0x61; 32],
            state.before.clone(),
        ))
    }

    fn patch_deployment(
        &self,
        request: NativePatchRequest<'_>,
        immediately_before_first_write: NativePreWriteAuthorization<'_>,
    ) -> Result<NativeEksResponse, TransportFailure> {
        immediately_before_first_write.authorize()?;
        let durable = self.store.admission_context(&self.key).is_ok();
        let mut state = self.state.lock().unwrap();
        state.attempt_was_durable_at_patch = durable;
        assert!(durable, "PATCH reached transport before ATTEMPT_IN_FLIGHT");
        assert_eq!(request.method(), "PATCH");
        state.patch_count += 1;
        match state.mode {
            PatchMode::Success => Ok(NativeEksResponse::new(
                200,
                state.api_server_identity.clone(),
                [0x62; 32],
                state.after.clone(),
            )),
            PatchMode::OutcomeUnknown => Err(TransportFailure::OutcomeUnknown(
                "connection closed after application bytes".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct FakeSecret {
    prepared: PreparedExecution,
}

#[derive(Debug)]
struct FakeIssued {
    claims: CredentialClaims,
    bearer: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct FakeRejection;

#[derive(Clone, Copy, Debug)]
struct FakeDeletion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReconcileMode {
    Matching,
    Absent,
    Conflicting,
}

struct FakeBroker {
    secret: FakeSecret,
    claims: CredentialClaims,
    bearer: Vec<u8>,
    create_failure: Option<PortFailure>,
    crash_after_create_io: bool,
    reconcile_mode: ReconcileMode,
    issue_failure: Option<PortFailure>,
    reject_review: bool,
    delete_present_remaining: AtomicUsize,
    after_create: Option<Arc<dyn Fn() + Send + Sync>>,
    events: Mutex<Vec<&'static str>>,
    mutation_in_flight_checks: AtomicUsize,
    reconciliation_only_checks: AtomicUsize,
}

impl fmt::Debug for FakeBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeBroker")
            .field("secret", &self.secret)
            .field("claims", &self.claims)
            .field("bearer", &"[REDACTED]")
            .field("create_failure", &self.create_failure)
            .field("crash_after_create_io", &self.crash_after_create_io)
            .field("reconcile_mode", &self.reconcile_mode)
            .field("issue_failure", &self.issue_failure)
            .field("reject_review", &self.reject_review)
            .finish_non_exhaustive()
    }
}

impl FakeBroker {
    fn event_count(&self, name: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == name)
            .count()
    }

    fn record_mutation_io(
        &self,
        state: &InMemoryStore,
        authority: &BrokerIoAuthority,
        event: &'static str,
    ) {
        let authority_audit = authority.audit();
        let durable = state
            .broker_operation_audit(authority_audit.key(), authority_audit.operation())
            .unwrap();
        assert_eq!(authority_audit.phase(), BrokerJournalPhase::InFlight);
        assert_eq!(durable.phase(), BrokerJournalPhase::InFlight);
        assert_eq!(durable.entry_id(), authority_audit.entry_id());
        self.mutation_in_flight_checks
            .fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push(event);
    }

    fn record_reconciliation_io(
        &self,
        state: &InMemoryStore,
        authority: &BrokerReconciliationAuthority,
        event: &'static str,
    ) {
        let authority_audit = authority.audit();
        let durable = state
            .broker_operation_audit(authority_audit.key(), authority_audit.operation())
            .unwrap();
        assert_eq!(authority_audit.phase(), BrokerJournalPhase::ReconcileOnly);
        assert_eq!(durable.phase(), BrokerJournalPhase::ReconcileOnly);
        assert_eq!(durable.entry_id(), authority_audit.entry_id());
        self.reconciliation_only_checks
            .fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push(event);
    }
}

impl BrokerPort<InMemoryStore> for FakeBroker {
    type Secret = FakeSecret;
    type Issued = FakeIssued;
    type Rejection = FakeRejection;
    type Deletion = FakeDeletion;

    fn create(
        &self,
        state: &InMemoryStore,
        token: &DispatchClaimToken,
        route_commitment: [u8; 32],
    ) -> Result<JournaledPortValue<Self::Secret>, PortFailure> {
        let request = BrokerOperationRequest::create(token, route_commitment)
            .map_err(|error| map_state_failure(&error))?;
        let intent = state
            .prepare_broker_operation(request)
            .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_io(intent)
            .map_err(|error| map_state_failure(&error))?;
        self.record_mutation_io(state, &authority, "create");
        if let Some(failure) = self.create_failure {
            if self.crash_after_create_io {
                drop(authority);
            } else {
                state
                    .mark_broker_io_unknown(authority)
                    .map_err(|error| map_state_failure(&error))?;
            }
            return Err(failure);
        }
        let observation = BrokerSecretObservation::matching(
            self.secret.prepared.bound_object_uid.clone(),
            [0x71; 32],
        )
        .map_err(|error| map_state_failure(&error))?;
        let receipt = state
            .commit_broker_create(authority, observation)
            .map_err(|error| map_state_failure(&error))?;
        if let Some(callback) = &self.after_create {
            callback();
        }
        Ok(JournaledPortValue {
            value: self.secret.clone(),
            audit: receipt.audit().clone(),
        })
    }

    fn reconcile_create(
        &self,
        state: &InMemoryStore,
        key: &ConsumeKey,
        route_commitment: [u8; 32],
    ) -> Result<ReconciledSecret<Self::Secret>, PortFailure> {
        let request = BrokerReconciliationRequest::new(
            key.clone(),
            BrokerJournalOperation::CreateSecret,
            route_commitment,
        )
        .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_reconciliation(&request)
            .map_err(|error| map_state_failure(&error))?;
        self.record_reconciliation_io(state, &authority, "reconcile");
        let observation = match self.reconcile_mode {
            ReconcileMode::Matching => BrokerSecretObservation::matching(
                self.secret.prepared.bound_object_uid.clone(),
                [0x72; 32],
            ),
            ReconcileMode::Absent => BrokerSecretObservation::absent([0x73; 32]),
            ReconcileMode::Conflicting => BrokerSecretObservation::conflicting([0x74; 32]),
        }
        .map_err(|error| map_state_failure(&error))?;
        let result = state
            .commit_broker_reconciliation(authority, observation)
            .map_err(|error| map_state_failure(&error))?;
        match (self.reconcile_mode, result) {
            (ReconcileMode::Matching, BrokerReconciliationResult::Completed(receipt)) => {
                Ok(ReconciledSecret::Matching(JournaledPortValue {
                    value: self.secret.clone(),
                    audit: receipt.audit().clone(),
                }))
            }
            (ReconcileMode::Absent, BrokerReconciliationResult::Pending(authority)) => {
                Ok(ReconciledSecret::Absent(authority.audit()))
            }
            (ReconcileMode::Conflicting, BrokerReconciliationResult::Completed(receipt)) => {
                Ok(ReconciledSecret::Conflicting(receipt.audit().clone()))
            }
            _ => Err(PortFailure::new(PortFailureKind::Invalid)),
        }
    }

    fn prepared(secret: &Self::Secret) -> PreparedExecution {
        secret.prepared.clone()
    }

    fn issue(
        &self,
        state: &InMemoryStore,
        token: &DispatchClaimToken,
        route_commitment: [u8; 32],
        policy: BrokerCredentialSafetyPolicy,
    ) -> Result<JournaledPortValue<Self::Issued>, PortFailure> {
        let request = BrokerOperationRequest::issue_token(token, route_commitment, policy)
            .map_err(|error| map_state_failure(&error))?;
        let intent = state
            .prepare_broker_operation(request)
            .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_io(intent)
            .map_err(|error| map_state_failure(&error))?;
        self.record_mutation_io(state, &authority, "issue");
        if let Some(failure) = self.issue_failure {
            state
                .mark_broker_io_unknown(authority)
                .map_err(|error| map_state_failure(&error))?;
            return Err(failure);
        }
        let observation = BrokerTokenIssueObservation::new(
            self.claims.token_digest,
            self.claims.expires_at,
            [0x75; 32],
        )
        .map_err(|error| map_state_failure(&error))?;
        let receipt = state
            .commit_broker_token_issue(authority, &observation)
            .map_err(|error| map_state_failure(&error))?;
        Ok(JournaledPortValue {
            value: FakeIssued {
                claims: self.claims.clone(),
                bearer: self.bearer.clone(),
            },
            audit: receipt.audit().clone(),
        })
    }

    fn review(
        &self,
        issued: Self::Issued,
    ) -> Result<ReviewedCredential<Self::Rejection>, PortFailure> {
        self.events.lock().unwrap().push("review");
        if self.reject_review {
            return Ok(ReviewedCredential::Rejected(FakeRejection));
        }
        Ok(ReviewedCredential::Authenticated {
            claims: issued.claims,
            bearer: ExclusiveBearer::new(issued.bearer).unwrap(),
        })
    }

    fn delete(
        &self,
        state: &InMemoryStore,
        key: &ConsumeKey,
        route_commitment: [u8; 32],
    ) -> Result<BrokerOperationAudit, PortFailure> {
        let request = BrokerCleanupRequest::new(key.clone(), route_commitment)
            .map_err(|error| map_state_failure(&error))?;
        let intent = state
            .prepare_broker_cleanup(&request)
            .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_io(intent)
            .map_err(|error| map_state_failure(&error))?;
        self.record_mutation_io(state, &authority, "delete");
        state
            .mark_broker_io_unknown(authority)
            .map_err(|error| map_state_failure(&error))
    }

    fn verify_deleted(
        &self,
        state: &InMemoryStore,
        key: &ConsumeKey,
        route_commitment: [u8; 32],
    ) -> Result<ObservedDeletion<Self::Deletion>, PortFailure> {
        let request = BrokerReconciliationRequest::new(
            key.clone(),
            BrokerJournalOperation::DeleteSecret,
            route_commitment,
        )
        .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_reconciliation(&request)
            .map_err(|error| map_state_failure(&error))?;
        self.record_reconciliation_io(state, &authority, "verify-delete");
        let observed_present = self
            .delete_present_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok();
        let observation = if observed_present {
            BrokerSecretObservation::matching(
                self.secret.prepared.bound_object_uid.clone(),
                [0x76; 32],
            )
        } else {
            BrokerSecretObservation::absent([0x77; 32])
        }
        .map_err(|error| map_state_failure(&error))?;
        match state
            .commit_broker_reconciliation(authority, observation)
            .map_err(|error| map_state_failure(&error))?
        {
            BrokerReconciliationResult::Completed(receipt) => {
                Ok(ObservedDeletion::Absent(JournaledPortValue {
                    value: FakeDeletion,
                    audit: receipt.audit().clone(),
                }))
            }
            BrokerReconciliationResult::Pending(authority) if observed_present => {
                Ok(ObservedDeletion::Present(authority.audit()))
            }
            BrokerReconciliationResult::Pending(_) => {
                Err(PortFailure::new(PortFailureKind::Invalid))
            }
        }
    }

    fn retirement(&self, _deletion: &Self::Deletion) -> Result<CredentialRetirement, PortFailure> {
        self.events.lock().unwrap().push("retirement");
        Ok(CredentialRetirement::Pending { safe_after: 170 })
    }
}

struct Fixture {
    store: InMemoryStore,
    state_clock: Arc<StateClock>,
    scope: Scope,
    authority: AuthorityVector,
    grant_id: Uuid,
    request: DispatchClaimRequest,
    machine: DispatchMachine,
    broker: FakeBroker,
    executor: ExclusiveEksExecutor<CheckingTransport, SequenceClock>,
    transport: CheckingTransport,
}

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new(
        seed: u128,
        patch_mode: PatchMode,
        orchestration_times: &[i64],
    ) -> (Self, SequenceClock) {
        let transaction_id = Uuid::from_u128((1_u128 << 120) | seed);
        let authorization_id = Uuid::from_u128((2_u128 << 120) | seed);
        let claim_id = Uuid::from_u128((3_u128 << 120) | seed);
        let deployment_uid = Uuid::from_u128((9_u128 << 120) | seed).to_string();
        let cluster_identity = format!("eks://cluster-{seed:x}");
        let api_server_identity = format!("urn:accordlock:api:cluster-{seed:x}");
        let service_account_uid = Uuid::from_u128((10_u128 << 120) | seed).to_string();
        let before = deployment_before(&deployment_uid);
        let before_bytes = serde_json::to_vec(&before).unwrap();
        let template = DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1".repeat(40),
            image_repository: "registry.example/acme/payments".to_owned(),
            image_digest: digest("new-image"),
            cluster_identity: cluster_identity.clone(),
            namespace: "payments".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: deployment_uid.clone(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: digest("old-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: Digest32::sha256(&before_bytes),
            prior_transaction_annotation: Some("unset".to_owned()),
            prior_authorization_annotation: Some("unset".to_owned()),
            prior_operation_hash_annotation: Some("unset".to_owned()),
        };
        let prepared_patch = prepare_patch(&template, transaction_id, authorization_id).unwrap();
        let after = deployment_after(
            before.clone(),
            &template,
            transaction_id,
            authorization_id,
            prepared_patch.operation_hash,
        );
        let prepared = PreparedExecution {
            bound_object_uid: format!("secret-uid-{seed:x}"),
            template_hash: *canonical_hash(&template).unwrap().as_bytes(),
            operation_hash: *prepared_patch.operation_hash.as_bytes(),
            token_subject: "system:serviceaccount:payments:accordlock-attempt".to_owned(),
            token_audience: "https://kubernetes.default.svc".to_owned(),
            effective_rbac_commitment: [0x41; 32],
            execution_command_commitment: *prepared_patch.execution_command_commitment.as_bytes(),
            final_wire_commitment: *prepared_patch.final_wire_commitment.as_bytes(),
        };
        let claims = CredentialClaims {
            token_digest: Sha256::digest(BEARER).into(),
            subject: prepared.token_subject.clone(),
            audience: prepared.token_audience.clone(),
            service_account_uid: service_account_uid.clone(),
            credential_id: format!(
                "AUTHORIZATION_ID={}",
                Uuid::from_u128((11_u128 << 120) | seed)
            ),
            bound_object_uid: prepared.bound_object_uid.clone(),
            not_before: 100,
            expires_at: 130,
        };

        let state_clock = Arc::new(StateClock::new(100));
        let store = InMemoryStore::with_clock(state_clock.clone());
        let scope = Scope::new("acme", "prod").unwrap();
        let signer = SigningIdentity::from_seed(format!("enforcement-{seed:x}"), [0x51; 32]);
        let grant_id = Uuid::from_u128((4_u128 << 120) | seed);
        let grant = CapabilityGrant {
            grant_id,
            holder: "workload:release".to_owned(),
            tenant: scope.tenant.clone(),
            operation: template.operation.clone(),
            repository: template.repository.clone(),
            audience: template.audience.clone(),
            cluster_identity: template.cluster_identity.clone(),
            namespace: template.namespace.clone(),
            deployment_uid: template.deployment_uid.clone(),
            container: template.container.clone(),
            image_repository: template.image_repository.clone(),
            not_before: 50,
            expires_at: 300,
            maximum_uses: 1,
        };
        let mut authority = authority(seed);
        authority.grant_registry.root = canonical_hash(&grant).unwrap();
        authority.signer.root =
            authorization_signer_root(signer.key_id(), signer.public_key_bytes()).unwrap();
        let deadline_policy = DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 60,
            profile_hard_cap: 200,
            immutable_dependency_expiries: vec![190],
        };
        store
            .compare_and_activate_authority(&scope, None, &authority)
            .unwrap();
        store
            .register_grant(&GrantRegistration {
                environment: scope.environment.clone(),
                grant: grant.clone(),
                authority: authority.clone(),
                dispatch_deadline_policy: deadline_policy.clone(),
            })
            .unwrap();
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id,
            evaluation_nonce: Uuid::from_u128((5_u128 << 120) | seed),
            request_id: Uuid::from_u128((6_u128 << 120) | seed),
            tenant: scope.tenant.clone(),
            holder: grant.holder.clone(),
            audience: template.audience.clone(),
            issued_at: 90,
            not_before: 90,
            consume_before: 180,
            dispatch_deadline_policy: deadline_policy,
            grant_id,
            template: template.clone(),
            template_hash: canonical_hash(&template).unwrap(),
            evidence_root: digest("evidence"),
            principals: vec!["principal:review".to_owned()],
            policy_root: authority.policy.root,
            authority: authority.clone(),
        };
        let cose_sign1 = sign_cose(
            &authorization.canonical_bytes().unwrap(),
            EXECUTION_AUTHORIZATION_DOMAIN,
            &signer,
        )
        .unwrap();
        store
            .record_issued_authorization(
                &IssuedAuthorizationRecord::new(
                    transaction_id,
                    SignedAuthorization {
                        authorization,
                        cose_sign1,
                    },
                    signer.key_id().to_owned(),
                    signer.public_key_bytes(),
                )
                .unwrap(),
            )
            .unwrap();
        let key = ConsumeKey {
            scope: scope.clone(),
            transaction_id,
            authorization_id,
        };
        store.consume(&key).unwrap();

        let physical = PhysicalResourceId {
            cluster_trust_domain: cluster_identity.clone(),
            api_server_identity: api_server_identity.clone(),
            namespace: template.namespace.clone(),
            deployment_uid: deployment_uid.clone(),
        };
        let ca_certificates = vec![b"enforcement-test-ca".to_vec()];
        let route_profile = EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: &physical.cluster_trust_domain,
            cluster_identity: &cluster_identity,
            api_server_identity: &api_server_identity,
            dns_server_name: "api.cluster.eks.amazonaws.com",
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::from(([192, 0, 2, 31], 443)))
                .unwrap(),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(&ca_certificates)
                .unwrap(),
            namespace: &template.namespace,
            deployment_name: &template.deployment,
            deployment_uid: &deployment_uid,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: &service_account_uid,
            token_audience: &prepared.token_audience,
        })
        .unwrap();
        let mut machine = DispatchMachine::new(
            DispatchBounds {
                max_dispatch_delay_s: 60,
                token_lifetime_upper_bound_s: 60,
                clock_uncertainty_s: 0,
                minimum_remaining_lifetime_s: 1,
                lease_ttl_s: 30,
            },
            authority_version_from_vector(&authority).unwrap(),
            100,
        )
        .unwrap();
        machine
            .register_destination(
                physical.clone(),
                LogicalOwner {
                    tenant: scope.tenant.clone(),
                    environment: scope.environment.clone(),
                },
                CredentialProfile {
                    token_subject: prepared.token_subject.clone(),
                    token_audience: prepared.token_audience.clone(),
                    effective_rbac_commitment: prepared.effective_rbac_commitment,
                },
            )
            .unwrap();

        let transport = CheckingTransport {
            route_profile: route_profile.clone(),
            state: Arc::new(Mutex::new(TransportState {
                before: serde_json::to_vec(&before).unwrap(),
                after: serde_json::to_vec(&after).unwrap(),
                api_server_identity: api_server_identity.clone(),
                mode: patch_mode,
                get_count: 0,
                patch_count: 0,
                attempt_was_durable_at_patch: false,
            })),
            store: store.clone(),
            key: key.clone(),
        };
        let executor = ExclusiveEksExecutor::new(
            ExecutorConfig::new(
                route_profile,
                format!("kubernetes-api-server/cluster-{seed:x}"),
                1,
            )
            .unwrap(),
            transport.clone(),
            SequenceClock::new([102, 103]),
        );
        let request = DispatchClaimRequest {
            key,
            claim_id,
            worker_id: format!("worker-{seed:x}"),
        };
        let broker = FakeBroker {
            secret: FakeSecret { prepared },
            claims,
            bearer: BEARER.to_vec(),
            create_failure: None,
            crash_after_create_io: false,
            reconcile_mode: ReconcileMode::Matching,
            issue_failure: None,
            reject_review: false,
            delete_present_remaining: AtomicUsize::new(0),
            after_create: None,
            events: Mutex::new(Vec::new()),
            mutation_in_flight_checks: AtomicUsize::new(0),
            reconciliation_only_checks: AtomicUsize::new(0),
        };
        (
            Self {
                store,
                state_clock,
                scope,
                authority,
                grant_id,
                request,
                machine,
                broker,
                executor,
                transport,
            },
            SequenceClock::new(orchestration_times.iter().copied()),
        )
    }
}

fn deployment_before(deployment_uid: &str) -> Value {
    json!({
        "apiVersion":"apps/v1",
        "kind":"Deployment",
        "metadata":{
            "name":"payments",
            "namespace":"payments",
            "uid":deployment_uid,
            "resourceVersion":"1001",
            "generation":7,
            "annotations":{
                "accordlock.io/transaction-id":"unset",
                "accordlock.io/authorization-id":"unset",
                "accordlock.io/operation-hash":"unset"
            },
            "labels":{"app":"payments"}
        },
        "spec":{
            "replicas":1,
            "selector":{"matchLabels":{"app":"payments"}},
            "template":{
                "metadata":{"labels":{"app":"payments"}},
                "spec":{"containers":[{
                    "name":"app",
                    "image":format!("registry.example/acme/payments@{}", digest("old-image"))
                }]}
            }
        }
    })
}

fn deployment_after(
    mut before: Value,
    template: &DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
    operation_hash: Digest32,
) -> Value {
    *before.pointer_mut("/metadata/resourceVersion").unwrap() = json!("1002");
    *before.pointer_mut("/metadata/generation").unwrap() = json!(8);
    *before
        .pointer_mut("/spec/template/spec/containers/0/image")
        .unwrap() = json!(format!(
        "{}@{}",
        template.image_repository, template.image_digest
    ));
    *before
        .pointer_mut("/metadata/annotations/accordlock.io~1transaction-id")
        .unwrap() = json!(transaction_id.to_string());
    *before
        .pointer_mut("/metadata/annotations/accordlock.io~1authorization-id")
        .unwrap() = json!(authorization_id.to_string());
    *before
        .pointer_mut("/metadata/annotations/accordlock.io~1operation-hash")
        .unwrap() = json!(operation_hash.to_string());
    before
}

fn digest(label: &str) -> Digest32 {
    Digest32::sha256(label.as_bytes())
}

fn domain(label: &str, epoch: u64, seed: u128) -> AuthorityDomainState {
    AuthorityDomainState {
        root: digest(label),
        epoch,
        activation_id: Uuid::from_u128(seed.wrapping_mul(100).wrapping_add(u128::from(epoch))),
    }
}

fn authority(seed: u128) -> AuthorityVector {
    AuthorityVector {
        policy: domain("policy", 1, seed),
        registry: domain("registry", 2, seed),
        revocation: domain("revocation", 3, seed),
        connector: domain("connector", 4, seed),
        resource: domain("resource", 5, seed),
        signer: domain("signer", 6, seed),
        mediation: domain("mediation", 7, seed),
        grant_registry: domain("grant", 8, seed),
        office_act_registry: domain("office", 9, seed),
        principal_registry: domain("principal", 10, seed),
        workload_build_allowlist: domain("build", 11, seed),
        kernel_configuration: domain("kernel", 12, seed),
    }
}

fn run(fixture: &mut Fixture, clock: &SequenceClock) -> EnforcementOutcome {
    let route_commitment = *fixture.executor.route_profile().commitment().as_bytes();
    let broker_credential_policy = BrokerCredentialSafetyPolicy::new(60, 0).unwrap();
    run_enforcement(
        &fixture.store,
        &mut fixture.machine,
        &fixture.broker,
        &fixture.executor,
        clock,
        &fixture.scope,
        route_commitment,
        broker_credential_policy,
        &fixture.request,
    )
}

#[test]
fn private_mechanical_path_establishes_effect_and_reports_conservative_retirement() {
    let (mut fixture, clock) = Fixture::new(0x101, PatchMode::Success, &[100]);
    let outcome = run(&mut fixture, &clock);
    assert_eq!(
        outcome,
        EnforcementOutcome::EffectEstablished {
            transaction_id: fixture.request.key.transaction_id,
            lifecycle_recorded: true,
            retirement: CredentialRetirement::Pending { safe_after: 170 },
        }
    );
    assert_eq!(fixture.transport.counts(), (1, 1));
    assert!(fixture.transport.durable_at_patch());
    assert_eq!(fixture.broker.event_count("create"), 1);
    assert_eq!(fixture.broker.event_count("issue"), 1);
    assert_eq!(fixture.broker.event_count("delete"), 1);
    assert_eq!(
        fixture
            .broker
            .mutation_in_flight_checks
            .load(Ordering::SeqCst),
        3
    );
    assert_eq!(
        fixture
            .broker
            .reconciliation_only_checks
            .load(Ordering::SeqCst),
        1
    );
    let create = fixture
        .store
        .broker_operation_audit(&fixture.request.key, BrokerJournalOperation::CreateSecret)
        .unwrap();
    assert_eq!(create.phase(), BrokerJournalPhase::Committed);
    assert_eq!(create.outcome(), Some(BrokerJournalOutcome::CreateMatching));
    let token = fixture
        .store
        .broker_operation_audit(&fixture.request.key, BrokerJournalOperation::IssueToken)
        .unwrap();
    assert_eq!(token.phase(), BrokerJournalPhase::Committed);
    assert_eq!(token.outcome(), Some(BrokerJournalOutcome::TokenIssued));
    let deletion = fixture
        .store
        .broker_operation_audit(&fixture.request.key, BrokerJournalOperation::DeleteSecret)
        .unwrap();
    assert_eq!(deletion.phase(), BrokerJournalPhase::Committed);
    assert_eq!(deletion.outcome(), Some(BrokerJournalOutcome::DeleteAbsent));
}

#[test]
fn private_mechanical_path_rejects_scope_substitution_before_claim_or_io() {
    let (mut fixture, clock) = Fixture::new(0x102, PatchMode::Success, &[100]);
    let mut substituted = fixture.request.clone();
    substituted.key.scope = Scope::new("attacker", "prod").unwrap();
    let route_commitment = *fixture.executor.route_profile().commitment().as_bytes();
    let broker_credential_policy = BrokerCredentialSafetyPolicy::new(60, 0).unwrap();

    let outcome = run_enforcement(
        &fixture.store,
        &mut fixture.machine,
        &fixture.broker,
        &fixture.executor,
        &clock,
        &fixture.scope,
        route_commitment,
        broker_credential_policy,
        &substituted,
    );

    assert_eq!(
        outcome,
        EnforcementOutcome::Quarantined {
            transaction_id: substituted.key.transaction_id,
            stage: EnforcementStage::Claim,
            reason: QuarantineReason::Rejected,
            conservative_safe_after: None,
            retirement: CredentialRetirement::Unknown,
        }
    );
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert_eq!(fixture.broker.event_count("create"), 0);
    assert_eq!(fixture.broker.event_count("issue"), 0);
    assert_eq!(fixture.broker.event_count("delete"), 0);
}

#[test]
fn production_readiness_gate_performs_no_provider_work() {
    let transaction_id = Uuid::from_u128(0xfeed);
    assert_eq!(
        production_readiness_blocked(transaction_id),
        EnforcementOutcome::ReadinessBlocked {
            transaction_id,
            blockers: [
                EnforcementReadinessBlocker::ManagementRbacLiveProof,
                EnforcementReadinessBlocker::AuthenticatedWebhookCallerBoundary,
                EnforcementReadinessBlocker::KubernetesApiAudienceLiveProof,
            ],
        }
    );
}

#[test]
fn production_surface_only_accepts_the_state_backed_attempt_authority() {
    let surface = include_str!("lib.rs");

    assert!(surface.contains("broker: EksCredentialBroker<StateBackedAttemptAuthority<S>, M, BC>"));
    assert!(surface.contains("StateBackedAttemptAuthority::new(state.clone(), scope.clone())"));
    assert!(!surface.contains("pub struct EksEnforcement<S, A,"));
    assert!(!surface.contains("broker: EksCredentialBroker<A, M, BC>"));
    assert!(!surface.contains("DurableAttemptFactsRegistry"));
    assert!(!surface.contains("AllProductionBoundariesVerified"));
    assert!(!surface.contains("production_gate"));
    assert!(surface.contains("enum VerifiedLiveDeploymentBoundaries {}"));
    assert!(!surface.contains("pub enum VerifiedLiveDeploymentBoundaries"));
}

#[test]
fn broker_configuration_error_is_coarse_and_redacted() {
    for source in [
        BrokerConfigError::InvalidCaBundle,
        BrokerConfigError::CaTrustCommitmentMismatch,
        BrokerConfigError::InvalidTransportBounds,
        BrokerConfigError::InvalidProfile,
        BrokerConfigError::TlsConfiguration,
    ] {
        let error = EnforcementConfigError::BrokerConfig(source);
        assert_eq!(
            error.to_string(),
            "fixed EKS broker configuration is invalid"
        );
    }
}

#[test]
fn orchestrator_requires_one_exact_broker_executor_route() {
    let (fixture, _clock) = Fixture::new(0x1f1, PatchMode::Success, &[100]);
    let route = fixture.executor.route_profile().clone();
    let alternate = EksRouteProfile::new(EksRouteProfileInput {
        cluster_trust_domain: route.cluster_trust_domain(),
        cluster_identity: "eks://alternate-cluster",
        api_server_identity: route.api_server_identity(),
        dns_server_name: route.dns_server_name(),
        port: route.port(),
        socket_target: route.socket_target(),
        ca_trust_commitment: route.ca_trust_commitment(),
        namespace: route.namespace(),
        deployment_name: route.deployment_name(),
        deployment_uid: route.deployment_uid(),
        attempt_service_account_name: route.attempt_service_account_name(),
        attempt_service_account_uid: route.attempt_service_account_uid(),
        token_audience: route.token_audience(),
    })
    .unwrap();

    assert_eq!(validate_unified_route(&route, &route, &route), Ok(()));
    assert_eq!(
        validate_unified_route(&route, &alternate, &route),
        Err(EnforcementConfigError::BrokerRouteMismatch(
            RouteField::ClusterIdentity
        ))
    );
    assert_eq!(
        validate_unified_route(&route, &route, &alternate),
        Err(EnforcementConfigError::ExecutorRouteMismatch(
            RouteField::ClusterIdentity
        ))
    );
}

#[test]
fn create_ambiguity_reconciles_once_without_a_second_create() {
    let (mut fixture, clock) = Fixture::new(0x102, PatchMode::Success, &[100, 100]);
    fixture.broker.create_failure = Some(PortFailure {
        kind: PortFailureKind::OutcomeUnknown,
        conservative_safe_after: None,
    });
    fixture.broker.crash_after_create_io = true;
    let outcome = run(&mut fixture, &clock);
    assert!(matches!(
        outcome,
        EnforcementOutcome::EffectEstablished { .. }
    ));
    assert_eq!(fixture.broker.event_count("create"), 1);
    assert_eq!(fixture.broker.event_count("reconcile"), 1);
    assert_eq!(fixture.transport.counts().1, 1);
}

#[test]
fn delete_presence_keeps_get_only_reconciliation_until_late_absence() {
    let (mut fixture, clock) = Fixture::new(0x10b, PatchMode::Success, &[100]);
    fixture
        .broker
        .delete_present_remaining
        .store(1, Ordering::SeqCst);

    let outcome = run(&mut fixture, &clock);
    assert!(matches!(
        outcome,
        EnforcementOutcome::EffectEstablished {
            retirement: CredentialRetirement::Unknown,
            ..
        }
    ));
    let pending = fixture
        .store
        .broker_operation_audit(&fixture.request.key, BrokerJournalOperation::DeleteSecret)
        .unwrap();
    assert_eq!(pending.phase(), BrokerJournalPhase::ReconcileOnly);
    assert_eq!(
        pending.last_reconciliation_outcome(),
        Some(BrokerJournalOutcome::DeletePresent)
    );
    assert_eq!(fixture.broker.event_count("delete"), 1);
    assert_eq!(fixture.broker.event_count("verify-delete"), 1);

    let route_commitment = *fixture.executor.route_profile().commitment().as_bytes();
    assert_eq!(
        cleanup(
            &fixture.store,
            &fixture.broker,
            &fixture.request.key,
            route_commitment,
        ),
        CredentialRetirement::Pending { safe_after: 170 }
    );
    assert_eq!(fixture.broker.event_count("delete"), 1);
    assert_eq!(fixture.broker.event_count("verify-delete"), 2);
    let committed = fixture
        .store
        .broker_operation_audit(&fixture.request.key, BrokerJournalOperation::DeleteSecret)
        .unwrap();
    assert_eq!(committed.phase(), BrokerJournalPhase::Committed);
    assert_eq!(
        committed.outcome(),
        Some(BrokerJournalOutcome::DeleteAbsent)
    );
}

#[test]
fn token_request_ambiguity_never_retries_or_patches() {
    let (mut fixture, clock) = Fixture::new(0x103, PatchMode::Success, &[100, 100]);
    fixture.broker.issue_failure = Some(PortFailure {
        kind: PortFailureKind::OutcomeUnknown,
        conservative_safe_after: Some(170),
    });
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.broker.event_count("issue"), 1);
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::CredentialIssue,
            reason: QuarantineReason::OutcomeUnknown,
            conservative_safe_after: Some(170),
            ..
        }
    ));
}

#[test]
fn patch_ambiguity_is_quarantined_after_exactly_one_durable_attempt() {
    let (mut fixture, clock) = Fixture::new(0x104, PatchMode::OutcomeUnknown, &[100, 103]);
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.transport.counts(), (1, 1));
    assert!(fixture.transport.durable_at_patch());
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::ProviderEffect,
            reason: QuarantineReason::OutcomeUnknown,
            ..
        }
    ));
}

#[test]
fn token_substitution_is_rejected_before_get_or_patch() {
    let (mut fixture, clock) = Fixture::new(0x105, PatchMode::Success, &[100, 103]);
    fixture.broker.bearer = SUBSTITUTE_BEARER.to_vec();
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::ProviderEffect,
            reason: QuarantineReason::Rejected,
            ..
        }
    ));
}

#[test]
fn deadline_change_after_secret_create_blocks_token_request() {
    let (mut fixture, clock) = Fixture::new(0x106, PatchMode::Success, &[100]);
    let state_clock = fixture.state_clock.clone();
    fixture.broker.after_create = Some(Arc::new(move || state_clock.set(160)));
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.broker.event_count("issue"), 0);
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::CredentialIssue,
            reason: QuarantineReason::Rejected,
            ..
        }
    ));
}

#[test]
fn revocation_after_secret_create_blocks_token_request() {
    let (mut fixture, clock) = Fixture::new(0x107, PatchMode::Success, &[100]);
    let store = fixture.store.clone();
    let scope = fixture.scope.clone();
    let grant_id = fixture.grant_id;
    let expected = fixture.authority.clone();
    let mut revoked = expected.clone();
    revoked.revocation.epoch += 1;
    revoked.revocation.activation_id = Uuid::new_v4();
    revoked.revocation.root = grant_revocation_root(grant_id);
    fixture.broker.after_create = Some(Arc::new(move || {
        store
            .revoke_grant(&scope, grant_id, &expected, &revoked)
            .unwrap();
    }));
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.broker.event_count("issue"), 0);
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::CredentialIssue,
            reason: QuarantineReason::Rejected,
            ..
        }
    ));
}

#[test]
fn pre_delete_token_rejection_is_not_terminal_retirement_evidence() {
    let (mut fixture, clock) = Fixture::new(0x108, PatchMode::Success, &[100, 100]);
    fixture.broker.reject_review = true;
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::TokenReview,
            reason: QuarantineReason::Rejected,
            retirement: CredentialRetirement::Pending { safe_after: 170 },
            ..
        }
    ));
    assert_eq!(fixture.broker.event_count("review"), 1);
    assert_eq!(fixture.broker.event_count("delete"), 1);
    assert_eq!(fixture.broker.event_count("verify-delete"), 1);
    assert_eq!(fixture.broker.event_count("retirement"), 1);
}

#[test]
fn conflicting_create_reconciliation_stops_without_mutation_retry() {
    let (mut fixture, clock) = Fixture::new(0x109, PatchMode::Success, &[100]);
    fixture.broker.create_failure = Some(PortFailure::new(PortFailureKind::OutcomeUnknown));
    fixture.broker.reconcile_mode = ReconcileMode::Conflicting;
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.broker.event_count("create"), 1);
    assert_eq!(fixture.broker.event_count("reconcile"), 1);
    assert_eq!(fixture.broker.event_count("issue"), 0);
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::SecretReconcile,
            ..
        }
    ));
}

#[test]
fn absent_create_reconciliation_stops_without_mutation_retry() {
    let (mut fixture, clock) = Fixture::new(0x10a, PatchMode::Success, &[100]);
    fixture.broker.create_failure = Some(PortFailure::new(PortFailureKind::OutcomeUnknown));
    fixture.broker.reconcile_mode = ReconcileMode::Absent;
    let outcome = run(&mut fixture, &clock);
    assert_eq!(fixture.broker.event_count("create"), 1);
    assert_eq!(fixture.broker.event_count("reconcile"), 1);
    assert_eq!(fixture.broker.event_count("issue"), 0);
    assert_eq!(fixture.transport.counts(), (0, 0));
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            stage: EnforcementStage::SecretReconcile,
            ..
        }
    ));
}
