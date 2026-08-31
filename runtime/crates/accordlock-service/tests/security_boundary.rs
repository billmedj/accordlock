use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use accordlock_ingress::{
    ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
    IngressError, IngressKeyStatus, MemoryReplayGuard, RegisteredIngressKey, SignedIngressRequest,
    sign_ingress_request,
};
use accordlock_protocol::{
    AgentProposal, AuthorityDomainState, DeploymentTemplate, Digest32, SigningIdentity,
};
use accordlock_service::trusted::{
    AuthenticatedIngressRequest, DispatchDisposition, EnforcementDecision, TrustedAuthorizer,
    TrustedClock, TrustedCommitter, TrustedDispatcher, TrustedFailure, TrustedFailureCode,
    TrustedIngress, TrustedInstant, TrustedStatusStore,
};
use accordlock_service::{
    AccordLockService, ActionState, EnvelopeViolation, MAX_SIGNED_STATUS_BYTES,
    MAX_SIGNED_SUBMISSION_BYTES, PublicReasonCode, ReceiptId, RequestId, ServiceError,
    StatusEnvelope, StatusLookup, StatusView, SubmissionEnvelope, TrustedPipeline,
};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const AUDIENCE: &str = "accordlock-executor://tenant-a/prod/eks";
const STATUS_MAC: &str = "trusted-test-status-mac";

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn valid<T, E>(result: Result<T, E>) -> T
where
    E: std::fmt::Display,
{
    result.unwrap_or_else(|error| unreachable!("test fixture is valid: {error}"))
}

fn required_error<T, E>(result: Result<T, E>) -> E {
    match result {
        Err(error) => error,
        Ok(_) => unreachable!("test expected a fail-closed error"),
    }
}

#[derive(Clone, Debug, Default)]
struct AuditLog {
    events: Arc<Mutex<Vec<String>>>,
}

impl AuditLog {
    fn push(&self, event: impl Into<String>) {
        lock(&self.events).push(event.into());
    }

    fn snapshot(&self) -> Vec<String> {
        lock(&self.events).clone()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AuthenticatedStatusScope {
    tenant: String,
    actor: String,
    environment: String,
}

#[derive(Debug, PartialEq, Eq)]
struct AuthenticatedSubmissionScope {
    tenant: String,
    actor: String,
    environment: String,
    request_id: String,
}

#[derive(Debug)]
struct RealProposalIngress {
    authenticator: IngressAuthenticator<MemoryReplayGuard>,
    now: i64,
    log: AuditLog,
}

impl RealProposalIngress {
    fn map_ingress_error(error: &IngressError) -> TrustedFailure {
        let code = match error {
            IngressError::Replay => TrustedFailureCode::ReplayRejected,
            IngressError::ReplayStateUnavailable => TrustedFailureCode::IngressUnavailable,
            _ => TrustedFailureCode::AuthenticationFailed,
        };
        TrustedFailure::new(code)
    }

    fn rejected() -> TrustedFailure {
        TrustedFailure::new(TrustedFailureCode::AuthenticationFailed)
    }
}

impl TrustedIngress for RealProposalIngress {
    type AuthenticatedStatusScope = AuthenticatedStatusScope;

    fn authenticate_submission(
        &self,
        signed_envelope: &[u8],
    ) -> Result<AuthenticatedIngressRequest, TrustedFailure> {
        self.log.push("ingress:submission");
        let json = std::str::from_utf8(signed_envelope).map_err(|_| Self::rejected())?;
        self.authenticator
            .authenticate_json(json, self.now)
            .map_err(|error| Self::map_ingress_error(&error))
    }

    fn authenticate_status(
        &self,
        lookup: &StatusLookup,
        signed_authentication: &[u8],
    ) -> Result<Self::AuthenticatedStatusScope, TrustedFailure> {
        self.log
            .push(format!("ingress:status:{}", lookup.receipt_id()));
        let wire = std::str::from_utf8(signed_authentication).map_err(|_| Self::rejected())?;
        let mut fields = wire.split('|');
        let schema = fields.next().ok_or_else(Self::rejected)?;
        let tenant = fields.next().ok_or_else(Self::rejected)?;
        let actor = fields.next().ok_or_else(Self::rejected)?;
        let environment = fields.next().ok_or_else(Self::rejected)?;
        let bound_receipt = fields.next().ok_or_else(Self::rejected)?;
        let mac = fields.next().ok_or_else(Self::rejected)?;

        let known_principal = matches!(
            (tenant, actor),
            ("tenant-a", "deploy-agent") | ("tenant-b", "other-agent")
        );
        if schema != "status-v1"
            || !known_principal
            || environment.is_empty()
            || bound_receipt != lookup.receipt_id().as_str()
            || mac != STATUS_MAC
            || fields.next().is_some()
        {
            return Err(Self::rejected());
        }

        Ok(AuthenticatedStatusScope {
            tenant: tenant.to_owned(),
            actor: actor.to_owned(),
            environment: environment.to_owned(),
        })
    }
}

#[derive(Debug)]
struct SequenceClock {
    values: Mutex<VecDeque<i64>>,
    log: AuditLog,
}

impl SequenceClock {
    fn new(values: [i64; 3], log: AuditLog) -> Self {
        Self {
            values: Mutex::new(values.into()),
            log,
        }
    }
}

impl TrustedClock for SequenceClock {
    fn now(&self) -> Result<TrustedInstant, TrustedFailure> {
        let Some(value) = lock(&self.values).pop_front() else {
            return Err(TrustedFailure::new(TrustedFailureCode::ClockUnavailable));
        };
        self.log.push(format!("clock:{value}"));
        Ok(TrustedInstant::from_unix_seconds(value))
    }
}

#[derive(Debug)]
struct AuthorizationCandidate {
    authority_source: &'static str,
    grant_source: &'static str,
    evaluated_at: i64,
}

#[derive(Debug)]
struct MockAuthorizer {
    allowed_image_repository: &'static str,
    log: AuditLog,
}

impl TrustedAuthorizer for MockAuthorizer {
    type Authorization = AuthorizationCandidate;
    type AuthenticatedSubmissionScope = AuthenticatedSubmissionScope;

    fn authorize(
        &self,
        request: AuthenticatedIngressRequest,
        evaluated_at: TrustedInstant,
    ) -> Result<
        EnforcementDecision<Self::Authorization, Self::AuthenticatedSubmissionScope>,
        TrustedFailure,
    > {
        // This helper deliberately takes ownership, mirroring a real
        // KernelContext::from_authenticated_ingress call. No second use of the
        // ingress capability is possible after it returns.
        let kernel_context = KernelStyleContext::from_authenticated_ingress(request);
        let evaluated = kernel_context.evaluate();
        self.log.push(format!(
            "authorize:{}:{}:{}:{}",
            evaluated.status_scope.tenant,
            evaluated.status_scope.actor,
            evaluated.image_repository,
            evaluated_at.unix_seconds()
        ));
        if evaluated.image_repository != self.allowed_image_repository {
            return Ok(EnforcementDecision::Denied {
                reason: PublicReasonCode::PolicyDenied,
                status_scope: evaluated.status_scope,
            });
        }
        Ok(EnforcementDecision::Authorized {
            authorization: AuthorizationCandidate {
                authority_source: "trusted-authority-store",
                grant_source: "server-selected-grant",
                evaluated_at: evaluated_at.unix_seconds(),
            },
            status_scope: evaluated.status_scope,
        })
    }
}

#[derive(Debug)]
struct KernelStyleEvaluation {
    status_scope: AuthenticatedSubmissionScope,
    image_repository: String,
}

struct KernelStyleContext {
    ingress: AuthenticatedIngressRequest,
}

impl KernelStyleContext {
    fn from_authenticated_ingress(ingress: AuthenticatedIngressRequest) -> Self {
        Self { ingress }
    }

    fn evaluate(&self) -> KernelStyleEvaluation {
        KernelStyleEvaluation {
            status_scope: AuthenticatedSubmissionScope {
                tenant: self.ingress.caller().tenant().to_owned(),
                actor: self.ingress.caller().actor().to_owned(),
                environment: self.ingress.proposal().template.environment.clone(),
                request_id: self.ingress.proposal().request_id.to_string(),
            },
            image_repository: self.ingress.proposal().template.image_repository.clone(),
        }
    }
}

#[derive(Debug)]
struct CommittedAuthorization {
    key_used: &'static str,
    authority_source: &'static str,
}

#[derive(Debug)]
struct MockCommitter {
    configured_key: &'static str,
    log: AuditLog,
    fail: bool,
}

impl TrustedCommitter<AuthorizationCandidate> for MockCommitter {
    type CommittedAuthorization = CommittedAuthorization;

    fn sign_and_commit(
        &self,
        authorization: AuthorizationCandidate,
        committed_at: TrustedInstant,
    ) -> Result<Self::CommittedAuthorization, TrustedFailure> {
        self.log.push(format!(
            "commit:key={}:authority={}:grant={}:evaluated={}:committed={}",
            self.configured_key,
            authorization.authority_source,
            authorization.grant_source,
            authorization.evaluated_at,
            committed_at.unix_seconds()
        ));
        if self.fail {
            return Err(TrustedFailure::new(
                TrustedFailureCode::SigningOrCommitFailed,
            ));
        }
        Ok(CommittedAuthorization {
            key_used: self.configured_key,
            authority_source: authorization.authority_source,
        })
    }
}

#[derive(Debug)]
struct MockDispatcher {
    log: AuditLog,
}

impl TrustedDispatcher<CommittedAuthorization> for MockDispatcher {
    fn dispatch(
        &self,
        authorization: CommittedAuthorization,
        dispatched_at: TrustedInstant,
    ) -> Result<DispatchDisposition, TrustedFailure> {
        self.log.push(format!(
            "dispatch:key={}:authority={}:at={}",
            authorization.key_used,
            authorization.authority_source,
            dispatched_at.unix_seconds()
        ));
        Ok(DispatchDisposition::Pending)
    }
}

type StatusKey = (String, String, String, ReceiptId);

#[derive(Debug, Default)]
struct MemoryStatusStore {
    records: Mutex<BTreeMap<StatusKey, StatusView>>,
    log: AuditLog,
}

impl TrustedStatusStore for MemoryStatusStore {
    type AuthenticatedSubmissionScope = AuthenticatedSubmissionScope;
    type AuthenticatedStatusScope = AuthenticatedStatusScope;

    fn record(
        &self,
        scope: &Self::AuthenticatedSubmissionScope,
        state: ActionState,
        reason: Option<PublicReasonCode>,
        observed_at: TrustedInstant,
    ) -> Result<StatusView, TrustedFailure> {
        self.log
            .push(format!("status:{state:?}:{}", observed_at.unix_seconds()));
        let request_id = valid(RequestId::new(scope.request_id.clone()));
        let receipt_id = valid(ReceiptId::new(format!("receipt-{request_id}")));
        let key = (
            scope.tenant.clone(),
            scope.actor.clone(),
            scope.environment.clone(),
            receipt_id.clone(),
        );
        let value = StatusView::new(request_id, receipt_id, state, reason);
        lock(&self.records).insert(key, value.clone());
        Ok(value)
    }

    fn lookup(
        &self,
        scope: &Self::AuthenticatedStatusScope,
        lookup: &StatusLookup,
    ) -> Result<Option<StatusView>, TrustedFailure> {
        let key = (
            scope.tenant.clone(),
            scope.actor.clone(),
            scope.environment.clone(),
            lookup.receipt_id().clone(),
        );
        Ok(lock(&self.records).get(&key).cloned())
    }
}

type TestPipeline = TrustedPipeline<
    SequenceClock,
    MockAuthorizer,
    MockCommitter,
    MockDispatcher,
    MemoryStatusStore,
>;

type TestService = AccordLockService<RealProposalIngress, TestPipeline>;

fn signer() -> SigningIdentity {
    SigningIdentity::from_seed("agent-key-1", [7; 32])
}

fn registration(identity: &SigningIdentity) -> RegisteredIngressKey {
    RegisteredIngressKey {
        key_id: identity.key_id().to_owned(),
        public_key: identity.public_key_bytes(),
        tenant: "tenant-a".to_owned(),
        actor: "deploy-agent".to_owned(),
        allowed_audiences: BTreeSet::from([AUDIENCE.to_owned()]),
        not_before: NOW - 100,
        expires_at: NOW + 100,
        status: IngressKeyStatus::Active,
    }
}

fn build_service(
    fail_commit: bool,
    clock_values: [i64; 3],
) -> (TestService, SigningIdentity, AuditLog) {
    let signer = signer();
    let registration = registration(&signer);
    let root = valid(ActivatedIngressRegistry::compute_root(
        AUDIENCE,
        120,
        std::slice::from_ref(&registration),
    ));
    let registry = valid(ActivatedIngressRegistry::new(
        AuthorityDomainState {
            root,
            epoch: 1,
            activation_id: Uuid::from_u128(0x9001),
        },
        AUDIENCE,
        120,
        vec![registration],
    ));
    let authenticator = valid(IngressAuthenticator::new(
        registry,
        MemoryReplayGuard::default(),
    ));
    let log = AuditLog::default();
    let pipeline = TrustedPipeline::new(
        SequenceClock::new(clock_values, log.clone()),
        MockAuthorizer {
            allowed_image_repository: "registry.example/payments",
            log: log.clone(),
        },
        MockCommitter {
            configured_key: "trusted-kms-key",
            log: log.clone(),
            fail: fail_commit,
        },
        MockDispatcher { log: log.clone() },
        MemoryStatusStore {
            records: Mutex::new(BTreeMap::new()),
            log: log.clone(),
        },
    );
    let ingress = RealProposalIngress {
        authenticator,
        now: NOW,
        log: log.clone(),
    };
    (AccordLockService::new(ingress, pipeline), signer, log)
}

fn proposal(tenant: &str, actor: &str, image_repository: &str) -> AgentProposal {
    AgentProposal {
        schema_version: 1,
        request_id: Uuid::from_u128(1),
        tenant: tenant.to_owned(),
        actor: actor.to_owned(),
        template: DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: AUDIENCE.to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            image_repository: image_repository.to_owned(),
            image_digest: Digest32::from_bytes([1; 32]),
            cluster_identity: "clock-999-authority-evil".to_owned(),
            namespace: "payments".to_owned(),
            deployment: "api".to_owned(),
            deployment_uid: "deployment-uid".to_owned(),
            container: "api".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::from_bytes([2; 32]),
            resource_version: "42".to_owned(),
            prior_projection_hash: Digest32::from_bytes([3; 32]),
            prior_transaction_annotation: None,
            prior_authorization_annotation: None,
            prior_operation_hash_annotation: None,
        },
    }
}

fn signed_submission(
    identity: &SigningIdentity,
    nonce: u128,
    proposal: AgentProposal,
) -> SubmissionEnvelope {
    let request = valid(sign_ingress_request(
        IngressClaims {
            schema_version: INGRESS_SCHEMA_VERSION,
            audience: AUDIENCE.to_owned(),
            issued_at: NOW - 1,
            expires_at: NOW + 60,
            nonce: Uuid::from_u128(nonce),
            proposal,
        },
        identity,
    ));
    valid(SubmissionEnvelope::from_bytes(valid(serde_json::to_vec(
        &request,
    ))))
}

fn status_envelope(
    tenant: &str,
    actor: &str,
    environment: &str,
    lookup: StatusLookup,
) -> StatusEnvelope {
    let proof = format!(
        "status-v1|{tenant}|{actor}|{environment}|{}|{STATUS_MAC}",
        lookup.receipt_id()
    );
    valid(StatusEnvelope::from_bytes(lookup, proof.into_bytes()))
}

#[test]
fn signed_agent_proposal_is_the_only_intent_and_opaque_capability_reaches_workflow() {
    let (service, signer, log) = build_service(false, [100, 101, 102]);
    let envelope = signed_submission(
        &signer,
        1,
        proposal("tenant-a", "deploy-agent", "registry.example/payments"),
    );
    let debug = format!("{envelope:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("agent-key-1"));

    let receipt = service
        .submit(envelope)
        .unwrap_or_else(|error| unreachable!("submission succeeds: {error}"));

    assert_eq!(receipt.state(), ActionState::DispatchPending);
    assert_eq!(
        log.snapshot(),
        [
            "ingress:submission",
            "clock:100",
            "authorize:tenant-a:deploy-agent:registry.example/payments:100",
            "clock:101",
            "commit:key=trusted-kms-key:authority=trusted-authority-store:grant=server-selected-grant:evaluated=100:committed=101",
            "clock:102",
            "dispatch:key=trusted-kms-key:authority=trusted-authority-store:at=102",
            "status:DispatchPending:102",
        ]
    );
    let public_debug = format!("{receipt:?}");
    assert!(!public_debug.contains("trusted-kms-key"));
    assert!(!public_debug.contains("server-selected-grant"));
}

#[test]
fn malformed_tampered_or_spoofed_submission_stops_before_workflow() {
    let (service, _signer, log) = build_service(false, [100, 101, 102]);
    let malformed = valid(SubmissionEnvelope::from_bytes(b"not-json".to_vec()));
    assert_eq!(
        service.submit(malformed),
        Err(ServiceError::RequestRejected)
    );
    assert_eq!(log.snapshot(), ["ingress:submission"]);

    let (service, signer, log) = build_service(false, [100, 101, 102]);
    let valid_envelope = signed_submission(
        &signer,
        2,
        proposal("tenant-a", "deploy-agent", "registry.example/payments"),
    );
    let mut request: SignedIngressRequest =
        valid(serde_json::from_slice(valid_envelope.as_bytes()));
    request.claims.proposal.template.namespace = "kube-system".to_owned();
    let tampered = valid(SubmissionEnvelope::from_bytes(valid(serde_json::to_vec(
        &request,
    ))));
    assert_eq!(service.submit(tampered), Err(ServiceError::RequestRejected));
    assert_eq!(log.snapshot(), ["ingress:submission"]);

    let (service, signer, log) = build_service(false, [100, 101, 102]);
    let spoofed = signed_submission(
        &signer,
        3,
        proposal("tenant-a", "admin", "registry.example/payments"),
    );
    assert_eq!(service.submit(spoofed), Err(ServiceError::RequestRejected));
    assert_eq!(log.snapshot(), ["ingress:submission"]);
}

#[test]
fn ingress_replay_is_rejected_before_a_second_clock_or_effect() {
    let (service, signer, log) = build_service(false, [100, 101, 102]);
    let signed_request = valid(sign_ingress_request(
        IngressClaims {
            schema_version: INGRESS_SCHEMA_VERSION,
            audience: AUDIENCE.to_owned(),
            issued_at: NOW - 1,
            expires_at: NOW + 60,
            nonce: Uuid::from_u128(4),
            proposal: proposal("tenant-a", "deploy-agent", "registry.example/payments"),
        },
        &signer,
    ));
    let bytes = valid(serde_json::to_vec(&signed_request));
    service
        .submit(valid(SubmissionEnvelope::from_bytes(bytes.clone())))
        .unwrap_or_else(|error| unreachable!("first submission succeeds: {error}"));
    assert_eq!(
        service.submit(valid(SubmissionEnvelope::from_bytes(bytes))),
        Err(ServiceError::RequestRejected)
    );
    assert_eq!(
        log.snapshot()
            .iter()
            .filter(|event| event.starts_with("dispatch:"))
            .count(),
        1
    );
}

#[test]
fn proposal_can_request_an_action_but_cannot_supply_grant_or_signing_authority() {
    let (service, signer, log) = build_service(false, [100, 101, 102]);
    let denied = service
        .submit(signed_submission(
            &signer,
            5,
            proposal("tenant-a", "deploy-agent", "registry.example/forbidden"),
        ))
        .unwrap_or_else(|error| unreachable!("policy denial is a receipt: {error}"));

    assert_eq!(denied.state(), ActionState::Denied);
    assert_eq!(denied.reason(), Some(PublicReasonCode::PolicyDenied));
    let events = log.snapshot();
    assert!(!events.iter().any(|event| event.starts_with("commit:")));
    assert!(!events.iter().any(|event| event.starts_with("dispatch:")));
}

#[test]
fn envelope_bounds_fail_before_tcb_invocation() {
    let empty = required_error(SubmissionEnvelope::from_bytes(Vec::new()));
    assert_eq!(empty.violation(), EnvelopeViolation::Empty);
    let oversized = required_error(SubmissionEnvelope::from_bytes(vec![
        b'x';
        MAX_SIGNED_SUBMISSION_BYTES
            + 1
    ]));
    assert_eq!(oversized.violation(), EnvelopeViolation::TooLarge);

    let lookup = StatusLookup::new(valid(ReceiptId::new("receipt-1")));
    let oversized = required_error(StatusEnvelope::from_bytes(
        lookup,
        vec![b'x'; MAX_SIGNED_STATUS_BYTES + 1],
    ));
    assert_eq!(oversized.violation(), EnvelopeViolation::TooLarge);
}

#[test]
fn failed_sign_or_commit_never_reaches_dispatch() {
    let (service, signer, log) = build_service(true, [100, 101, 102]);
    let error = required_error(service.submit(signed_submission(
        &signer,
        6,
        proposal("tenant-a", "deploy-agent", "registry.example/payments"),
    )));
    assert_eq!(error, ServiceError::ControlUnavailable);
    let events = log.snapshot();
    assert!(events.iter().any(|event| event.starts_with("commit:")));
    assert!(!events.iter().any(|event| event.starts_with("dispatch:")));
}

#[test]
fn rollback_from_trusted_clock_fails_before_commit_or_dispatch() {
    let (service, signer, log) = build_service(false, [100, 99, 102]);
    let error = required_error(service.submit(signed_submission(
        &signer,
        7,
        proposal("tenant-a", "deploy-agent", "registry.example/payments"),
    )));
    assert_eq!(error, ServiceError::ControlUnavailable);
    assert_eq!(
        log.snapshot(),
        [
            "ingress:submission",
            "clock:100",
            "authorize:tenant-a:deploy-agent:registry.example/payments:100",
            "clock:99"
        ]
    );
}

#[test]
fn status_lookup_requires_exact_authenticated_scope_and_lookup_binding() {
    let (service, signer, _) = build_service(false, [100, 101, 102]);
    let receipt = service
        .submit(signed_submission(
            &signer,
            8,
            proposal("tenant-a", "deploy-agent", "registry.example/payments"),
        ))
        .unwrap_or_else(|error| unreachable!("submission succeeds: {error}"));

    let status = service
        .status(status_envelope(
            "tenant-a",
            "deploy-agent",
            "prod",
            receipt.status_lookup(),
        ))
        .unwrap_or_else(|error| unreachable!("exact owner can read status: {error}"));
    assert_eq!(status.state(), ActionState::DispatchPending);
    assert_eq!(status.receipt_id(), receipt.receipt_id());

    assert_eq!(
        service.status(status_envelope(
            "tenant-b",
            "other-agent",
            "prod",
            receipt.status_lookup(),
        )),
        Err(ServiceError::StatusNotFound)
    );
    assert_eq!(
        service.status(status_envelope(
            "tenant-a",
            "deploy-agent",
            "dev",
            receipt.status_lookup(),
        )),
        Err(ServiceError::StatusNotFound)
    );

    let original_lookup = receipt.status_lookup();
    let proof = format!(
        "status-v1|tenant-a|deploy-agent|prod|{}|{STATUS_MAC}",
        original_lookup.receipt_id()
    );
    let different_lookup = StatusLookup::new(valid(ReceiptId::new("receipt-other")));
    let misbound = valid(StatusEnvelope::from_bytes(
        different_lookup,
        proof.into_bytes(),
    ));
    assert_eq!(service.status(misbound), Err(ServiceError::RequestRejected));
}
