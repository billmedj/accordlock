//! State-backed `AccordLock` authorization issuance.
//!
//! This crate is the intended product path to the authorization signing key. The
//! repository does not yet isolate that key in an HSM or separate signer
//! service, so confinement remains an architectural premise. Public request
//! data selects only a proposal and grant identifier. Grant material,
//! current authority, executor audience, trusted time, dispatch policy, `AUTHORIZATION_ID`,
//! and transaction identifier are derived inside the trusted boundary.

use core::fmt;

use accordlock_protocol::{
    AgentProposal, CanonicalEncode, CoseVerifier, DecisionOutcome,
    EVALUATION_ATTESTATION_SCHEMA_VERSION, EXECUTION_AUTHORIZATION_DOMAIN,
    EXECUTION_AUTHORIZATION_SCHEMA_VERSION, ExecutionAuthorization, SignedAuthorization,
    SignedEvaluation, SigningIdentity, authorization_signer_root, canonical_hash,
    evaluator_verifier_root, sign_cose, verify_cose,
};
use accordlock_state::{
    ConsumeKey, ControlIssuanceCommitOutcome, ControlIssuanceWork, ControlPlaneState,
    ControlWorkFinalizationReason, IssuanceSnapshot, IssuedAuthorizationRecord, Scope, StateError,
    TransactionalState, compute_dispatch_deadline,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Successful durable issuance. The consume key is server-derived and exactly
/// identifies the state record committed before signed bytes are returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceSuccess {
    pub signed_authorization: SignedAuthorization,
    pub consume_key: ConsumeKey,
}

#[derive(Debug)]
struct PreparedIssuance {
    record: IssuedAuthorizationRecord,
    success: IssuanceSuccess,
}

/// State-backed authorization issuer. The signer is never accepted per request.
///
/// Durable ISSUE authority cannot be duplicated for two signer calls:
///
/// ```compile_fail
/// # use accordlock_state::ControlIssuanceWork;
/// fn clone_issue_authority(work: &ControlIssuanceWork) {
///     let _duplicate = (*work).clone();
/// }
/// ```
pub struct AuthorizationIssuer<S> {
    state: S,
    evaluator: CoseVerifier,
    authorization_signer: SigningIdentity,
}

impl<S> fmt::Debug for AuthorizationIssuer<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationIssuer")
            .field("evaluator_key_id", &self.evaluator.key_id())
            .field("authorization_signer", &"<isolated>")
            .field("state", &"<trusted-state>")
            .finish()
    }
}

impl<S: TransactionalState> AuthorizationIssuer<S> {
    #[must_use]
    pub fn new(state: S, evaluator: CoseVerifier, authorization_signer: SigningIdentity) -> Self {
        Self {
            state,
            evaluator,
            authorization_signer,
        }
    }

    /// Legacy synchronous harness issuance from explicit request references.
    ///
    /// Product workers must use [`Self::issue_or_recover`], whose only request
    /// authority is a non-forgeable [`ControlIssuanceWork`] and whose authorization
    /// record plus control-phase transition commit atomically. This method is
    /// retained while local v12 harnesses migrate.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid evaluation, a state-derived grant or
    /// profile mismatch, key-purpose reuse, an empty dispatch window, signing
    /// failure, or a failed final state recheck/record.
    pub fn issue(
        &self,
        proposal: &AgentProposal,
        signed_evaluation: &SignedEvaluation,
        scope: &Scope,
        grant_id: Uuid,
    ) -> Result<IssuanceSuccess, IssuanceError> {
        let snapshot = self.state.issuance_snapshot(scope, grant_id)?;
        let prepared =
            self.prepare_issuance(proposal, signed_evaluation, scope, grant_id, &snapshot)?;

        // Legacy-only second current-state check. The durable v13 method below
        // replaces this split write with one atomic record + phase link.
        self.state.record_issued_authorization(&prepared.record)?;
        Ok(prepared.success)
    }

    /// Deterministically issues or exactly recovers one durable control authorization.
    ///
    /// The work capability supplies the proposal, signed evaluation, selected
    /// grant, scope, decision lineage, and state-owned claim time. State first
    /// validates that exact active ISSUE claim and returns an opaque snapshot
    /// whose `issued_at` equals the claim time. After deterministic signing,
    /// state atomically records (or byte-exactly recovers) the authorization and moves
    /// the control queue to CONSUME. A commit-ambiguous result never releases
    /// signed bytes; the worker must reclaim durable work.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/wrong work, an invalid or substituted signed
    /// evaluation, current authority/grant/time failure, non-deterministic
    /// snapshot binding, signing failure, corrupt recovery, or an ambiguous
    /// atomic commit.
    pub fn issue_or_recover(
        &self,
        work: ControlIssuanceWork,
    ) -> Result<IssuanceSuccess, IssuanceError>
    where
        S: ControlPlaneState,
    {
        let snapshot = self.state.control_issuance_snapshot(&work)?;
        if snapshot.scope() != work.scope()
            || snapshot.issued_at() != work.lease().claimed_at()
            || snapshot.registration().grant.grant_id != work.selected_grant_id()
        {
            return Err(IssuanceError::ControlWorkMismatch);
        }

        let prepared = self.prepare_issuance(
            work.proposal(),
            work.signed_evaluation(),
            work.scope(),
            work.selected_grant_id(),
            &snapshot,
        )?;
        let submission_id = work.lease().submission_id();
        match self
            .state
            .record_and_link_control_issuance_or_recover(work, &prepared.record)?
        {
            ControlIssuanceCommitOutcome::Committed | ControlIssuanceCommitOutcome::Recovered => {
                Ok(prepared.success)
            }
            ControlIssuanceCommitOutcome::Finalized(receipt)
                if receipt.submission_id() == submission_id =>
            {
                Err(IssuanceError::ControlIssuanceFinalized {
                    submission_id,
                    reason: receipt.reason(),
                    finalized_at: receipt.finalized_at(),
                })
            }
            ControlIssuanceCommitOutcome::Finalized(_) => Err(IssuanceError::ControlWorkMismatch),
            ControlIssuanceCommitOutcome::OutcomeUnknown {
                submission_id: observed,
            } if observed == submission_id => {
                Err(IssuanceError::ControlIssuanceOutcomeUnknown { submission_id })
            }
            ControlIssuanceCommitOutcome::OutcomeUnknown { .. } => {
                Err(IssuanceError::ControlWorkMismatch)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_issuance(
        &self,
        proposal: &AgentProposal,
        signed_evaluation: &SignedEvaluation,
        scope: &Scope,
        grant_id: Uuid,
        snapshot: &IssuanceSnapshot,
    ) -> Result<PreparedIssuance, IssuanceError> {
        if self.evaluator.public_key_bytes() == self.authorization_signer.public_key_bytes() {
            return Err(IssuanceError::KeySeparationRequired);
        }

        let registration = snapshot.registration();
        let grant = &registration.grant;
        let issued_at = snapshot.issued_at();

        let evaluator_root =
            evaluator_verifier_root(self.evaluator.key_id(), self.evaluator.public_key_bytes())
                .map_err(|error| IssuanceError::EvaluationSignature(error.to_string()))?;
        if evaluator_root != registration.authority.kernel_configuration.root {
            return Err(IssuanceError::EvaluatorAuthorityMismatch);
        }

        let signer_public_key = self.authorization_signer.public_key_bytes();
        let signer_root =
            authorization_signer_root(self.authorization_signer.key_id(), signer_public_key)
                .map_err(|error| IssuanceError::AuthorizationSignature(error.to_string()))?;
        if signer_root != registration.authority.signer.root {
            return Err(IssuanceError::AuthorizationSignerAuthorityMismatch);
        }

        let signed_payload = verify_cose(
            &signed_evaluation.cose_sign1,
            accordlock_protocol::EVALUATION_DOMAIN,
            &self.evaluator,
        )
        .map_err(|error| IssuanceError::EvaluationSignature(error.to_string()))?;
        let expected_payload = signed_evaluation
            .attestation
            .canonical_bytes()
            .map_err(|error| IssuanceError::Canonical(error.to_string()))?;
        if signed_payload != expected_payload {
            return Err(IssuanceError::EvaluationPayloadMismatch);
        }
        let evaluation = &signed_evaluation.attestation;
        if evaluation.outcome != DecisionOutcome::Allow {
            return Err(IssuanceError::EvaluationDenied);
        }
        if evaluation.schema_version != EVALUATION_ATTESTATION_SCHEMA_VERSION
            || evaluation.reasons.as_slice() != [accordlock_protocol::ReasonCode::Allowed]
            || evaluation.policy_root != evaluation.authority.policy.root
            || evaluation.evaluated_at > issued_at
            || evaluation.consume_before <= evaluation.evaluated_at
            || evaluation.authority != registration.authority
            || evaluation.request_id != proposal.request_id
            || evaluation.tenant != proposal.tenant
            || evaluation.actor != proposal.actor
        {
            return Err(IssuanceError::EvaluationPayloadMismatch);
        }
        if snapshot.scope() != scope
            || scope.tenant != proposal.tenant
            || scope.environment != proposal.template.environment
            || canonical_hash(&proposal.template)
                .map_err(|error| IssuanceError::Canonical(error.to_string()))?
                != evaluation.template_hash
        {
            return Err(IssuanceError::EvaluationPayloadMismatch);
        }
        if !grant_allows(grant, proposal) {
            return Err(IssuanceError::GrantScopeMismatch);
        }

        let consume_before = evaluation.consume_before.min(grant.expires_at);
        compute_dispatch_deadline(
            issued_at,
            consume_before,
            &registration.dispatch_deadline_policy,
        )?;
        let authorization_id = derive_uuid(
            b"accordlock:v1:authorization-id",
            scope,
            proposal.request_id,
            evaluation.evaluation_nonce,
            grant_id,
        );
        let transaction_id = derive_uuid(
            b"accordlock:v1:authorization-transaction",
            scope,
            proposal.request_id,
            evaluation.evaluation_nonce,
            grant_id,
        );
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id,
            evaluation_nonce: evaluation.evaluation_nonce,
            request_id: proposal.request_id,
            tenant: proposal.tenant.clone(),
            holder: proposal.actor.clone(),
            audience: grant.audience.clone(),
            issued_at,
            not_before: issued_at,
            consume_before,
            dispatch_deadline_policy: registration.dispatch_deadline_policy.clone(),
            grant_id,
            template: proposal.template.clone(),
            template_hash: evaluation.template_hash,
            evidence_root: evaluation.evidence_root,
            principals: evaluation.principals.clone(),
            policy_root: evaluation.policy_root,
            authority: evaluation.authority.clone(),
        };
        let payload = authorization
            .canonical_bytes()
            .map_err(|error| IssuanceError::Canonical(error.to_string()))?;
        let cose_sign1 = sign_cose(
            &payload,
            EXECUTION_AUTHORIZATION_DOMAIN,
            &self.authorization_signer,
        )
        .map_err(|error| IssuanceError::AuthorizationSignature(error.to_string()))?;
        let signed_authorization = SignedAuthorization {
            authorization: authorization.clone(),
            cose_sign1,
        };
        let record = IssuedAuthorizationRecord::new(
            transaction_id,
            signed_authorization.clone(),
            self.authorization_signer.key_id().to_owned(),
            signer_public_key,
        )?;

        Ok(PreparedIssuance {
            record,
            success: IssuanceSuccess {
                signed_authorization,
                consume_key: ConsumeKey {
                    scope: scope.clone(),
                    transaction_id,
                    authorization_id,
                },
            },
        })
    }
}

fn grant_allows(grant: &accordlock_protocol::CapabilityGrant, proposal: &AgentProposal) -> bool {
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

fn derive_uuid(
    domain: &[u8],
    scope: &Scope,
    request_id: Uuid,
    evaluation_nonce: Uuid,
    grant_id: Uuid,
) -> Uuid {
    let mut hasher = Sha256::new();
    for component in [
        domain,
        scope.tenant.as_bytes(),
        scope.environment.as_bytes(),
    ] {
        hasher.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(component);
    }
    hasher.update(request_id.as_bytes());
    hasher.update(evaluation_nonce.as_bytes());
    hasher.update(grant_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122 variant with a deterministic version-8 application UUID.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("evaluation attestation is not allowed")]
    EvaluationDenied,
    #[error("evaluation signature is invalid: {0}")]
    EvaluationSignature(String),
    #[error("evaluation payload does not match trusted issuance state")]
    EvaluationPayloadMismatch,
    #[error("evaluation and authorization signing require distinct Ed25519 keys")]
    KeySeparationRequired,
    #[error("evaluation verifier does not match the active kernel-configuration authority root")]
    EvaluatorAuthorityMismatch,
    #[error("authorization signing key does not match the active signer authority root")]
    AuthorizationSignerAuthorityMismatch,
    #[error("current capability grant does not authorize this proposal")]
    GrantScopeMismatch,
    #[error("durable control issuance work does not match its state-owned snapshot or outcome")]
    ControlWorkMismatch,
    #[error("control issuance commit outcome is unknown for submission {submission_id}")]
    ControlIssuanceOutcomeUnknown { submission_id: Uuid },
    #[error(
        "control issuance finalized fail-closed for submission {submission_id} at {finalized_at}: {reason:?}"
    )]
    ControlIssuanceFinalized {
        submission_id: Uuid,
        reason: ControlWorkFinalizationReason,
        finalized_at: i64,
    },
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
    #[error("authorization signature failed: {0}")]
    AuthorizationSignature(String),
    #[error(transparent)]
    State(#[from] StateError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use accordlock_ingress::{
        ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
        IngressKeyStatus, IngressRecoveryProbe, MemoryReplayGuard, RegisteredIngressKey,
        StaticallyVerifiedIngressSubmission, sign_ingress_request,
    };
    use accordlock_kernel::{
        ExplicitAuthorizationVerificationContext, sign_evaluation, verify_authorization,
        verify_authorization_signature,
    };
    use accordlock_protocol::{
        AuthorityDomainState, AuthorityVector, CapabilityGrant, DeploymentTemplate, Digest32,
        DispatchDeadlinePolicy, EvaluationAttestation, ReasonCode, authorization_signer_root,
        evaluator_verifier_root,
    };
    use accordlock_state::{
        ClaimedControlWork, ControlPlaneState, ControlStatusCode, ControlSubmissionIntakeOutcome,
        ControlWorkClaimOutcome, ControlWorkClaimRequest, ControlWorkerRole, GrantRegistration,
        InMemoryStore, StateError, TransactionalState, TrustedClock, grant_revocation_root,
    };

    use super::*;

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl TrustedClock for TestClock {
        fn now_unix_seconds(&self) -> Result<i64, StateError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    struct Fixture {
        store: InMemoryStore,
        clock: Arc<TestClock>,
        scope: Scope,
        proposal: AgentProposal,
        authority: AuthorityVector,
        grant: CapabilityGrant,
        evaluator: SigningIdentity,
        authorization_signer: SigningIdentity,
        ingress_signer: SigningIdentity,
    }

    impl Fixture {
        fn new(maximum_uses: u32) -> Self {
            let clock = Arc::new(TestClock::new(100));
            let store = InMemoryStore::with_clock(clock.clone());
            let scope = Scope::new("acme", "prod").unwrap();
            let template = template("accordlock-executor:prod");
            let proposal = AgentProposal {
                schema_version: 1,
                request_id: Uuid::from_u128(0x101),
                tenant: scope.tenant.clone(),
                actor: "workload:release".to_owned(),
                template: template.clone(),
            };
            let grant = CapabilityGrant {
                grant_id: Uuid::from_u128(0x201),
                holder: proposal.actor.clone(),
                tenant: proposal.tenant.clone(),
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
                maximum_uses,
            };
            let evaluator = SigningIdentity::from_seed("issuer-test-evaluator", [41; 32]);
            let authorization_signer =
                SigningIdentity::from_seed("issuer-test-authorization", [42; 32]);
            let ingress_signer = SigningIdentity::from_seed("issuer-test-ingress", [43; 32]);
            let mut authority = authority();
            authority.grant_registry.root = canonical_hash(&grant).unwrap();
            authority.signer.root = authorization_signer_root(
                authorization_signer.key_id(),
                authorization_signer.public_key_bytes(),
            )
            .unwrap();
            authority.kernel_configuration.root =
                evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes()).unwrap();
            authority.principal_registry.root = ActivatedIngressRegistry::compute_root(
                &proposal.template.audience,
                120,
                &[ingress_registration(&proposal, &ingress_signer)],
            )
            .unwrap();
            let registration = GrantRegistration {
                environment: scope.environment.clone(),
                grant: grant.clone(),
                authority: authority.clone(),
                dispatch_deadline_policy: DispatchDeadlinePolicy {
                    max_dispatch_delay_seconds: 30,
                    profile_hard_cap: 200,
                    immutable_dependency_expiries: vec![190],
                },
            };
            store
                .compare_and_activate_authority(&scope, None, &authority)
                .unwrap();
            store.register_grant(&registration).unwrap();
            Self {
                store,
                clock,
                scope,
                proposal,
                authority,
                grant,
                evaluator,
                authorization_signer,
                ingress_signer,
            }
        }

        fn signed_evaluation(&self, proposal: &AgentProposal, nonce: u128) -> SignedEvaluation {
            self.signed_evaluation_at(proposal, Uuid::from_u128(nonce), 99)
        }

        fn signed_evaluation_at(
            &self,
            proposal: &AgentProposal,
            nonce: Uuid,
            evaluated_at: i64,
        ) -> SignedEvaluation {
            let attestation = EvaluationAttestation {
                schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
                request_id: proposal.request_id,
                evaluation_nonce: nonce,
                tenant: proposal.tenant.clone(),
                actor: proposal.actor.clone(),
                evaluated_at,
                outcome: DecisionOutcome::Allow,
                reasons: vec![ReasonCode::Allowed],
                template_hash: canonical_hash(&proposal.template).unwrap(),
                evidence_root: digest("evidence"),
                principals: vec!["principal:review".to_owned()],
                policy_root: self.authority.policy.root,
                authority: self.authority.clone(),
                consume_before: 180,
            };
            sign_evaluation(attestation, &self.evaluator).unwrap()
        }

        fn verified_submission(&self, nonce: u128) -> StaticallyVerifiedIngressSubmission {
            let registration = ingress_registration(&self.proposal, &self.ingress_signer);
            let registry = ActivatedIngressRegistry::new(
                self.authority.principal_registry.clone(),
                self.proposal.template.audience.clone(),
                120,
                vec![registration],
            )
            .unwrap();
            let authenticator =
                IngressAuthenticator::new(registry, MemoryReplayGuard::default()).unwrap();
            let claims = IngressClaims {
                schema_version: INGRESS_SCHEMA_VERSION,
                audience: self.proposal.template.audience.clone(),
                issued_at: 99,
                expires_at: 180,
                nonce: Uuid::from_u128(nonce),
                proposal: self.proposal.clone(),
            };
            let wire =
                serde_json::to_vec(&sign_ingress_request(claims, &self.ingress_signer).unwrap())
                    .unwrap();
            let probe = IngressRecoveryProbe::parse_bytes(&wire).unwrap();
            authenticator.verify_durable_static(probe).unwrap()
        }

        fn issue_work(&self, nonce: u128) -> (ControlIssuanceWork, Uuid) {
            let intake = self
                .store
                .accept_control_submission_or_recover(self.verified_submission(nonce))
                .unwrap();
            let receipt = match intake {
                ControlSubmissionIntakeOutcome::Fresh(receipt) => receipt,
                other => panic!("expected fresh intake, got {other:?}"),
            };
            let evaluate_request = ControlWorkClaimRequest::new(
                "evaluator-1",
                ControlWorkerRole::Evaluator,
                Uuid::from_u128(nonce + 1),
            )
            .unwrap();
            let evaluation_work = match self
                .store
                .claim_next_control_work_or_recover(&evaluate_request)
                .unwrap()
            {
                ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
                other => panic!("expected EVALUATE work, got {other:?}"),
            };
            let signed_evaluation = self.signed_evaluation_at(
                evaluation_work.proposal(),
                evaluation_work.evaluation_nonce(),
                evaluation_work.lease().claimed_at(),
            );
            let decision = self
                .store
                .record_control_evaluation(
                    evaluation_work,
                    &signed_evaluation,
                    &self.evaluator.verifier(),
                )
                .unwrap();
            assert_eq!(decision.selected_grant_id(), Some(self.grant.grant_id));

            let issue_request = ControlWorkClaimRequest::new(
                "issuer-1",
                ControlWorkerRole::Issuer,
                Uuid::from_u128(nonce + 2),
            )
            .unwrap();
            let issue_work = match self
                .store
                .claim_next_control_work_or_recover(&issue_request)
                .unwrap()
            {
                ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
                other => panic!("expected ISSUE work, got {other:?}"),
            };
            (issue_work, receipt.receipt_id())
        }

        fn issuer(self) -> AuthorizationIssuer<InMemoryStore> {
            AuthorizationIssuer::new(
                self.store,
                self.evaluator.verifier(),
                self.authorization_signer,
            )
        }
    }

    fn ingress_registration(
        proposal: &AgentProposal,
        signer: &SigningIdentity,
    ) -> RegisteredIngressKey {
        RegisteredIngressKey {
            key_id: signer.key_id().to_owned(),
            public_key: signer.public_key_bytes(),
            tenant: proposal.tenant.clone(),
            actor: proposal.actor.clone(),
            allowed_audiences: BTreeSet::from([proposal.template.audience.clone()]),
            not_before: 50,
            expires_at: 300,
            status: IngressKeyStatus::Active,
        }
    }

    fn digest(label: &str) -> Digest32 {
        Digest32::sha256(label.as_bytes())
    }

    fn domain(label: &str) -> AuthorityDomainState {
        AuthorityDomainState {
            root: digest(label),
            epoch: 1,
            activation_id: Uuid::new_v4(),
        }
    }

    fn authority() -> AuthorityVector {
        AuthorityVector {
            policy: domain("policy"),
            registry: domain("registry"),
            revocation: domain("revocation"),
            connector: domain("connector"),
            resource: domain("resource"),
            signer: domain("signer"),
            mediation: domain("mediation"),
            grant_registry: domain("grant-registry"),
            office_act_registry: domain("office"),
            principal_registry: domain("principal"),
            workload_build_allowlist: domain("build"),
            kernel_configuration: domain("kernel"),
        }
    }

    fn template(audience: &str) -> DeploymentTemplate {
        DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: audience.to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1111111111111111111111111111111111111111".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            image_digest: digest("new-image"),
            cluster_identity: "cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: "deployment-uid".to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: digest("old-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: digest("projection"),
            prior_transaction_annotation: None,
            prior_authorization_annotation: None,
            prior_operation_hash_annotation: None,
        }
    }

    #[test]
    fn issuance_derives_and_records_every_security_sensitive_field() {
        let fixture = Fixture::new(2);
        let signed_evaluation = fixture.signed_evaluation(&fixture.proposal, 0x301);
        let store = fixture.store.clone();
        let scope = fixture.scope.clone();
        let proposal = fixture.proposal.clone();
        let grant_id = fixture.grant.grant_id;
        let authority = fixture.authority.clone();
        let authorization_verifier = fixture.authorization_signer.verifier();
        let issued = fixture
            .issuer()
            .issue(&proposal, &signed_evaluation, &scope, grant_id)
            .unwrap();

        let historical_verification = ExplicitAuthorizationVerificationContext::new(
            100,
            "accordlock-executor:prod",
            &authority,
        )
        .unwrap();
        verify_authorization(
            &issued.signed_authorization,
            &authorization_verifier,
            &historical_verification,
        )
        .unwrap();
        assert_eq!(issued.signed_authorization.authorization.schema_version, 2);
        assert_eq!(
            issued.signed_authorization.authorization.audience,
            "accordlock-executor:prod"
        );
        assert_eq!(
            issued
                .signed_authorization
                .authorization
                .dispatch_deadline_policy,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 30,
                profile_hard_cap: 200,
                immutable_dependency_expiries: vec![190],
            }
        );
        let consumed = store.consume(&issued.consume_key).unwrap();
        assert_eq!(
            consumed.issued().signed_authorization,
            issued.signed_authorization
        );
        assert_eq!(consumed.receipt().dispatch_deadline, 130);
    }

    #[test]
    fn durable_issue_uses_claim_time_and_atomically_advances_to_consume() {
        let fixture = Fixture::new(2);
        let (work, receipt_id) = fixture.issue_work(0x4100);
        let claimed_at = work.lease().claimed_at();
        let store = fixture.store.clone();
        let authorization_issuer = AuthorizationIssuer::new(
            store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );

        let issuance = authorization_issuer.issue_or_recover(work).unwrap();
        assert_eq!(
            issuance.signed_authorization.authorization.issued_at,
            claimed_at
        );
        assert_eq!(
            issuance.signed_authorization.authorization.not_before,
            claimed_at
        );
        assert_eq!(
            store
                .control_status(&fixture.scope, receipt_id)
                .unwrap()
                .status(),
            ControlStatusCode::AuthorizationIssued
        );

        let consume_request = ControlWorkClaimRequest::new(
            "consumer-1",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x4103),
        )
        .unwrap();
        let consume_work = match store
            .claim_next_control_work_or_recover(&consume_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            other => panic!("expected CONSUME work, got {other:?}"),
        };
        assert_eq!(consume_work.consume_key(), &issuance.consume_key);
    }

    #[test]
    fn durable_issue_reclaims_after_precommit_crash_without_signing_a_variant() {
        let fixture = Fixture::new(2);
        let (work, receipt_id) = fixture.issue_work(0x4200);
        let store = fixture.store.clone();
        let issuer = AuthorizationIssuer::new(
            store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );
        let snapshot = store.control_issuance_snapshot(&work).unwrap();
        let prepared = issuer
            .prepare_issuance(
                work.proposal(),
                work.signed_evaluation(),
                work.scope(),
                work.selected_grant_id(),
                &snapshot,
            )
            .unwrap();

        let expected = prepared.success;
        // The process signed deterministically but crashed before calling the
        // atomic state boundary. Dropping its capability and reclaiming with
        // the same worker/claim identity reconstructs the exact ISSUE work.
        drop(work);
        let recovery_request = ControlWorkClaimRequest::new(
            "issuer-1",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(0x4202),
        )
        .unwrap();
        let recovered_work = match store
            .claim_next_control_work_or_recover(&recovery_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Recovered(ClaimedControlWork::Issue(work)) => work,
            other => panic!("expected recovered ISSUE work, got {other:?}"),
        };
        let recovered = issuer.issue_or_recover(recovered_work).unwrap();

        assert_eq!(recovered, expected);
        assert_eq!(
            store
                .control_status(&fixture.scope, receipt_id)
                .unwrap()
                .status(),
            ControlStatusCode::AuthorizationIssued
        );
    }

    #[test]
    fn expired_durable_issue_work_cannot_release_signed_bytes_or_a_authorization() {
        let fixture = Fixture::new(2);
        let (work, _) = fixture.issue_work(0x4300);
        let lease_until = work.lease().lease_until();
        let evaluation_nonce = work.signed_evaluation().attestation.evaluation_nonce;
        let request_id = work.proposal().request_id;
        let grant_id = work.selected_grant_id();
        let expected_key = ConsumeKey {
            scope: work.scope().clone(),
            transaction_id: derive_uuid(
                b"accordlock:v1:authorization-transaction",
                work.scope(),
                request_id,
                evaluation_nonce,
                grant_id,
            ),
            authorization_id: derive_uuid(
                b"accordlock:v1:authorization-id",
                work.scope(),
                request_id,
                evaluation_nonce,
                grant_id,
            ),
        };
        fixture.clock.set(lease_until);
        let store = fixture.store.clone();
        let issuer = AuthorizationIssuer::new(
            store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );

        assert!(matches!(
            issuer.issue_or_recover(work),
            Err(IssuanceError::State(StateError::ControlWorkLeaseExpired {
                observed,
                lease_until: expired,
            })) if observed == lease_until && expired == lease_until
        ));
        assert!(matches!(
            store.consume(&expected_key),
            Err(StateError::AuthorizationNotFound)
        ));
    }

    #[test]
    fn durable_issue_work_from_another_state_instance_fails_closed() {
        let source = Fixture::new(2);
        let (foreign_work, _) = source.issue_work(0x4400);
        let target = Fixture::new(2);
        let target_store = target.store.clone();
        let issuer = AuthorizationIssuer::new(
            target_store,
            target.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );

        assert!(matches!(
            issuer.issue_or_recover(foreign_work),
            Err(IssuanceError::State(StateError::ControlWorkMismatch))
        ));
    }

    #[test]
    fn legacy_v1_evaluation_domain_is_rejected_before_issuance() {
        let fixture = Fixture::new(1);
        let mut legacy = fixture.signed_evaluation(&fixture.proposal, 0x302);
        legacy.cose_sign1 = sign_cose(
            &legacy.attestation.canonical_bytes().unwrap(),
            "accordlock:v1:evaluation-attestation",
            &fixture.evaluator,
        )
        .unwrap();
        let scope = fixture.scope.clone();
        let proposal = fixture.proposal.clone();
        let grant_id = fixture.grant.grant_id;

        assert!(matches!(
            fixture.issuer().issue(&proposal, &legacy, &scope, grant_id),
            Err(IssuanceError::EvaluationSignature(_))
        ));
    }

    #[test]
    fn legacy_v1_evaluation_schema_is_rejected_before_issuance() {
        let fixture = Fixture::new(1);
        let mut attestation = fixture
            .signed_evaluation(&fixture.proposal, 0x303)
            .attestation;
        attestation.schema_version = 1;
        let legacy = sign_evaluation(attestation, &fixture.evaluator).unwrap();
        let scope = fixture.scope.clone();
        let proposal = fixture.proposal.clone();
        let grant_id = fixture.grant.grant_id;

        assert!(matches!(
            fixture.issuer().issue(&proposal, &legacy, &scope, grant_id),
            Err(IssuanceError::EvaluationPayloadMismatch)
        ));
    }

    #[test]
    fn issuance_after_evaluation_bound_refuses_without_recording_a_authorization() {
        let fixture = Fixture::new(1);
        let mut attestation = fixture
            .signed_evaluation(&fixture.proposal, 0x30b)
            .attestation;
        // In an integrated evaluation this is the signed ingress-expiry bound.
        attestation.consume_before = 120;
        let signed_evaluation = sign_evaluation(attestation, &fixture.evaluator).unwrap();
        fixture.clock.set(121);

        let authorization_issuer = AuthorizationIssuer::new(
            fixture.store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );
        assert!(matches!(
            authorization_issuer.issue(
                &fixture.proposal,
                &signed_evaluation,
                &fixture.scope,
                fixture.grant.grant_id,
            ),
            Err(IssuanceError::State(StateError::AuthorizationExpired {
                observed: 121,
                consume_before: 120,
            }))
        ));

        // The deadline check precedes both COSE signing and the state write.
        // Absence under the exact deterministic key proves no record escaped.
        let key = ConsumeKey {
            scope: fixture.scope.clone(),
            transaction_id: derive_uuid(
                b"accordlock:v1:authorization-transaction",
                &fixture.scope,
                fixture.proposal.request_id,
                signed_evaluation.attestation.evaluation_nonce,
                fixture.grant.grant_id,
            ),
            authorization_id: derive_uuid(
                b"accordlock:v1:authorization-id",
                &fixture.scope,
                fixture.proposal.request_id,
                signed_evaluation.attestation.evaluation_nonce,
                fixture.grant.grant_id,
            ),
        };
        assert!(matches!(
            fixture.store.consume(&key),
            Err(StateError::AuthorizationNotFound)
        ));
    }

    #[test]
    fn fabricated_grant_and_audience_are_rejected() {
        let fixture = Fixture::new(2);
        let unknown = fixture.signed_evaluation(&fixture.proposal, 0x302);
        let authorization_issuer = AuthorizationIssuer::new(
            fixture.store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );
        assert!(matches!(
            authorization_issuer.issue(
                &fixture.proposal,
                &unknown,
                &fixture.scope,
                Uuid::from_u128(0xdead)
            ),
            Err(IssuanceError::State(StateError::GrantNotFound))
        ));

        let mut forged_proposal = fixture.proposal.clone();
        forged_proposal.request_id = Uuid::from_u128(0x102);
        forged_proposal.template.audience = "attacker-selected-executor".to_owned();
        let forged_evaluation = fixture.signed_evaluation(&forged_proposal, 0x303);
        assert!(matches!(
            authorization_issuer.issue(
                &forged_proposal,
                &forged_evaluation,
                &fixture.scope,
                fixture.grant.grant_id
            ),
            Err(IssuanceError::GrantScopeMismatch)
        ));
    }

    #[test]
    fn signer_root_mismatch_is_rejected_before_authorization_release() {
        let fixture = Fixture::new(1);
        let evaluation = fixture.signed_evaluation(&fixture.proposal, 0x304);
        let authorization_issuer = AuthorizationIssuer::new(
            fixture.store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("wrong-authorization", [43; 32]),
        );
        assert!(matches!(
            authorization_issuer.issue(
                &fixture.proposal,
                &evaluation,
                &fixture.scope,
                fixture.grant.grant_id
            ),
            Err(IssuanceError::AuthorizationSignerAuthorityMismatch)
        ));
    }

    #[test]
    fn evaluator_from_another_trust_domain_cannot_use_the_authorization_signer_as_a_deputy() {
        let fixture = Fixture::new(1);
        let wrong_evaluator = SigningIdentity::from_seed("tenant-b-evaluator", [44; 32]);
        let attestation = fixture
            .signed_evaluation(&fixture.proposal, 0x30a)
            .attestation;
        let wrong_evaluation = sign_evaluation(attestation, &wrong_evaluator).unwrap();
        let authorization_issuer = AuthorizationIssuer::new(
            fixture.store.clone(),
            wrong_evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );

        assert!(matches!(
            authorization_issuer.issue(
                &fixture.proposal,
                &wrong_evaluation,
                &fixture.scope,
                fixture.grant.grant_id
            ),
            Err(IssuanceError::EvaluatorAuthorityMismatch)
        ));
    }

    #[test]
    fn stale_authority_and_revocation_block_issue_and_consume() {
        let fixture = Fixture::new(2);
        let first_evaluation = fixture.signed_evaluation(&fixture.proposal, 0x305);
        let authorization_issuer = AuthorizationIssuer::new(
            fixture.store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );
        let issuance = authorization_issuer
            .issue(
                &fixture.proposal,
                &first_evaluation,
                &fixture.scope,
                fixture.grant.grant_id,
            )
            .unwrap();

        let mut revoked_authority = fixture.authority.clone();
        revoked_authority.revocation.epoch += 1;
        revoked_authority.revocation.activation_id = Uuid::from_u128(0x999);
        revoked_authority.revocation.root = grant_revocation_root(fixture.grant.grant_id);
        fixture
            .store
            .revoke_grant(
                &fixture.scope,
                fixture.grant.grant_id,
                &fixture.authority,
                &revoked_authority,
            )
            .unwrap();

        assert!(matches!(
            authorization_issuer.issue(
                &fixture.proposal,
                &first_evaluation,
                &fixture.scope,
                fixture.grant.grant_id
            ),
            Err(IssuanceError::State(
                StateError::AuthorityMismatch | StateError::GrantRevoked
            ))
        ));
        assert!(matches!(
            fixture.store.consume(&issuance.consume_key),
            Err(StateError::AuthorityMismatch | StateError::GrantRevoked)
        ));
    }

    #[test]
    fn exhausted_and_expired_grants_cannot_issue() {
        let fixture = Fixture::new(1);
        let first = fixture.signed_evaluation(&fixture.proposal, 0x306);
        let authorization_issuer = AuthorizationIssuer::new(
            fixture.store.clone(),
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        );
        let issuance = authorization_issuer
            .issue(
                &fixture.proposal,
                &first,
                &fixture.scope,
                fixture.grant.grant_id,
            )
            .unwrap();
        fixture.store.consume(&issuance.consume_key).unwrap();

        let mut second_proposal = fixture.proposal.clone();
        second_proposal.request_id = Uuid::from_u128(0x103);
        let second = fixture.signed_evaluation(&second_proposal, 0x307);
        assert!(matches!(
            authorization_issuer.issue(
                &second_proposal,
                &second,
                &fixture.scope,
                fixture.grant.grant_id
            ),
            Err(IssuanceError::State(StateError::GrantExhausted))
        ));

        fixture.clock.set(300);
        assert!(matches!(
            authorization_issuer.issue(
                &second_proposal,
                &second,
                &fixture.scope,
                fixture.grant.grant_id
            ),
            Err(IssuanceError::State(StateError::GrantExpired { .. }))
        ));
    }

    #[test]
    fn signed_deadline_tamper_and_v1_domain_are_rejected() {
        let fixture = Fixture::new(1);
        let evaluation = fixture.signed_evaluation(&fixture.proposal, 0x308);
        let verifier = fixture.authorization_signer.verifier();
        let proposal = fixture.proposal.clone();
        let scope = fixture.scope.clone();
        let grant_id = fixture.grant.grant_id;
        let mut issued = fixture
            .issuer()
            .issue(&proposal, &evaluation, &scope, grant_id)
            .unwrap();
        issued
            .signed_authorization
            .authorization
            .dispatch_deadline_policy
            .profile_hard_cap += 1;
        assert!(verify_authorization_signature(&issued.signed_authorization, &verifier).is_err());

        let legacy_cose = sign_cose(
            &issued
                .signed_authorization
                .authorization
                .canonical_bytes()
                .unwrap(),
            "accordlock:v1:execution-authorization",
            &SigningIdentity::from_seed("issuer-test-authorization", [42; 32]),
        )
        .unwrap();
        issued.signed_authorization.cose_sign1 = legacy_cose;
        assert!(verify_authorization_signature(&issued.signed_authorization, &verifier).is_err());
    }

    #[test]
    fn deterministic_ids_bind_full_scope_and_request() {
        let request = Uuid::from_u128(1);
        let nonce = Uuid::from_u128(2);
        let grant = Uuid::from_u128(3);
        let base = derive_uuid(
            b"accordlock:v1:test-id",
            &Scope::new("acme", "prod").unwrap(),
            request,
            nonce,
            grant,
        );
        assert_ne!(
            base,
            derive_uuid(
                b"accordlock:v1:test-id",
                &Scope::new("other", "prod").unwrap(),
                request,
                nonce,
                grant,
            )
        );
        assert_ne!(
            base,
            derive_uuid(
                b"accordlock:v1:test-id",
                &Scope::new("acme", "stage").unwrap(),
                request,
                nonce,
                grant,
            )
        );
        assert_ne!(
            base,
            derive_uuid(
                b"accordlock:v1:test-id",
                &Scope::new("acme", "prod").unwrap(),
                Uuid::from_u128(4),
                nonce,
                grant,
            )
        );
    }
}
