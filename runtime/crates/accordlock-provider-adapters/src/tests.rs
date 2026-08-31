use std::sync::Arc;

use accordlock_connectors::{
    ArtifactLookupId, ArtifactSource, BuildSource, ReviewSource, TargetSource,
};
use accordlock_protocol::Digest32;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::*;

const REQUEST_ID: Uuid = Uuid::from_bytes([0x11; 16]);
const EVIDENCE_ID: Uuid = Uuid::from_bytes([0x22; 16]);
const DEPLOYMENT_UID: Uuid = Uuid::from_bytes([0x33; 16]);
const NOW: i64 = 1_900_000_000;

#[derive(Debug)]
struct GitHubFixtureTransport {
    expected: GitHubReadRequest,
    body: Vec<u8>,
}

impl GitHubAuthenticatedTransport for GitHubFixtureTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "fixture-github-v1",
            "github-app:acme",
            "fixture:github",
            Digest32::from_bytes([0xa1; 32]),
        )
    }

    fn read(
        &self,
        request: &GitHubReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        if request != &self.expected {
            return Err(TransportFailure::Route);
        }
        Ok(AuthenticatedJsonResponse::new(
            200,
            ResponseMediaType::Json,
            self.body.clone(),
        ))
    }
}

#[derive(Debug)]
struct EcrFixtureTransport {
    expected: EcrReadRequest,
    body: Vec<u8>,
}

impl EcrAuthenticatedTransport for EcrFixtureTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "fixture-aws-sigv4-v1",
            "arn:aws:iam::111122223333:role/accordlock-runner",
            "fixture:aws",
            Digest32::from_bytes([0xa2; 32]),
        )
    }

    fn read(
        &self,
        request: &EcrReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        if request != &self.expected {
            return Err(TransportFailure::Route);
        }
        Ok(AuthenticatedJsonResponse::new(
            200,
            ResponseMediaType::Json,
            self.body.clone(),
        ))
    }
}

#[derive(Debug)]
struct KubernetesFixtureTransport {
    expected: KubernetesReadRequest,
    body: Vec<u8>,
}

impl KubernetesAuthenticatedTransport for KubernetesFixtureTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "fixture-eks-auth-v1",
            "arn:aws:iam::111122223333:role/accordlock-runner",
            "fixture:aws",
            Digest32::from_bytes([0xa3; 32]),
        )
    }

    fn read(
        &self,
        request: &KubernetesReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        if request != &self.expected {
            return Err(TransportFailure::Route);
        }
        Ok(AuthenticatedJsonResponse::new(
            200,
            ResponseMediaType::Json,
            self.body.clone(),
        ))
    }
}

fn github_config(maximum: usize) -> Result<GitHubAdapterConfig, AdapterConfigError> {
    GitHubAdapterConfig::new(
        HttpsEndpoint::new("api.github.example", "/api/v3")?,
        "acme",
        "payments",
        ".github/workflows/release.yml@refs/heads/main",
        maximum,
    )
}

fn review_request() -> GitHubReadRequest {
    GitHubReadRequest {
        method: ReadMethod::Get,
        authority: "api.github.example".to_owned(),
        path: "/api/v3/repos/acme/payments/pulls/17/accordlock-review-decision".to_owned(),
        redirect_policy: RedirectPolicy::Deny,
        maximum_response_bytes: 16_384,
        operation: GitHubReadOperation::PullReviewDecision,
    }
}

fn build_request() -> GitHubReadRequest {
    GitHubReadRequest {
        method: ReadMethod::Get,
        authority: "api.github.example".to_owned(),
        path: "/api/v3/repos/acme/payments/actions/runs/83/accordlock-build-attestation".to_owned(),
        redirect_policy: RedirectPolicy::Deny,
        maximum_response_bytes: 16_384,
        operation: GitHubReadOperation::ActionsBuildAttestation,
    }
}

fn review_body() -> Value {
    json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "evidence_id": EVIDENCE_ID,
        "observed_at": NOW,
        "source_sequence": 91,
        "repository": "acme/payments",
        "pull_number": 17,
        "commit_sha": "a".repeat(40),
        "approved": true
    })
}

fn build_body() -> Value {
    json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "evidence_id": EVIDENCE_ID,
        "observed_at": NOW,
        "source_sequence": 92,
        "repository": "acme/payments",
        "workflow_ref": ".github/workflows/release.yml@refs/heads/main",
        "run_id": 83,
        "commit_sha": "a".repeat(40),
        "succeeded": true,
        "input_manifest_root": Digest32::from_bytes([0x44; 32]),
        "completeness_profile": "HERMETIC_INPUTS_V1",
        "output_digest": Digest32::from_bytes([0x55; 32])
    })
}

fn ecr_config(maximum: usize) -> Result<EcrAdapterConfig, AdapterConfigError> {
    EcrAdapterConfig::new(
        HttpsEndpoint::new("api.ecr.us-east-1.amazonaws.com", "/")?,
        "111122223333",
        "us-east-1",
        "acme/payments",
        "acme/payments",
        maximum,
    )
}

fn ecr_request(digest: Digest32) -> EcrReadRequest {
    EcrReadRequest {
        method: ReadMethod::Post,
        authority: "api.ecr.us-east-1.amazonaws.com".to_owned(),
        path: "/".to_owned(),
        redirect_policy: RedirectPolicy::Deny,
        maximum_response_bytes: 16_384,
        sigv4_service: "ecr".to_owned(),
        region: "us-east-1".to_owned(),
        x_amz_target: "AmazonEC2ContainerRegistry_V20150921.BatchGetImage".to_owned(),
        registry_id: "111122223333".to_owned(),
        repository_name: "acme/payments".to_owned(),
        image_digest: digest,
    }
}

fn ecr_body(digest: Digest32) -> Value {
    json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "evidence_id": EVIDENCE_ID,
        "observed_at": NOW,
        "source_sequence": 93,
        "registry_id": "111122223333",
        "region": "us-east-1",
        "repository_name": "acme/payments",
        "image_digest": digest,
        "source_repository": "acme/payments",
        "commit_sha": "a".repeat(40),
        "source_run_id": 83,
        "signature_valid": true,
        "quarantined": false
    })
}

fn kubernetes_config(maximum: usize) -> Result<KubernetesAdapterConfig, AdapterConfigError> {
    KubernetesAdapterConfig::new(
        HttpsEndpoint::new("cluster.example", "/")?,
        "eks://111122223333/us-east-1/prod",
        "payments-prod",
        "payments",
        "api",
        "acme/payments",
        "111122223333.dkr.ecr.us-east-1.amazonaws.com/acme/payments",
        maximum,
    )
}

fn kubernetes_request() -> KubernetesReadRequest {
    KubernetesReadRequest {
        method: ReadMethod::Get,
        authority: "cluster.example".to_owned(),
        path: "/apis/apps/v1/namespaces/payments-prod/deployments/payments".to_owned(),
        redirect_policy: RedirectPolicy::Deny,
        maximum_response_bytes: 16_384,
        api_group: "apps".to_owned(),
        api_version: "v1".to_owned(),
        resource: "deployments".to_owned(),
        namespace: "payments-prod".to_owned(),
        name: "payments".to_owned(),
    }
}

fn kubernetes_body() -> Value {
    json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "evidence_id": EVIDENCE_ID,
        "observed_at": NOW,
        "source_sequence": 94,
        "cluster_identity": "eks://111122223333/us-east-1/prod",
        "namespace": "payments-prod",
        "deployment": "payments",
        "deployment_uid": DEPLOYMENT_UID,
        "resource_version": "83191",
        "container": "api",
        "source_repository": "acme/payments",
        "commit_sha": "a".repeat(40),
        "image_repository": "111122223333.dkr.ecr.us-east-1.amazonaws.com/acme/payments",
        "desired_image_digest": Digest32::from_bytes([0x55; 32]),
        "current_image": Digest32::from_bytes([0x66; 32]),
        "projection_hash": Digest32::from_bytes([0x77; 32])
    })
}

#[test]
fn maps_all_four_sources_with_exact_request_binding() -> Result<(), Box<dyn std::error::Error>> {
    let review_adapter = GitHubSourceAdapter::new(
        github_config(16_384)?,
        Arc::new(GitHubFixtureTransport {
            expected: review_request(),
            body: serde_json::to_vec(&review_body())?,
        }),
    )?;
    let review = ReviewSource::fetch(&review_adapter, &github_review_lookup(REQUEST_ID, 17)?)?;
    assert_eq!(review.meta.request_id, REQUEST_ID);
    assert_eq!(review.repository, "acme/payments");
    assert!(review.approved);

    let build_adapter = GitHubSourceAdapter::new(
        github_config(16_384)?,
        Arc::new(GitHubFixtureTransport {
            expected: build_request(),
            body: serde_json::to_vec(&build_body())?,
        }),
    )?;
    let build = BuildSource::fetch(&build_adapter, &github_actions_lookup(REQUEST_ID, 83)?)?;
    assert!(build.succeeded);
    assert_eq!(build.output_digest, Digest32::from_bytes([0x55; 32]));

    let digest = Digest32::from_bytes([0x55; 32]);
    let artifact_adapter = EcrSourceAdapter::new(
        ecr_config(16_384)?,
        Arc::new(EcrFixtureTransport {
            expected: ecr_request(digest),
            body: serde_json::to_vec(&ecr_body(digest))?,
        }),
    )?;
    let artifact = artifact_adapter.fetch(&ecr_artifact_lookup(REQUEST_ID, digest)?)?;
    assert_eq!(artifact.digest, digest);
    assert!(artifact.signature_valid);
    assert_eq!(
        artifact.meta.source_uri,
        format!(
            "https://api.ecr.us-east-1.amazonaws.com/accordlock/ecr/registries/111122223333/repositories/acme/payments/digests/sha256/{}",
            digest.to_hex()
        )
    );

    let target_adapter = KubernetesSourceAdapter::new(
        kubernetes_config(16_384)?,
        Arc::new(KubernetesFixtureTransport {
            expected: kubernetes_request(),
            body: serde_json::to_vec(&kubernetes_body())?,
        }),
    )?;
    let target = target_adapter.fetch(&kubernetes_target_lookup(
        REQUEST_ID,
        DEPLOYMENT_UID,
        "83191",
    )?)?;
    assert_eq!(target.deployment_uid, DEPLOYMENT_UID.to_string());
    assert_eq!(target.resource_version, "83191");
    Ok(())
}

#[test]
fn serialized_request_specs_are_credential_free_and_redirect_closed()
-> Result<(), Box<dyn std::error::Error>> {
    for value in [
        serde_json::to_value(review_request())?,
        serde_json::to_value(build_request())?,
        serde_json::to_value(ecr_request(Digest32::from_bytes([0x55; 32])))?,
        serde_json::to_value(kubernetes_request())?,
    ] {
        assert_eq!(value["redirect_policy"], "DENY");
        let serialized = serde_json::to_string(&value)?.to_ascii_lowercase();
        for forbidden in [
            "authorization",
            "credential",
            "password",
            "private_key",
            "secret_access_key",
            "bearer",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
    assert_eq!(review_request().method, ReadMethod::Get);
    assert_eq!(
        ecr_request(Digest32::from_bytes([1; 32])).method,
        ReadMethod::Post
    );
    Ok(())
}

#[test]
fn canonical_lookups_reject_substitution_and_mutable_tags() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(github_review_lookup(Uuid::nil(), 17).is_err());
    assert!(github_actions_lookup(REQUEST_ID, 0).is_err());
    assert!(kubernetes_target_lookup(REQUEST_ID, DEPLOYMENT_UID, "083191").is_err());

    let tag_lookup = ArtifactLookupId::parse(format!("al1/aws/ecr/{REQUEST_ID}/tag/latest"))?;
    let digest = Digest32::from_bytes([0x55; 32]);
    let adapter = EcrSourceAdapter::new(
        ecr_config(16_384)?,
        Arc::new(EcrFixtureTransport {
            expected: ecr_request(digest),
            body: serde_json::to_vec(&ecr_body(digest))?,
        }),
    )?;
    assert_eq!(
        adapter
            .fetch(&tag_lookup)
            .err()
            .map(|error| error.code().to_owned()),
        Some("invalid_provider_lookup".to_owned())
    );
    Ok(())
}

#[test]
fn strict_json_rejects_unknown_duplicate_malformed_and_oversize()
-> Result<(), Box<dyn std::error::Error>> {
    let mut unknown = review_body();
    unknown
        .as_object_mut()
        .ok_or("review fixture must be an object")?
        .insert("authorization".to_owned(), json!("Bearer ghp_stolen"));
    let adapter = GitHubSourceAdapter::new(
        github_config(16_384)?,
        Arc::new(GitHubFixtureTransport {
            expected: review_request(),
            body: serde_json::to_vec(&unknown)?,
        }),
    )?;
    let error = ReviewSource::fetch(&adapter, &github_review_lookup(REQUEST_ID, 17)?)
        .err()
        .ok_or("unknown field must fail")?;
    assert_eq!(error.code(), "invalid_provider_response");
    assert!(!format!("{error:?}").contains("ghp_stolen"));

    let duplicate =
        format!("{{\"schema_version\":1,\"schema_version\":1,\"request_id\":\"{REQUEST_ID}\"}}");
    let adapter = GitHubSourceAdapter::new(
        github_config(16_384)?,
        Arc::new(GitHubFixtureTransport {
            expected: review_request(),
            body: duplicate.into_bytes(),
        }),
    )?;
    assert!(ReviewSource::fetch(&adapter, &github_review_lookup(REQUEST_ID, 17)?).is_err());

    let adapter = GitHubSourceAdapter::new(
        github_config(16_384)?,
        Arc::new(GitHubFixtureTransport {
            expected: review_request(),
            body: b"{not-json".to_vec(),
        }),
    )?;
    assert!(ReviewSource::fetch(&adapter, &github_review_lookup(REQUEST_ID, 17)?).is_err());

    let mut expected = review_request();
    expected.maximum_response_bytes = 512;
    let adapter = GitHubSourceAdapter::new(
        github_config(512)?,
        Arc::new(GitHubFixtureTransport {
            expected,
            body: vec![b' '; 513],
        }),
    )?;
    assert!(ReviewSource::fetch(&adapter, &github_review_lookup(REQUEST_ID, 17)?).is_err());
    Ok(())
}

#[test]
fn provider_route_and_request_substitution_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut wrong_review = review_body();
    wrong_review["repository"] = json!("attacker/payments");
    let adapter = GitHubSourceAdapter::new(
        github_config(16_384)?,
        Arc::new(GitHubFixtureTransport {
            expected: review_request(),
            body: serde_json::to_vec(&wrong_review)?,
        }),
    )?;
    assert!(ReviewSource::fetch(&adapter, &github_review_lookup(REQUEST_ID, 17)?).is_err());

    let mut wrong_build = build_body();
    wrong_build["workflow_ref"] = json!(".github/workflows/evil.yml@refs/heads/main");
    let adapter = GitHubSourceAdapter::new(
        github_config(16_384)?,
        Arc::new(GitHubFixtureTransport {
            expected: build_request(),
            body: serde_json::to_vec(&wrong_build)?,
        }),
    )?;
    assert!(BuildSource::fetch(&adapter, &github_actions_lookup(REQUEST_ID, 83)?).is_err());

    let digest = Digest32::from_bytes([0x55; 32]);
    let mut wrong_ecr = ecr_body(digest);
    wrong_ecr["repository_name"] = json!("acme/other");
    let adapter = EcrSourceAdapter::new(
        ecr_config(16_384)?,
        Arc::new(EcrFixtureTransport {
            expected: ecr_request(digest),
            body: serde_json::to_vec(&wrong_ecr)?,
        }),
    )?;
    assert!(
        adapter
            .fetch(&ecr_artifact_lookup(REQUEST_ID, digest)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn kubernetes_cluster_uid_and_resource_version_mismatches_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    for (field, replacement) in [
        (
            "cluster_identity",
            json!("eks://111122223333/us-east-1/other"),
        ),
        ("deployment_uid", json!(Uuid::from_bytes([0x99; 16]))),
        ("resource_version", json!("83192")),
    ] {
        let mut body = kubernetes_body();
        body[field] = replacement;
        let adapter = KubernetesSourceAdapter::new(
            kubernetes_config(16_384)?,
            Arc::new(KubernetesFixtureTransport {
                expected: kubernetes_request(),
                body: serde_json::to_vec(&body)?,
            }),
        )?;
        assert!(
            adapter
                .fetch(&kubernetes_target_lookup(
                    REQUEST_ID,
                    DEPLOYMENT_UID,
                    "83191"
                )?)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn response_debug_redacts_even_credential_shaped_bodies() {
    let response = AuthenticatedJsonResponse::new(
        200,
        ResponseMediaType::Json,
        b"Bearer ghp_super_secret".to_vec(),
    );
    let rendered = format!("{response:?}");
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("ghp_super_secret"));
}
