use std::{
    fmt::Debug,
    fs,
    io::{Read, Write as _},
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use accordlock_protocol::Digest32;
use accordlock_provider_adapters::{
    GitHubAuthenticatedTransport as _, GitHubReadOperation, GitHubReadRequest, ReadMethod,
    RedirectPolicy, TransportFailure,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use rcgen::generate_simple_self_signed;
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    http::{FixedHttpsClient, HttpMethod},
    model::{
        ArtifactTrustPayload, Base64Bytes, BuildTrustPayload, CandidateReceipt, CheckKind,
        CheckReceipt, CheckStatus, CredentialBundle, EKS_ENROLLMENT_SCHEMA_VERSION, EcrProfile,
        Effect, EksDiscoveryProfile, EksEnrollmentCredentials, EksEnrollmentRequest, GitHubProfile,
        KubernetesProfile, ModelError, PREFLIGHT_BUILD_MARKER_SCHEMA_VERSION,
        PREFLIGHT_PROTOCOL_VERSION, PREFLIGHT_SCHEMA_VERSION, PreflightCommand, PreflightOutcome,
        PreflightProfile, PreflightRunnerBuildMarker, ReceiptVerifierProfile,
        SignedPreflightReceipt, TargetReceipt, TrustVerifierProfile, UnsignedPreflightReceipt,
        sign_artifact_trust_record, sign_build_trust_record, sign_receipt, verify_receipt,
    },
    run_preflight,
    transports::{EksDiscoveryTransport, EksEnrollmentTransport, GitHubTransport},
};

const TEST_AUTHORITY: &str = "preflight.test";

struct TlsFixture {
    socket: SocketAddr,
    certificate_der: Vec<u8>,
    server: JoinHandle<Result<Vec<u8>, String>>,
}

struct TlsSequenceFixture {
    socket: SocketAddr,
    certificate_der: Vec<u8>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    server: JoinHandle<Result<(), String>>,
}

impl TlsSequenceFixture {
    fn finish(self) -> Vec<Vec<u8>> {
        must(
            self.server
                .join()
                .map_err(|_| "TLS sequence fixture thread panicked".to_owned())
                .and_then(|result| result),
        );
        must(
            self.requests
                .lock()
                .map(|requests| requests.clone())
                .map_err(|_| "TLS request capture lock was poisoned".to_owned()),
        )
    }
}

impl TlsFixture {
    fn finish(self) -> Vec<u8> {
        must(
            self.server
                .join()
                .map_err(|_| "TLS fixture thread panicked".to_owned())
                .and_then(|result| result),
        )
    }
}

fn must<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("test fixture failed: {error:?}"))
}

fn spawn_tls_fixture(authority: &str, response: Vec<u8>) -> TlsFixture {
    let certified = must(generate_simple_self_signed(vec![authority.to_owned()]));
    let certificate = certified.cert.der().clone();
    let certificate_der = certificate.as_ref().to_vec();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut server_config = must(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key),
    );
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);
    let listener = must(TcpListener::bind("127.0.0.1:0"));
    let socket = must(listener.local_addr());
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().map_err(|error| error.to_string())?;
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let connection = ServerConnection::new(server_config).map_err(|error| error.to_string())?;
        let mut stream = StreamOwned::new(connection, socket);
        let request = read_request(&mut stream)?;
        stream
            .write_all(&response)
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        stream.conn.send_close_notify();
        stream.flush().map_err(|error| error.to_string())?;
        Ok(request)
    });
    TlsFixture {
        socket,
        certificate_der,
        server,
    }
}

fn spawn_tls_sequence(authority: &str, responses: Vec<Vec<u8>>) -> TlsSequenceFixture {
    let certified = must(generate_simple_self_signed(vec![authority.to_owned()]));
    let certificate = certified.cert.der().clone();
    let certificate_der = certificate.as_ref().to_vec();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut server_config = must(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key),
    );
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);
    let listener = must(TcpListener::bind("127.0.0.1:0"));
    must(listener.set_nonblocking(true));
    let socket = must(listener.local_addr());
    let requests = Arc::new(Mutex::new(Vec::with_capacity(responses.len())));
    let captured = Arc::clone(&requests);
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        for response in responses {
            let (socket, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err("timed out waiting for bounded TLS request".to_owned());
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            };
            socket
                .set_nonblocking(false)
                .map_err(|error| error.to_string())?;
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|error| error.to_string())?;
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|error| error.to_string())?;
            let connection = ServerConnection::new(Arc::clone(&server_config))
                .map_err(|error| error.to_string())?;
            let mut stream = StreamOwned::new(connection, socket);
            let request = read_request(&mut stream)?;
            captured
                .lock()
                .map_err(|_| "TLS request capture lock was poisoned".to_owned())?
                .push(request);
            stream
                .write_all(&response)
                .map_err(|error| error.to_string())?;
            stream.flush().map_err(|error| error.to_string())?;
            stream.conn.send_close_notify();
            stream.flush().map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    TlsSequenceFixture {
        socket,
        certificate_der,
        requests,
        server,
    }
}

fn read_request(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2_048];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("client closed before completing its request".to_owned());
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 2 * 1024 * 1024 {
            return Err("request exceeded test fixture bound".to_owned());
        }
        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        else {
            continue;
        };
        let header =
            std::str::from_utf8(&request[..header_end]).map_err(|error| error.to_string())?;
        let content_length = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>())
            })
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or(0);
        if request.len() == header_end.saturating_add(content_length) {
            return Ok(request);
        }
        if request.len() > header_end.saturating_add(content_length) {
            return Err("client sent bytes beyond Content-Length".to_owned());
        }
    }
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        wire.extend_from_slice(name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"Connection: close\r\n\r\n");
    wire.extend_from_slice(body);
    wire
}

fn json_response(value: &serde_json::Value) -> Vec<u8> {
    let body = must(serde_json::to_vec(value));
    response(
        "200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", &body.len().to_string()),
        ],
        &body,
    )
}

fn client_for(fixture: &TlsFixture) -> FixedHttpsClient {
    must(FixedHttpsClient::new(
        TEST_AUTHORITY,
        Some(fixture.socket),
        std::slice::from_ref(&fixture.certificate_der),
    ))
}

#[test]
fn fixed_https_client_uses_pinned_tls_authority_and_exact_request() {
    let body = br#"{"ok":true}"#;
    let fixture = spawn_tls_fixture(
        TEST_AUTHORITY,
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", &body.len().to_string()),
            ],
            body,
        ),
    );
    let client = client_for(&fixture);
    let actual = must(client.send_json(
        HttpMethod::Post,
        "/v1/check?fixed=1",
        &[("x-test", "bound".to_owned())],
        b"{}",
        1_024,
    ));
    assert_eq!(actual.status, 200);
    assert_eq!(
        actual.content_type.as_deref(),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(actual.body, body);

    let request = must(String::from_utf8(fixture.finish()));
    assert!(request.starts_with("POST /v1/check?fixed=1 HTTP/1.1\r\n"));
    assert!(request.contains("\r\nHost: preflight.test\r\n"));
    assert!(request.contains("\r\nx-test: bound\r\n"));
    assert!(request.ends_with("\r\n\r\n{}"));
}

#[test]
fn fixed_https_client_never_follows_redirects() {
    let fixture = spawn_tls_fixture(
        TEST_AUTHORITY,
        response(
            "302 Found",
            &[
                ("Location", "https://attacker.invalid/collect"),
                ("Content-Length", "0"),
            ],
            b"",
        ),
    );
    let result = client_for(&fixture).send_json(HttpMethod::Get, "/fixed", &[], b"", 1_024);
    assert!(matches!(result, Err(TransportFailure::Route)));
    let request = must(String::from_utf8(fixture.finish()));
    assert!(request.starts_with("GET /fixed HTTP/1.1\r\n"));
    assert!(!request.contains("attacker.invalid"));
}

#[test]
fn fixed_https_client_rejects_oversized_or_ambiguous_responses() {
    let oversized = spawn_tls_fixture(
        TEST_AUTHORITY,
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Content-Length", "3"),
            ],
            b"123",
        ),
    );
    let result = client_for(&oversized).send_json(HttpMethod::Get, "/fixed", &[], b"", 2);
    assert!(matches!(result, Err(TransportFailure::Integrity)));
    let _ = oversized.finish();

    let ambiguous = spawn_tls_fixture(
        TEST_AUTHORITY,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    );
    let result = client_for(&ambiguous).send_json(HttpMethod::Get, "/fixed", &[], b"", 1_024);
    assert!(matches!(result, Err(TransportFailure::Integrity)));
    let _ = ambiguous.finish();
}

#[test]
fn fixed_https_client_accepts_only_minimal_unambiguous_chunked_encoding() {
    let valid = spawn_tls_fixture(
        TEST_AUTHORITY,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
    );
    let actual = must(client_for(&valid).send_json(HttpMethod::Get, "/fixed", &[], b"", 1_024));
    assert_eq!(actual.body, b"hello");
    let _ = valid.finish();

    let extended = spawn_tls_fixture(
        TEST_AUTHORITY,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n".to_vec(),
    );
    let result = client_for(&extended).send_json(HttpMethod::Get, "/fixed", &[], b"", 1_024);
    assert!(matches!(result, Err(TransportFailure::Integrity)));
    let _ = extended.finish();
}

#[test]
fn fixed_https_client_rejects_route_and_header_injection_before_network_io() {
    let certified = must(generate_simple_self_signed(vec![TEST_AUTHORITY.to_owned()]));
    let client = must(FixedHttpsClient::new(
        TEST_AUTHORITY,
        Some(must("127.0.0.1:9".parse())),
        &[certified.cert.der().as_ref().to_vec()],
    ));
    let bad_path = client.send_json(
        HttpMethod::Get,
        "/fixed\r\nx-injected: yes",
        &[],
        b"",
        1_024,
    );
    assert!(matches!(bad_path, Err(TransportFailure::Route)));
    let bad_header = client.send_json(
        HttpMethod::Get,
        "/fixed",
        &[("X-Test", "value".to_owned())],
        b"",
        1_024,
    );
    assert!(matches!(bad_header, Err(TransportFailure::Route)));
}

#[test]
fn github_transport_rejects_success_body_with_wrong_content_type() {
    let fixture = spawn_tls_fixture(
        TEST_AUTHORITY,
        response(
            "200 OK",
            &[("Content-Type", "text/html"), ("Content-Length", "2")],
            b"{}",
        ),
    );
    let temporary = must(TempDir::new());
    let build_seed = [31_u8; 32];
    let artifact_seed = [32_u8; 32];
    let receipt_seed = [33_u8; 32];
    let profile = profile_fixture(
        fixture.socket,
        fixture.certificate_der.clone(),
        &temporary,
        build_seed,
        artifact_seed,
        receipt_seed,
    );
    let credentials = credential_fixture(receipt_seed);
    let image_digest = digest(b"candidate-image");
    let build = must(sign_build_trust_record(
        BuildTrustPayload {
            schema_version: 1,
            key_id: "build-key".to_owned(),
            repository: "acme/service".to_owned(),
            workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
            run_id: 99,
            commit_sha: "a".repeat(40),
            input_manifest_root: digest(b"inputs"),
            output_digest: image_digest,
            issued_at: 100,
            expires_at: 900,
        },
        build_seed,
    ));
    let transport = must(GitHubTransport::new(
        Arc::new(profile),
        Arc::new(credentials),
        Uuid::from_u128(1),
        7,
        99,
        image_digest,
        build,
        200,
    ));
    let result = transport.read(&GitHubReadRequest {
        method: ReadMethod::Get,
        authority: TEST_AUTHORITY.to_owned(),
        path: "/api/v3/repos/acme/service/pulls/7/accordlock-review-decision".to_owned(),
        redirect_policy: RedirectPolicy::Deny,
        maximum_response_bytes: 64 * 1024,
        operation: GitHubReadOperation::PullReviewDecision,
    });
    assert!(matches!(result, Err(TransportFailure::Integrity)));
    let request = must(String::from_utf8(fixture.finish()));
    assert!(request.starts_with("GET /api/v3/repos/acme/service/pulls/7 HTTP/1.1\r\n"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn run_preflight_completes_full_read_only_provider_chain_and_signs_passed_receipt() {
    const GITHUB_AUTHORITY: &str = "github.preflight.test";
    const ECR_AUTHORITY: &str = "api.ecr.us-east-1.amazonaws.com";
    const EKS_AUTHORITY: &str = "eks.us-east-1.amazonaws.com";
    const KUBERNETES_AUTHORITY: &str = "kubernetes.preflight.test";
    const NOW: i64 = 200;
    let commit = "a".repeat(40);
    let candidate_digest = digest(b"release-candidate");
    let current_digest = digest(b"currently-deployed");
    let deployment_uid = Uuid::from_u128(300);

    let github = spawn_tls_sequence(
        GITHUB_AUTHORITY,
        vec![
            json_response(&json!({
                "id": 701,
                "number": 7,
                "head": { "sha": commit }
            })),
            json_response(&json!([{
                "id": 702,
                "user": { "login": "reviewer" },
                "state": "APPROVED",
                "commit_id": commit
            }])),
            json_response(&json!({
                "id": 99,
                "run_attempt": 1,
                "head_sha": commit,
                "path": ".github/workflows/release.yml@refs/heads/main",
                "status": "completed",
                "conclusion": "success"
            })),
        ],
    );
    let ecr = spawn_tls_sequence(
        ECR_AUTHORITY,
        vec![json_response(&json!({
            "images": [{
                "registryId": "123456789012",
                "repositoryName": "acme/service",
                "imageId": { "imageDigest": candidate_digest.to_string() }
            }],
            "failures": []
        }))],
    );
    let deployment = deployment_response(deployment_uid, "12345", current_digest);
    let kubernetes = spawn_tls_sequence(KUBERNETES_AUTHORITY, vec![deployment.clone(), deployment]);
    let eks = spawn_tls_sequence(
        EKS_AUTHORITY,
        vec![eks_cluster_response(
            "arn:aws:eks:us-east-1:123456789012:cluster/primary",
            KUBERNETES_AUTHORITY,
            &kubernetes.certificate_der,
        )],
    );
    let temporary = must(TempDir::new());
    let build_seed = [71_u8; 32];
    let artifact_seed = [72_u8; 32];
    let receipt_seed = [73_u8; 32];
    let profile = integration_profile(
        EndpointConfig {
            authority: GITHUB_AUTHORITY,
            socket: github.socket,
            certificate_der: github.certificate_der.clone(),
        },
        EndpointConfig {
            authority: ECR_AUTHORITY,
            socket: ecr.socket,
            certificate_der: ecr.certificate_der.clone(),
        },
        EndpointConfig {
            authority: EKS_AUTHORITY,
            socket: eks.socket,
            certificate_der: eks.certificate_der.clone(),
        },
        EndpointConfig {
            authority: KUBERNETES_AUTHORITY,
            socket: kubernetes.socket,
            certificate_der: kubernetes.certificate_der.clone(),
        },
        &temporary,
        build_seed,
        artifact_seed,
        receipt_seed,
    );
    write_trust_records(
        &profile,
        build_seed,
        artifact_seed,
        &commit,
        candidate_digest,
        NOW,
    );
    let command = preflight_command(&profile, candidate_digest);
    let receipt = must(run_preflight(
        &profile,
        credential_fixture(receipt_seed),
        &command,
        NOW,
    ));

    assert_eq!(
        receipt.payload.outcome,
        PreflightOutcome::Passed,
        "unexpected preflight failure: {:?}",
        receipt.payload.reason_codes
    );
    assert_eq!(
        receipt
            .payload
            .checks
            .iter()
            .map(|check| check.kind)
            .collect::<Vec<_>>(),
        vec![
            CheckKind::CodeReview,
            CheckKind::Build,
            CheckKind::Image,
            CheckKind::Target,
        ]
    );
    assert!(
        receipt
            .payload
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Passed)
    );
    assert!(receipt.payload.policy_decision_hash.is_some());
    assert!(receipt.payload.evidence_root.is_some());
    assert!(receipt.payload.evaluation_attestation.is_some());
    assert_eq!(receipt.payload.effect, Effect::None);
    assert!(!receipt.payload.deployment_performed);
    assert_eq!(receipt.payload.candidate.commit_sha, commit);
    assert_eq!(receipt.payload.candidate.image_digest, candidate_digest);
    assert_eq!(
        receipt.payload.target.deployment_uid,
        deployment_uid.to_string()
    );
    assert_eq!(receipt.payload.target.resource_version, "12345");
    assert_eq!(receipt.payload.target.observed_image_digest, current_digest);
    assert_eq!(
        receipt.payload.target.cluster_identity,
        "arn:aws:eks:us-east-1:123456789012:cluster/primary"
    );
    assert_eq!(
        receipt.payload.target.cluster_endpoint,
        format!("https://{KUBERNETES_AUTHORITY}")
    );
    assert_ne!(
        receipt.payload.target.cluster_ca_hash,
        Digest32::from_bytes([0; 32])
    );
    let receipt_json = must(serde_json::to_string(&receipt));
    assert!(!receipt_json.contains("k8s-aws-v1."));
    assert!(!receipt_json.contains("kubernetes_bearer"));
    must(verify_receipt(&receipt, &profile));

    let github_requests = text_requests(github.finish());
    assert_eq!(github_requests.len(), 3);
    assert_request(
        &github_requests[0],
        "GET /api/v3/repos/acme/service/pulls/7 HTTP/1.1",
        "github.preflight.test",
        Some("authorization: Bearer github-test-token"),
    );
    assert_request(
        &github_requests[1],
        "GET /api/v3/repos/acme/service/pulls/7/reviews?per_page=100 HTTP/1.1",
        "github.preflight.test",
        Some("authorization: Bearer github-test-token"),
    );
    assert_request(
        &github_requests[2],
        "GET /api/v3/repos/acme/service/actions/runs/99 HTTP/1.1",
        "github.preflight.test",
        Some("authorization: Bearer github-test-token"),
    );

    let ecr_requests = text_requests(ecr.finish());
    assert_eq!(ecr_requests.len(), 1);
    assert_request(
        &ecr_requests[0],
        "POST / HTTP/1.1",
        ECR_AUTHORITY,
        Some("x-amz-target: AmazonEC2ContainerRegistry_V20150921.BatchGetImage"),
    );
    assert!(ecr_requests[0].contains("authorization: AWS4-HMAC-SHA256 Credential=AKIATESTACCESS/"));
    assert!(ecr_requests[0].contains(&candidate_digest.to_string()));

    let eks_requests = text_requests(eks.finish());
    assert_eq!(eks_requests.len(), 1);
    assert_request(
        &eks_requests[0],
        "GET /clusters/primary HTTP/1.1",
        EKS_AUTHORITY,
        None,
    );
    assert!(eks_requests[0].contains(
        "authorization: AWS4-HMAC-SHA256 Credential=AKIATESTACCESS/19700101/us-east-1/eks/aws4_request"
    ));

    let kubernetes_requests = text_requests(kubernetes.finish());
    assert_eq!(kubernetes_requests.len(), 2);
    for request in &kubernetes_requests {
        assert_request(
            request,
            "GET /apis/apps/v1/namespaces/production/deployments/service HTTP/1.1",
            KUBERNETES_AUTHORITY,
            None,
        );
        let authorization = request
            .lines()
            .find(|line| line.starts_with("authorization: Bearer k8s-aws-v1."));
        assert!(authorization.is_some());
        assert!(!request.contains("kubernetes-test-token"));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn run_preflight_turns_kubernetes_redirect_into_signed_indeterminate_receipt() {
    const EKS_AUTHORITY: &str = "eks.us-east-1.amazonaws.com";
    const KUBERNETES_AUTHORITY: &str = "kubernetes.preflight.test";
    const NOW: i64 = 200;
    let redirect = spawn_tls_sequence(
        KUBERNETES_AUTHORITY,
        vec![response(
            "307 Temporary Redirect",
            &[
                ("Location", "https://attacker.invalid/cluster"),
                ("Content-Length", "0"),
            ],
            b"",
        )],
    );
    let eks = spawn_tls_sequence(
        EKS_AUTHORITY,
        vec![eks_cluster_response(
            "arn:aws:eks:us-east-1:123456789012:cluster/primary",
            KUBERNETES_AUTHORITY,
            &redirect.certificate_der,
        )],
    );
    let certified = must(generate_simple_self_signed(vec![
        "unused.preflight.test".to_owned(),
    ]));
    let unused_certificate = certified.cert.der().as_ref().to_vec();
    let temporary = must(TempDir::new());
    let build_seed = [81_u8; 32];
    let artifact_seed = [82_u8; 32];
    let receipt_seed = [83_u8; 32];
    let profile = integration_profile(
        EndpointConfig {
            authority: "unused.preflight.test",
            socket: must("127.0.0.1:9".parse()),
            certificate_der: unused_certificate.clone(),
        },
        EndpointConfig {
            authority: "api.ecr.us-east-1.amazonaws.com",
            socket: must("127.0.0.1:9".parse()),
            certificate_der: unused_certificate,
        },
        EndpointConfig {
            authority: EKS_AUTHORITY,
            socket: eks.socket,
            certificate_der: eks.certificate_der.clone(),
        },
        EndpointConfig {
            authority: KUBERNETES_AUTHORITY,
            socket: redirect.socket,
            certificate_der: redirect.certificate_der.clone(),
        },
        &temporary,
        build_seed,
        artifact_seed,
        receipt_seed,
    );
    let candidate_digest = digest(b"redirected-release-candidate");
    write_trust_records(
        &profile,
        build_seed,
        artifact_seed,
        &"c".repeat(40),
        candidate_digest,
        NOW,
    );
    let command = preflight_command(&profile, candidate_digest);
    let receipt = must(run_preflight(
        &profile,
        credential_fixture(receipt_seed),
        &command,
        NOW,
    ));

    assert_eq!(receipt.payload.outcome, PreflightOutcome::Indeterminate);
    assert_eq!(
        receipt.payload.reason_codes,
        vec!["KUBERNETES_TARGET_UNAVAILABLE"]
    );
    assert!(
        receipt
            .payload
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Indeterminate)
    );
    assert!(receipt.payload.policy_decision_hash.is_none());
    assert!(receipt.payload.evidence_root.is_none());
    assert!(receipt.payload.evaluation_attestation.is_none());
    assert_eq!(receipt.payload.effect, Effect::None);
    assert!(!receipt.payload.deployment_performed);
    must(verify_receipt(&receipt, &profile));

    let eks_requests = text_requests(eks.finish());
    assert_eq!(eks_requests.len(), 1);
    assert_request(
        &eks_requests[0],
        "GET /clusters/primary HTTP/1.1",
        EKS_AUTHORITY,
        None,
    );

    let requests = text_requests(redirect.finish());
    assert_eq!(requests.len(), 1);
    assert_request(
        &requests[0],
        "GET /apis/apps/v1/namespaces/production/deployments/service HTTP/1.1",
        KUBERNETES_AUTHORITY,
        None,
    );
    assert!(requests[0].contains("authorization: Bearer k8s-aws-v1."));
    assert!(!requests[0].contains("attacker.invalid"));
}

#[test]
fn eks_permission_failure_returns_a_signed_indeterminate_receipt() {
    let body = br#"{"message":"AccessDeniedException"}"#;
    let (receipt, profile, requests) = run_eks_discovery_failure(response(
        "403 Forbidden",
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", &body.len().to_string()),
        ],
        body,
    ));

    assert_eq!(receipt.payload.outcome, PreflightOutcome::Indeterminate);
    assert_eq!(
        receipt.payload.reason_codes,
        vec!["EKS_CLUSTER_DISCOVERY_UNAVAILABLE"]
    );
    assert_eq!(receipt.payload.target.cluster_identity, "unresolved");
    assert_eq!(receipt.payload.target.cluster_endpoint, "unresolved");
    assert_eq!(
        receipt.payload.target.cluster_ca_hash,
        Digest32::from_bytes([0; 32])
    );
    assert!(!receipt.payload.deployment_performed);
    must(verify_receipt(&receipt, &profile));
    assert_eq!(requests.len(), 1);
    assert_request(
        &requests[0],
        "GET /clusters/primary HTTP/1.1",
        "eks.us-east-1.amazonaws.com",
        None,
    );
}

#[test]
fn eks_discovery_rejects_substituted_arn_and_endpoint() {
    let certified = must(generate_simple_self_signed(vec![
        "kubernetes.preflight.test".to_owned(),
    ]));
    let certificate_der = certified.cert.der().as_ref().to_vec();

    let (wrong_arn, wrong_arn_profile, _) = run_eks_discovery_failure(eks_cluster_response(
        "arn:aws:eks:us-east-1:999999999999:cluster/primary",
        "kubernetes.preflight.test",
        &certificate_der,
    ));
    assert_eq!(wrong_arn.payload.outcome, PreflightOutcome::Indeterminate);
    assert_eq!(
        wrong_arn.payload.reason_codes,
        vec!["EKS_CLUSTER_DISCOVERY_UNAVAILABLE"]
    );
    must(verify_receipt(&wrong_arn, &wrong_arn_profile));

    let (wrong_endpoint, wrong_endpoint_profile, _) =
        run_eks_discovery_failure(eks_cluster_response(
            "arn:aws:eks:us-east-1:123456789012:cluster/primary",
            "substituted.preflight.test",
            &certificate_der,
        ));
    assert_eq!(
        wrong_endpoint.payload.outcome,
        PreflightOutcome::Indeterminate
    );
    assert_eq!(
        wrong_endpoint.payload.reason_codes,
        vec!["EKS_CLUSTER_DISCOVERY_UNAVAILABLE"]
    );
    must(verify_receipt(&wrong_endpoint, &wrong_endpoint_profile));
}

#[test]
fn eks_discovery_ca_substitution_changes_the_bound_cluster_identity() {
    const EKS_AUTHORITY: &str = "eks.us-east-1.amazonaws.com";
    const KUBERNETES_AUTHORITY: &str = "kubernetes.preflight.test";
    const NOW: i64 = 200;
    let first_ca = must(generate_simple_self_signed(vec![
        KUBERNETES_AUTHORITY.to_owned(),
    ]));
    let second_ca = must(generate_simple_self_signed(vec![
        KUBERNETES_AUTHORITY.to_owned(),
    ]));
    let first_der = first_ca.cert.der().as_ref().to_vec();
    let second_der = second_ca.cert.der().as_ref().to_vec();
    let eks = spawn_tls_sequence(
        EKS_AUTHORITY,
        vec![
            eks_cluster_response(
                "arn:aws:eks:us-east-1:123456789012:cluster/primary",
                KUBERNETES_AUTHORITY,
                &first_der,
            ),
            eks_cluster_response(
                "arn:aws:eks:us-east-1:123456789012:cluster/primary",
                KUBERNETES_AUTHORITY,
                &second_der,
            ),
        ],
    );
    let unused = must(generate_simple_self_signed(vec![
        "unused.preflight.test".to_owned(),
    ]));
    let unused_der = unused.cert.der().as_ref().to_vec();
    let temporary = must(TempDir::new());
    let profile = integration_profile(
        EndpointConfig {
            authority: "unused.preflight.test",
            socket: must("127.0.0.1:9".parse()),
            certificate_der: unused_der.clone(),
        },
        EndpointConfig {
            authority: "api.ecr.us-east-1.amazonaws.com",
            socket: must("127.0.0.1:9".parse()),
            certificate_der: unused_der,
        },
        EndpointConfig {
            authority: EKS_AUTHORITY,
            socket: eks.socket,
            certificate_der: eks.certificate_der.clone(),
        },
        EndpointConfig {
            authority: KUBERNETES_AUTHORITY,
            socket: must("127.0.0.1:9".parse()),
            certificate_der: first_der,
        },
        &temporary,
        [91_u8; 32],
        [92_u8; 32],
        [93_u8; 32],
    );
    let transport = must(EksDiscoveryTransport::new(
        Arc::new(profile),
        Arc::new(credential_fixture([93_u8; 32])),
        NOW,
    ));
    let first = must(transport.describe_cluster());
    let second = must(transport.describe_cluster());

    assert_ne!(first.cluster_ca_hash, second.cluster_ca_hash);
    assert_ne!(
        first.discovery_identity_hash,
        second.discovery_identity_hash
    );
    assert_eq!(text_requests(eks.finish()).len(), 2);
}

#[test]
fn eks_enrollment_uses_one_fixed_authenticated_request_and_emits_only_public_pins() {
    const EKS_AUTHORITY: &str = "eks.us-east-1.amazonaws.com";
    const KUBERNETES_AUTHORITY: &str = "primary.eks.test";
    const NOW: i64 = 200;
    let kubernetes_ca = must(generate_simple_self_signed(vec![
        KUBERNETES_AUTHORITY.to_owned(),
    ]));
    let kubernetes_ca_der = kubernetes_ca.cert.der().as_ref().to_vec();
    let eks = spawn_tls_fixture(
        EKS_AUTHORITY,
        eks_cluster_response(
            "arn:aws:eks:us-east-1:123456789012:cluster/primary",
            KUBERNETES_AUTHORITY,
            &kubernetes_ca_der,
        ),
    );
    let transport = must(EksEnrollmentTransport::new_for_test(
        eks_enrollment_request(),
        eks_enrollment_credentials(),
        NOW,
        eks.socket,
        eks.certificate_der.clone(),
    ));
    let result = must(transport.describe_cluster());
    assert_eq!(result.schema_version, EKS_ENROLLMENT_SCHEMA_VERSION);
    assert_eq!(
        result.cluster_arn,
        "arn:aws:eks:us-east-1:123456789012:cluster/primary"
    );
    assert_eq!(result.endpoint, format!("https://{KUBERNETES_AUTHORITY}"));
    let expected_kubernetes_client = must(FixedHttpsClient::new(
        KUBERNETES_AUTHORITY,
        None,
        std::slice::from_ref(&kubernetes_ca_der),
    ));
    assert_eq!(
        result.cluster_ca_hash,
        expected_kubernetes_client.trust_anchor_hash()
    );

    let request = must(String::from_utf8(eks.finish()));
    assert_request(
        &request,
        "GET /clusters/primary HTTP/1.1\r\n",
        EKS_AUTHORITY,
        Some("x-amz-security-token: test-session-token"),
    );
    assert!(request.contains("Credential=AKIATESTACCESS/"));
    assert!(request.contains("/us-east-1/eks/aws4_request"));
    assert_eq!(request.matches("GET /clusters/primary HTTP/1.1").count(), 1);
    assert!(!request.contains("primary.eks.test/"));
}

#[test]
fn eks_enrollment_rejects_permission_redirect_arn_endpoint_and_ca_attacks() {
    const EKS_AUTHORITY: &str = "eks.us-east-1.amazonaws.com";
    const KUBERNETES_AUTHORITY: &str = "primary.eks.test";
    const NOW: i64 = 200;
    let kubernetes_ca = must(generate_simple_self_signed(vec![
        KUBERNETES_AUTHORITY.to_owned(),
    ]));
    let kubernetes_ca_der = kubernetes_ca.cert.der().as_ref().to_vec();

    let permission = spawn_tls_fixture(
        EKS_AUTHORITY,
        response(
            "403 Forbidden",
            &[
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
            ],
            b"{}",
        ),
    );
    let transport = must(EksEnrollmentTransport::new_for_test(
        eks_enrollment_request(),
        eks_enrollment_credentials(),
        NOW,
        permission.socket,
        permission.certificate_der.clone(),
    ));
    assert!(matches!(
        transport.describe_cluster(),
        Err(TransportFailure::Authentication)
    ));
    let _ = permission.finish();

    let redirect = spawn_tls_fixture(
        EKS_AUTHORITY,
        response(
            "302 Found",
            &[
                ("Location", "https://attacker.invalid/clusters/primary"),
                ("Content-Length", "0"),
            ],
            b"",
        ),
    );
    let transport = must(EksEnrollmentTransport::new_for_test(
        eks_enrollment_request(),
        eks_enrollment_credentials(),
        NOW,
        redirect.socket,
        redirect.certificate_der.clone(),
    ));
    assert!(matches!(
        transport.describe_cluster(),
        Err(TransportFailure::Route)
    ));
    let redirected_request = must(String::from_utf8(redirect.finish()));
    assert!(!redirected_request.contains("attacker.invalid"));

    for malicious_response in [
        eks_cluster_response(
            "arn:aws:eks:us-east-1:999999999999:cluster/primary",
            KUBERNETES_AUTHORITY,
            &kubernetes_ca_der,
        ),
        eks_cluster_response(
            "arn:aws:eks:us-east-1:123456789012:cluster/primary",
            "primary.eks.test:443",
            &kubernetes_ca_der,
        ),
        json_response(&json!({
            "cluster": {
                "name": "primary",
                "arn": "arn:aws:eks:us-east-1:123456789012:cluster/primary",
                "endpoint": "https://primary.eks.test",
                "certificateAuthority": { "data": "bm90LWEtY2VydGlmaWNhdGU=" }
            }
        })),
    ] {
        let fixture = spawn_tls_fixture(EKS_AUTHORITY, malicious_response);
        let transport = must(EksEnrollmentTransport::new_for_test(
            eks_enrollment_request(),
            eks_enrollment_credentials(),
            NOW,
            fixture.socket,
            fixture.certificate_der.clone(),
        ));
        assert!(matches!(
            transport.describe_cluster(),
            Err(TransportFailure::Integrity)
        ));
        let _ = fixture.finish();
    }
}

#[test]
fn eks_enrollment_ca_substitution_changes_the_exported_pin() {
    const EKS_AUTHORITY: &str = "eks.us-east-1.amazonaws.com";
    const KUBERNETES_AUTHORITY: &str = "primary.eks.test";
    const NOW: i64 = 200;
    let first = must(generate_simple_self_signed(vec![
        KUBERNETES_AUTHORITY.to_owned(),
    ]));
    let second = must(generate_simple_self_signed(vec![
        KUBERNETES_AUTHORITY.to_owned(),
    ]));
    let fixture = spawn_tls_sequence(
        EKS_AUTHORITY,
        vec![
            eks_cluster_response(
                "arn:aws:eks:us-east-1:123456789012:cluster/primary",
                KUBERNETES_AUTHORITY,
                first.cert.der().as_ref(),
            ),
            eks_cluster_response(
                "arn:aws:eks:us-east-1:123456789012:cluster/primary",
                KUBERNETES_AUTHORITY,
                second.cert.der().as_ref(),
            ),
        ],
    );
    let transport = must(EksEnrollmentTransport::new_for_test(
        eks_enrollment_request(),
        eks_enrollment_credentials(),
        NOW,
        fixture.socket,
        fixture.certificate_der.clone(),
    ));
    let first_result = must(transport.describe_cluster());
    let second_result = must(transport.describe_cluster());
    assert_ne!(first_result.cluster_ca_hash, second_result.cluster_ca_hash);
    assert_eq!(text_requests(fixture.finish()).len(), 2);
}

#[test]
fn eks_enrollment_rejects_noncanonical_targets_and_redacts_aws_secrets() {
    for region in [
        "US-EAST-1",
        "us-east-0",
        "us--east",
        "cn-north-1",
        "us-gov-west-1",
    ] {
        let mut request = eks_enrollment_request();
        request.region = region.to_owned();
        assert_eq!(request.validate(), Err(ModelError::InvalidRequest));
    }
    for account_id in ["123", "12345678901a"] {
        let mut request = eks_enrollment_request();
        request.account_id = account_id.to_owned();
        assert_eq!(request.validate(), Err(ModelError::InvalidRequest));
    }
    for cluster_name in ["Primary", "primary/other", "-primary"] {
        let mut request = eks_enrollment_request();
        request.cluster_name = cluster_name.to_owned();
        assert_eq!(request.validate(), Err(ModelError::InvalidRequest));
    }

    let debug = format!("{:?}", eks_enrollment_credentials());
    assert!(!debug.contains("AKIATESTACCESS"));
    assert!(!debug.contains("test-secret"));
    assert!(!debug.contains("session-token"));
    assert_eq!(debug.matches("<redacted>").count(), 3);
}

#[test]
fn receipt_signature_binds_every_payload_field_and_requires_canonical_signature() {
    let certified = must(generate_simple_self_signed(vec![TEST_AUTHORITY.to_owned()]));
    let temporary = must(TempDir::new());
    let receipt_seed = [43_u8; 32];
    let profile = profile_fixture(
        must("127.0.0.1:9".parse()),
        certified.cert.der().as_ref().to_vec(),
        &temporary,
        [41_u8; 32],
        [42_u8; 32],
        receipt_seed,
    );
    let payload = receipt_fixture(&profile);
    let receipt = must(sign_receipt(payload, &profile, receipt_seed));
    must(verify_receipt(&receipt, &profile));

    let encoded = must(serde_json::to_vec(&receipt));
    let decoded = must(serde_json::from_slice(&encoded));
    assert_eq!(receipt, decoded);

    let mut changed_payload = receipt.clone();
    changed_payload.payload.candidate.pull_number += 1;
    assert_eq!(
        verify_receipt(&changed_payload, &profile),
        Err(ModelError::ReceiptSignature)
    );

    let mut changed_hash = receipt.clone();
    changed_hash.receipt_hash = digest(b"different-receipt");
    assert_eq!(
        verify_receipt(&changed_hash, &profile),
        Err(ModelError::ReceiptSignature)
    );

    let mut noncanonical_signature = receipt;
    noncanonical_signature.signature.push('=');
    assert_eq!(
        verify_receipt(&noncanonical_signature, &profile),
        Err(ModelError::ReceiptSignature)
    );
}

#[test]
fn receipt_signing_rejects_wrong_key_and_invalid_effect_claims() {
    let certified = must(generate_simple_self_signed(vec![TEST_AUTHORITY.to_owned()]));
    let temporary = must(TempDir::new());
    let receipt_seed = [53_u8; 32];
    let profile = profile_fixture(
        must("127.0.0.1:9".parse()),
        certified.cert.der().as_ref().to_vec(),
        &temporary,
        [51_u8; 32],
        [52_u8; 32],
        receipt_seed,
    );
    assert_eq!(
        sign_receipt(receipt_fixture(&profile), &profile, [54_u8; 32]),
        Err(ModelError::CredentialBindingMismatch)
    );

    let mut invalid = receipt_fixture(&profile);
    invalid.deployment_performed = true;
    assert_eq!(
        sign_receipt(invalid, &profile, receipt_seed),
        Err(ModelError::InvalidReceipt)
    );
}

#[test]
fn build_marker_validation_rejects_unpinned_or_ambiguous_provenance() {
    let valid = PreflightRunnerBuildMarker {
        schema_version: PREFLIGHT_BUILD_MARKER_SCHEMA_VERSION,
        component: "accordlock-preflight-runner".to_owned(),
        protocol_version: PREFLIGHT_PROTOCOL_VERSION,
        binary_sha256: digest(b"runner-binary"),
        source_commit: "b".repeat(40),
        dirty: false,
    };
    must(valid.validate());

    let mut zero_binary = valid.clone();
    zero_binary.binary_sha256 = Digest32::from_bytes([0; 32]);
    assert_eq!(zero_binary.validate(), Err(ModelError::InvalidBuildMarker));

    let mut uppercase_commit = valid.clone();
    uppercase_commit.source_commit = "A".repeat(40);
    assert_eq!(
        uppercase_commit.validate(),
        Err(ModelError::InvalidBuildMarker)
    );

    let mut wrong_component = valid.clone();
    wrong_component.component = "another-runner".to_owned();
    assert_eq!(
        wrong_component.validate(),
        Err(ModelError::InvalidBuildMarker)
    );

    let mut encoded = must(serde_json::to_value(valid));
    must(encoded.as_object_mut().ok_or("marker must be an object"))
        .insert("unexpected".to_owned(), json!(true));
    assert!(serde_json::from_value::<PreflightRunnerBuildMarker>(encoded).is_err());
}

#[derive(Clone)]
struct EndpointConfig<'a> {
    authority: &'a str,
    socket: SocketAddr,
    certificate_der: Vec<u8>,
}

fn run_eks_discovery_failure(
    eks_response: Vec<u8>,
) -> (SignedPreflightReceipt, PreflightProfile, Vec<String>) {
    const EKS_AUTHORITY: &str = "eks.us-east-1.amazonaws.com";
    const NOW: i64 = 200;
    let eks = spawn_tls_sequence(EKS_AUTHORITY, vec![eks_response]);
    let unused = must(generate_simple_self_signed(vec![
        "unused.preflight.test".to_owned(),
    ]));
    let unused_der = unused.cert.der().as_ref().to_vec();
    let temporary = must(TempDir::new());
    let build_seed = [101_u8; 32];
    let artifact_seed = [102_u8; 32];
    let receipt_seed = [103_u8; 32];
    let profile = integration_profile(
        EndpointConfig {
            authority: "unused.preflight.test",
            socket: must("127.0.0.1:9".parse()),
            certificate_der: unused_der.clone(),
        },
        EndpointConfig {
            authority: "api.ecr.us-east-1.amazonaws.com",
            socket: must("127.0.0.1:9".parse()),
            certificate_der: unused_der.clone(),
        },
        EndpointConfig {
            authority: EKS_AUTHORITY,
            socket: eks.socket,
            certificate_der: eks.certificate_der.clone(),
        },
        EndpointConfig {
            authority: "kubernetes.preflight.test",
            socket: must("127.0.0.1:9".parse()),
            certificate_der: unused_der,
        },
        &temporary,
        build_seed,
        artifact_seed,
        receipt_seed,
    );
    let candidate_digest = digest(b"eks-discovery-failure-candidate");
    write_trust_records(
        &profile,
        build_seed,
        artifact_seed,
        &"d".repeat(40),
        candidate_digest,
        NOW,
    );
    let command = preflight_command(&profile, candidate_digest);
    let receipt = must(run_preflight(
        &profile,
        credential_fixture(receipt_seed),
        &command,
        NOW,
    ));
    let requests = text_requests(eks.finish());
    (receipt, profile, requests)
}

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn integration_profile(
    github: EndpointConfig<'_>,
    ecr: EndpointConfig<'_>,
    eks: EndpointConfig<'_>,
    kubernetes: EndpointConfig<'_>,
    temporary: &TempDir,
    build_seed: [u8; 32],
    artifact_seed: [u8; 32],
    receipt_seed: [u8; 32],
) -> PreflightProfile {
    assert_eq!(ecr.authority, "api.ecr.us-east-1.amazonaws.com");
    assert_eq!(eks.authority, "eks.us-east-1.amazonaws.com");
    let build_public = SigningKey::from_bytes(&build_seed).verifying_key();
    let artifact_public = SigningKey::from_bytes(&artifact_seed).verifying_key();
    let receipt_public = SigningKey::from_bytes(&receipt_seed).verifying_key();
    let profile = PreflightProfile {
        schema_version: PREFLIGHT_SCHEMA_VERSION,
        profile_id: Uuid::from_u128(400),
        organization_id: "acme".to_owned(),
        environment_id: "production".to_owned(),
        actor_id: "accordlock://actor/release".to_owned(),
        executor_audience: "accordlock://runner/preflight".to_owned(),
        github: GitHubProfile {
            authority: github.authority.to_owned(),
            api_base_path: "/api/v3".to_owned(),
            socket_address: Some(github.socket),
            ca_certificates_der: vec![Base64Bytes(github.certificate_der)],
            owner: "acme".to_owned(),
            repository: "service".to_owned(),
            workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
            minimum_approvals: 1,
            maximum_response_bytes: 64 * 1024,
        },
        ecr: EcrProfile {
            registry_id: "123456789012".to_owned(),
            region: "us-east-1".to_owned(),
            repository: "acme/service".to_owned(),
            socket_address: Some(ecr.socket),
            ca_certificates_der: vec![Base64Bytes(ecr.certificate_der)],
            maximum_response_bytes: 64 * 1024,
        },
        eks_discovery: EksDiscoveryProfile {
            socket_address: Some(eks.socket),
            ca_certificates_der: vec![Base64Bytes(eks.certificate_der)],
            maximum_response_bytes: 64 * 1024,
        },
        kubernetes: KubernetesProfile {
            expected_endpoint: format!("https://{}", kubernetes.authority),
            socket_address: Some(kubernetes.socket),
            cluster_name: "primary".to_owned(),
            namespace: "production".to_owned(),
            deployment: "service".to_owned(),
            container: "service".to_owned(),
            maximum_response_bytes: 64 * 1024,
        },
        build_trust: TrustVerifierProfile {
            key_id: "build-key".to_owned(),
            public_key: Base64Bytes(build_public.as_bytes().to_vec()),
            records_directory: temporary.path().join("build"),
        },
        artifact_trust: TrustVerifierProfile {
            key_id: "artifact-key".to_owned(),
            public_key: Base64Bytes(artifact_public.as_bytes().to_vec()),
            records_directory: temporary.path().join("artifact"),
        },
        receipt: ReceiptVerifierProfile {
            key_id: "receipt-key".to_owned(),
            public_key: Base64Bytes(receipt_public.as_bytes().to_vec()),
            public_key_hash: Digest32::sha256(receipt_public.as_bytes()),
        },
        evidence_ttl_seconds: 120,
        maximum_source_age_seconds: 60,
        maximum_future_skew_seconds: 5,
        created_at: 1,
        expires_at: 1_000,
    };
    must(profile.validate());
    profile
}

fn write_trust_records(
    profile: &PreflightProfile,
    build_seed: [u8; 32],
    artifact_seed: [u8; 32],
    commit: &str,
    image_digest: Digest32,
    now: i64,
) {
    must(fs::create_dir_all(&profile.build_trust.records_directory));
    must(fs::create_dir_all(
        &profile.artifact_trust.records_directory,
    ));
    let build = must(sign_build_trust_record(
        BuildTrustPayload {
            schema_version: 1,
            key_id: profile.build_trust.key_id.clone(),
            repository: profile.github_repository(),
            workflow_ref: profile.github.workflow_ref.clone(),
            run_id: 99,
            commit_sha: commit.to_owned(),
            input_manifest_root: digest(b"hermetic-build-inputs"),
            output_digest: image_digest,
            issued_at: now - 10,
            expires_at: now + 100,
        },
        build_seed,
    ));
    let artifact = must(sign_artifact_trust_record(
        ArtifactTrustPayload {
            schema_version: 1,
            key_id: profile.artifact_trust.key_id.clone(),
            registry_id: profile.ecr.registry_id.clone(),
            region: profile.ecr.region.clone(),
            repository_name: profile.ecr.repository.clone(),
            image_digest,
            source_repository: profile.github_repository(),
            commit_sha: commit.to_owned(),
            source_run_id: 99,
            signature_valid: true,
            quarantined: false,
            issued_at: now - 10,
            expires_at: now + 100,
        },
        artifact_seed,
    ));
    must(fs::write(
        profile.build_trust.records_directory.join("99.json"),
        must(serde_json::to_vec(&build)),
    ));
    must(fs::write(
        profile
            .artifact_trust
            .records_directory
            .join(format!("{}.json", image_digest.to_hex())),
        must(serde_json::to_vec(&artifact)),
    ));
}

fn preflight_command(profile: &PreflightProfile, image_digest: Digest32) -> PreflightCommand {
    PreflightCommand::RunDeploymentPreflight {
        schema_version: PREFLIGHT_SCHEMA_VERSION,
        check_id: Uuid::from_u128(401),
        environment_id: profile.environment_id.clone(),
        environment_profile_hash: must(profile.digest()),
        pull_number: 7,
        actions_run_id: 99,
        image_digest,
    }
}

fn deployment_response(
    deployment_uid: Uuid,
    resource_version: &str,
    current_digest: Digest32,
) -> Vec<u8> {
    json_response(&json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "uid": deployment_uid,
            "resourceVersion": resource_version,
            "namespace": "production",
            "name": "service"
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "service",
                        "image": format!(
                            "123456789012.dkr.ecr.us-east-1.amazonaws.com/acme/service@{current_digest}"
                        )
                    }]
                }
            }
        }
    }))
}

fn eks_cluster_response(arn: &str, kubernetes_authority: &str, certificate_der: &[u8]) -> Vec<u8> {
    let pem = pem_certificate(certificate_der);
    json_response(&json!({
        "cluster": {
            "name": "primary",
            "arn": arn,
            "endpoint": format!("https://{kubernetes_authority}"),
            "certificateAuthority": {
                "data": STANDARD.encode(pem.as_bytes())
            }
        }
    }))
}

fn pem_certificate(certificate_der: &[u8]) -> String {
    let encoded = STANDARD.encode(certificate_der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(must(std::str::from_utf8(chunk)));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn text_requests(requests: Vec<Vec<u8>>) -> Vec<String> {
    requests
        .into_iter()
        .map(|request| must(String::from_utf8(request)))
        .collect()
}

fn assert_request(
    request: &str,
    request_line: &str,
    authority: &str,
    required_header: Option<&str>,
) {
    assert!(request.starts_with(request_line));
    assert!(request.contains(&format!("\r\nHost: {authority}\r\n")));
    if let Some(header) = required_header {
        assert!(request.contains(&format!("\r\n{header}\r\n")));
    }
}

fn profile_fixture(
    socket: SocketAddr,
    certificate_der: Vec<u8>,
    temporary: &TempDir,
    build_seed: [u8; 32],
    artifact_seed: [u8; 32],
    receipt_seed: [u8; 32],
) -> PreflightProfile {
    let build_public = SigningKey::from_bytes(&build_seed).verifying_key();
    let artifact_public = SigningKey::from_bytes(&artifact_seed).verifying_key();
    let receipt_public = SigningKey::from_bytes(&receipt_seed).verifying_key();
    let profile = PreflightProfile {
        schema_version: PREFLIGHT_SCHEMA_VERSION,
        profile_id: Uuid::from_u128(100),
        organization_id: "acme".to_owned(),
        environment_id: "production".to_owned(),
        actor_id: "accordlock://actor/release".to_owned(),
        executor_audience: "accordlock://runner/preflight".to_owned(),
        github: GitHubProfile {
            authority: TEST_AUTHORITY.to_owned(),
            api_base_path: "/api/v3".to_owned(),
            socket_address: Some(socket),
            ca_certificates_der: vec![Base64Bytes(certificate_der.clone())],
            owner: "acme".to_owned(),
            repository: "service".to_owned(),
            workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
            minimum_approvals: 1,
            maximum_response_bytes: 64 * 1024,
        },
        ecr: EcrProfile {
            registry_id: "123456789012".to_owned(),
            region: "us-east-1".to_owned(),
            repository: "acme/service".to_owned(),
            socket_address: Some(socket),
            ca_certificates_der: vec![Base64Bytes(certificate_der.clone())],
            maximum_response_bytes: 64 * 1024,
        },
        eks_discovery: EksDiscoveryProfile {
            socket_address: Some(socket),
            ca_certificates_der: vec![Base64Bytes(certificate_der)],
            maximum_response_bytes: 64 * 1024,
        },
        kubernetes: KubernetesProfile {
            expected_endpoint: format!("https://{TEST_AUTHORITY}"),
            socket_address: Some(socket),
            cluster_name: "primary".to_owned(),
            namespace: "production".to_owned(),
            deployment: "service".to_owned(),
            container: "service".to_owned(),
            maximum_response_bytes: 64 * 1024,
        },
        build_trust: TrustVerifierProfile {
            key_id: "build-key".to_owned(),
            public_key: Base64Bytes(build_public.as_bytes().to_vec()),
            records_directory: temporary.path().join("build"),
        },
        artifact_trust: TrustVerifierProfile {
            key_id: "artifact-key".to_owned(),
            public_key: Base64Bytes(artifact_public.as_bytes().to_vec()),
            records_directory: temporary.path().join("artifact"),
        },
        receipt: ReceiptVerifierProfile {
            key_id: "receipt-key".to_owned(),
            public_key: Base64Bytes(receipt_public.as_bytes().to_vec()),
            public_key_hash: Digest32::sha256(receipt_public.as_bytes()),
        },
        evidence_ttl_seconds: 120,
        maximum_source_age_seconds: 60,
        maximum_future_skew_seconds: 5,
        created_at: 1,
        expires_at: 1_000,
    };
    must(profile.validate());
    profile
}

fn credential_fixture(receipt_seed: [u8; 32]) -> CredentialBundle {
    must(serde_json::from_value(json!({
        "schema_version": 1,
        "github_token": "github-test-token",
        "aws_access_key_id": "AKIATESTACCESS",
        "aws_secret_access_key": "test-secret-access-key-material",
        "aws_session_token": "test-session-token",
        "runner_master_seed": URL_SAFE_NO_PAD.encode([61_u8; 32]),
        "receipt_signing_seed": URL_SAFE_NO_PAD.encode(receipt_seed),
    })))
}

fn eks_enrollment_request() -> EksEnrollmentRequest {
    EksEnrollmentRequest {
        account_id: "123456789012".to_owned(),
        region: "us-east-1".to_owned(),
        cluster_name: "primary".to_owned(),
    }
}

fn eks_enrollment_credentials() -> EksEnrollmentCredentials {
    must(serde_json::from_value(json!({
        "aws_access_key_id": "AKIATESTACCESS",
        "aws_secret_access_key": "test-secret-access-key-material",
        "aws_session_token": "test-session-token"
    })))
}

fn receipt_fixture(profile: &PreflightProfile) -> UnsignedPreflightReceipt {
    UnsignedPreflightReceipt {
        schema_version: PREFLIGHT_SCHEMA_VERSION,
        check_id: Uuid::from_u128(201),
        request_id: Uuid::from_u128(202),
        environment_id: profile.environment_id.clone(),
        environment_profile_hash: must(profile.digest()),
        runner_id: Uuid::from_u128(203),
        runner_registration_hash: digest(b"runner-registration"),
        dispatch_hash: digest(b"dispatch"),
        policy_decision_hash: None,
        outcome: PreflightOutcome::Indeterminate,
        reason_codes: vec!["UPSTREAM_UNAVAILABLE".to_owned()],
        candidate: CandidateReceipt {
            repository: profile.github_repository(),
            pull_number: 7,
            commit_sha: "a".repeat(40),
            workflow_ref: profile.github.workflow_ref.clone(),
            actions_run_id: 99,
            ecr_repository: profile.ecr_image_repository(),
            image_digest: digest(b"candidate-image"),
        },
        target: TargetReceipt {
            cluster_identity: profile.expected_cluster_arn(),
            cluster_endpoint: profile.kubernetes.expected_endpoint.clone(),
            cluster_ca_hash: digest(b"cluster-ca"),
            namespace: profile.kubernetes.namespace.clone(),
            deployment: profile.kubernetes.deployment.clone(),
            deployment_uid: Uuid::from_u128(204).to_string(),
            resource_version: "12345".to_owned(),
            container: profile.kubernetes.container.clone(),
            observed_image_digest: digest(b"current-image"),
        },
        checks: [
            CheckKind::CodeReview,
            CheckKind::Build,
            CheckKind::Image,
            CheckKind::Target,
        ]
        .into_iter()
        .map(|kind| CheckReceipt {
            kind,
            status: CheckStatus::Indeterminate,
            summary: "Evidence could not be completed.".to_owned(),
            reason_code: Some("UPSTREAM_UNAVAILABLE".to_owned()),
            observed_at: None,
            freshness_seconds: None,
            evidence_reference: None,
        })
        .collect(),
        evidence_root: None,
        evaluation_attestation: None,
        started_at: 200,
        completed_at: 201,
        valid_until: None,
        effect: Effect::None,
        deployment_performed: false,
    }
}

fn digest(value: &[u8]) -> Digest32 {
    Digest32::sha256(value)
}
