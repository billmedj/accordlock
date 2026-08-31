# AccordLock Deployment Preflight Runner

This crate implements one bounded, read-only product vertical:

> Verify that an approved GitHub commit, a successful GitHub Actions build, an
> immutable ECR image and one current Kubernetes Deployment still agree.

It performs no deployment and exposes no generic HTTP, shell or cloud-CLI
surface. Every receipt declares `effect: "NONE"` and
`deployment_performed: false`.

## Commands

- `check-stdio --profile <absolute-file> --state <absolute-directory>` reads
  one strict request-and-credentials envelope from its inherited stdin handle,
  then writes one signed receipt to stdout.
- `verify --profile <absolute-file>` reads one signed receipt from stdin and
  verifies its schema, payload hash and Ed25519 signature.
- `profile-hash --profile <absolute-file>` returns the authoritative profile
  and receipt-key commitments used by trusted desktop code.
- `init-installation-stdio` generates local runner and receipt seeds together
  with public receipt verification material on its inherited stdout handle.
- `discover-eks-stdio` reads one strict AWS enrollment envelope from inherited
  stdin, performs exactly one authenticated EKS `DescribeCluster` request, and
  writes only the authenticated cluster ARN, endpoint, and CA hash to stdout.
- `marker --binary <absolute-file> --source-commit <hex> [--dirty]` creates the
  public build-provenance sidecar for a packaged executable.

The trusted desktop parent spawns both local-only commands with anonymous
inherited pipes, captures bounded output in memory, encrypts installation
secrets immediately and zeroizes transient buffers. No named endpoint is
created, so another same-user process cannot race the secret channel.
Credentials never belong in argv, the public profile, renderer state or
receipts.

### Desktop EKS enrollment contract

The Desktop invokes `accordlock-preflight-runner discover-eks-stdio` without
arguments. It writes at most 16 KiB of UTF-8 JSON to the child's inherited
stdin and closes that handle:

```json
{
  "schema_version": 1,
  "request": {
    "account_id": "123456789012",
    "region": "us-east-1",
    "cluster_name": "production"
  },
  "credentials": {
    "aws_access_key_id": "...",
    "aws_secret_access_key": "...",
    "aws_session_token": "..."
  }
}
```

`aws_session_token` may be `null`. Unknown or non-canonical fields are
rejected. In particular, the input has no endpoint, URL, socket, CA, GitHub
token, runner seed, or receipt key. The runner derives
`eks.<region>.amazonaws.com`, uses its compiled exact `WebPKI` root corpus,
denies redirects, and bounds the AWS response to 256 KiB. It makes no
Kubernetes request.

On success, stdout contains at most 2 KiB and exactly this public schema:

```json
{
  "schema_version": 1,
  "cluster_arn": "arn:aws:eks:us-east-1:123456789012:cluster/production",
  "endpoint": "https://example.eks.amazonaws.com",
  "cluster_ca_hash": "sha256:..."
}
```

Desktop stores `endpoint` as the hidden v2 profile
`kubernetes.expected_endpoint` pin and may display the ARN and CA hash for
review. It never stores the enrollment credential envelope in the public
profile. Enrollment schema v1 is an independent protocol: it does not change
preflight schema v2, credential schema v1, installation schema v1, build-marker
schema v1, or protocol version 1.

## Provider authority

- GitHub is limited to the profile's DNS authority, repository, pull request
  and Actions run. Redirects are denied.
- ECR authority is derived as `api.ecr.<region>.amazonaws.com` and the request
  is an exact SigV4 `BatchGetImage` for one immutable digest.
- EKS authority is derived as `eks.<region>.amazonaws.com`. The runner signs an
  exact `GET /clusters/<name>` with SigV4, verifies the returned account,
  region, cluster ARN and previously enrolled endpoint, and accepts the
  returned certificate authority only from that authenticated response.
- Kubernetes is limited to `GET` on one named `apps/v1` Deployment. The
  runner uses the EKS-discovered endpoint and CA for both reads. It derives a
  fresh `k8s-aws-v1` token with a 60-second STS presign from the configured AWS identity;
  no Kubernetes bearer token is stored. The observed UID, `resourceVersion`,
  container and projection must not change between target discovery and
  evidence collection.

The v2 preflight profile, command and receipt schemas are separate from the v1
credential envelope, v1 EKS enrollment envelope, v1 build marker and protocol
version. Signed target receipts expose the authenticated cluster ARN,
canonical endpoint and CA hash.

Build and artifact trust booleans do not come from the model or from unsigned
request fields. They come from separately signed trust records under public
keys committed in the profile.

## Current release boundary

The implementation, protected Desktop handoff and deterministic TLS tests are
local evidence. A production claim still requires durable replay and
observation checkpoints across runner restarts, least-privilege permission
tests, a signed-package authority ceremony, redacted runs against disposable
GitHub, ECR and Kubernetes accounts, and an independent security review. See
[Deployment Preflight](../../docs/DEPLOYMENT_PREFLIGHT.md).
