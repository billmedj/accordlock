# Deployment Preflight

**Status:** runner, Desktop handoff and CI evidence import implemented; real-account validation pending  
**Scope:** GitHub pull request and GitHub Actions build to AWS ECR image to one
Kubernetes Deployment  
**Effect:** read-only

## Product contract

Deployment Preflight answers one question:

> Do the approved source commit, successful build, immutable image and current
> deployment target still agree?

It returns an auditable result and performs no deployment.

The first release is intentionally narrow. It verifies one candidate against
one saved environment. It does not merge code, start a workflow, push an image,
change a cluster, run a shell command or grant general network access.

Every result must state:

> No deployment was performed.

## Availability and evidence level

The repository now contains a dedicated `accordlock-preflight-runner` binary.
It implements bounded authenticated reads for GitHub, AWS ECR, AWS EKS and
Kubernetes, projects their responses through the strict provider adapters, collects four
signed evidence assertions, evaluates them in the deterministic kernel and
returns an Ed25519-signed read-only receipt.

This is implementation evidence, not real-account release evidence. Until the
disposable real-account runs in this document are complete:

- the desktop must not display a provider as **Connected**;
- documentation must not describe this flow as available against a real
  account or cluster; and
- fixture-based demonstrations must be labelled **Demo data**.

This distinction is part of the product contract, not a release-note detail.

## What one preflight verifies

One check joins four authenticated observations:

1. **Code review** — the named pull request resolves to the expected repository
   and commit, and the configured review rule is satisfied.
2. **Build** — the named GitHub Actions run succeeded, consumed that exact
   commit and produced an authenticated attestation for the candidate image
   digest.
3. **Image** — the exact `sha256:` digest exists in the configured ECR
   repository and the configured trust source reports its signature and
   quarantine state.
4. **Target** — the EKS-authenticated cluster ARN, endpoint and CA plus the
   configured Kubernetes Deployment, immutable UID,
   `resourceVersion`, container and current image still match the state bound
   to the check.

The result passes only when all four observations are authenticated, fresh and
mutually consistent. A normal GitHub Actions run record is not a build
attestation. An ECR lookup is not proof of signature validity. Those facts must
come from explicitly configured trust sources.

## User journey

### 1. An administrator saves an environment

In **Settings → Connections**, the administrator creates one bounded
environment containing:

- one GitHub organization, repository and workflow;
- one AWS account, region and ECR repository;
- one AWS account, commercial region and EKS cluster name;
- one endpoint pin enrolled automatically from authenticated EKS discovery,
  plus the namespace, Deployment and container; and
- the review, build, image-trust and evidence-freshness rules for that
  environment.

The administrator never pastes a Kubernetes API hostname, CA or bearer token.
Enrollment performs an authenticated EKS lookup, displays the resolved
account, region, cluster ARN and endpoint for confirmation, and stores the
endpoint as a hidden pin. The runner obtains the current CA from the same
authenticated lookup and derives a fresh, cluster-bound EKS credential from
the AWS identity for every check.

The environment is immutable to ordinary task users. Changing any route,
trust source or rule creates a new environment version and profile hash.

### 2. The release workflow produces signed build proof

The protected GitHub Actions release job runs the dependency-free AccordLock
evidence action after the image has been built, published and checked. The
action creates one JSON package that binds:

- the saved AccordLock environment;
- repository, workflow, run and commit;
- ECR account, region, repository and immutable image digest; and
- the build-input commitment plus the workflow's image-signature and
  quarantine results.

The package contains no private signing seed. The build and artifact authority
seeds remain separate protected GitHub Environment secrets.

### 3. An administrator imports the build proof

In **Settings → Connections**, the administrator chooses **Add build proof**
for a new environment or **Import build proof…** for a later run, then selects
the JSON package.

AccordLock verifies the package locally, checks every route against the saved
environment and opens a native confirmation showing the repository, workflow,
run, commit, image and both public-key fingerprints. On first import, confirming
pins those two CI authorities. A later package with different keys is rejected;
rotation requires a separate explicit workflow.

The first import is a trust-on-first-use event. The administrator should compare
the displayed fingerprints with the public enrollment values retained from the
one-time authority setup or another trusted channel. A self-contained signed
package proves integrity under its included keys; it does not by itself prove
who owns those keys.

The verified build and artifact records are written before their authority is
activated. A crash can therefore leave unused records, never a trusted key with
missing evidence. Re-importing the same package is safe and idempotent.

### 4. A project owner binds the environment

In project settings, the owner selects the saved environment. Tasks may refer
to that environment by its internal identifier. They may not replace its
hosts, repositories, cluster route, namespace or policy.

### 5. A user starts a check

The user chooses **Verify deployment** and supplies only:

- a pull-request URL from the saved repository;
- a GitHub Actions run URL from the saved workflow; and
- an immutable ECR image digest in canonical `sha256:<64 lowercase hex>` form.

The application parses the URLs into provider identifiers. It never follows a
user-supplied URL and never uses it as a network destination. Mutable image
tags such as `latest` are rejected before any provider call.

The selected Kubernetes target is shown for confirmation but cannot be edited
inside the check.

### 6. The trusted runner observes and evaluates

The runner refreshes the exact Deployment identity and pre-state through its
saved Kubernetes route. The control plane then creates one short-lived,
credential-free observation dispatch. After authenticating and validating the
dispatch, the runner performs four bounded reads and returns signed evidence
to the deterministic evaluation kernel.

No provider is contacted before the dispatch, runner registration,
environment version and policy bindings pass validation.

### 7. The user receives one result

The UI returns exactly one of:

- **Checks passed** — all required observations agree at the recorded time;
- **Deployment blocked** — authenticated evidence proves a policy violation or
  mismatch; or
- **Couldn't verify** — the system could not establish a trustworthy answer.

The first result is not a deployment authorization and is not a prediction
that a later deployment will succeed. A change to the pull request, run,
digest, target state, policy or environment requires a new check.

## Trust boundaries

```text
desktop renderer / model
        |
        | selectors only
        v
trusted desktop control plane
        |
        | fixed environment + short-lived dispatch
        v
customer-controlled preflight runner
        |
        | authenticated, bounded provider reads
        v
GitHub + GitHub Actions | AWS ECR + trust source | Kubernetes API
        |
        | strict provider projections
        v
evidence collector -> deterministic evaluation -> audit receipt
```

### Desktop renderer and model

Untrusted. They may select a saved environment and provide the three candidate
identifiers. They may not supply or override:

- credentials, tokens, certificates or request headers;
- provider hosts, URLs, methods or redirect behavior;
- repository, workflow, account, region, cluster, namespace or Deployment
  authority;
- approval status, build result, signature result, quarantine status or target
  state;
- trusted time, evidence age, policy, verdict or reason code; or
- Deployment UID or `resourceVersion`.

### Trusted desktop control plane

Loads the saved environment, validates selectors and constructs the bounded
dispatch. It does not make cloud calls and does not expose credentials to the
renderer.

### Preflight runner

Part of the trusted computing base. It owns provider sessions, TLS roots,
trusted time, environment routes, replay protection and authenticated
transport implementations. It accepts typed read requests only. It exposes no
generic HTTP client, shell, cloud CLI or arbitrary MCP/network authority.

Production replay and monotonic-observation state must survive runner restarts.
The current in-process connector checkpoint is not sufficient for that claim.

### Provider adapters and evidence collector

Provider adapters validate minimal source-specific response projections. The
collector binds the repository, commit, run, digest and target across all four
observations, checks freshness and signs the resulting assertions. Neither
layer decides policy.

### Evaluation kernel

Evaluates only verified evidence and activated internal policy. It is
deterministic and performs no provider I/O.

### Audit and UI

Read-only projections of the result. A displayed status is not execution
authority and cannot be replayed as permission to mutate a provider.

## Credential ownership

Credentials belong to the customer-controlled runner, not to the model,
renderer, task record, dispatch or audit receipt.

| Provider | Required authority | Explicitly forbidden |
|---|---|---|
| GitHub | A GitHub App installation or equivalent fine-grained credential limited to the saved repository, with read access to repository metadata, pull requests and reviews, Actions runs and authenticated build attestations | Merge, push, issue write, workflow dispatch, repository administration and access to other repositories |
| AWS ECR | A workload role limited to exact read operations for the saved account, region and repository, plus a configured read-only source for signature and quarantine facts | Image push, delete, retag, repository-policy change, IAM administration and caller-selected regions or endpoints |
| AWS EKS | The same workload role, allowed only to call `eks:DescribeCluster` for the saved cluster ARN | Cluster mutation, access-entry mutation, arbitrary cluster enumeration and caller-selected regions or endpoints |
| Kubernetes | The AWS identity mapped to RBAC that allows `get` on one named `apps/v1` Deployment in one namespace through the authenticated EKS endpoint | Stored bearer tokens, `list`, `watch`, `create`, `update`, `patch`, `delete`, `exec`, secret reads and cluster administration |

Secrets must be stored through the operating-system secret store for a local
runner or the organization's workload-identity and secret-management system
for a remote runner. They must never appear in logs, debug output, serialized
protocol records, crash reports or exports.

Connection tests use the same bounded read path as a preflight. A generic
“credentials accepted” probe is not enough to mark an environment connected.

## Exact result contract

Every completed request produces one immutable signed envelope. Decision data
lives under `payload`; signature metadata remains outside it:

```json
{
  "payload": { "schema_version": 2, "effect": "NONE", "deployment_performed": false },
  "receipt_hash": "sha256:...",
  "signer_key_id": "...",
  "receipt_public_key_hash": "sha256:...",
  "signature": "..."
}
```

The serialized schema may evolve before 1.0, but a release implementing this
contract must contain the following fields and meanings inside `payload`
unless the table explicitly names an envelope field:

| Field | Required meaning |
|---|---|
| `schema_version` | Version of the preflight receipt schema |
| `check_id` | Unique identifier for this check |
| `request_id` | Identifier bound across the four evidence lookups |
| `environment_id` | Saved environment identifier |
| `environment_profile_hash` | Commitment to the exact routes and rules used |
| `runner_id` and `runner_registration_hash` | Identity and enrolled capability set of the runner |
| `dispatch_hash` and `policy_decision_hash` | Commitments to the validated request and evaluation context |
| `outcome` | `PASSED`, `BLOCKED` or `INDETERMINATE` |
| `reason_codes` | Stable machine-readable reasons; never free-form provider errors |
| `candidate` | Repository, pull request, commit, workflow, run, ECR repository and immutable digest |
| `target` | Authenticated EKS cluster ARN, canonical endpoint, CA hash, namespace, Deployment, UID, `resourceVersion`, container and observed image digest |
| `checks` | Four entries: `CODE_REVIEW`, `BUILD`, `IMAGE` and `TARGET`, each with status, observation time, freshness limit and non-secret evidence reference |
| `evidence_root` | Commitment to the exact verified evidence set when evaluation occurred |
| `started_at`, `completed_at`, `valid_until` | Trusted timestamps for the observation window |
| `effect` | Always `NONE` for this vertical |
| `deployment_performed` | Always `false` |
| `evaluation_attestation` | Authenticated kernel evaluation for `PASSED` and `BLOCKED` outcomes |
| `receipt_hash` | Envelope commitment to the canonical payload |
| `signer_key_id`, `receipt_public_key_hash`, `signature` | Envelope fields binding the receipt to the installation's enrolled receipt key |

`INDETERMINATE` records contain the validated bindings and operational failure
stage but must not fabricate an evidence root or evaluation attestation. Fields
that could not be established use explicit non-passing unresolved values, and
all four checks remain `INDETERMINATE`; unresolved values are never treated as
observed facts or favorable defaults.

Schema v2 uses `schema_version: 2` for the public profile, preflight command
and signed receipt payload. The bounded EKS enrollment envelope and public
enrollment result use their own schema v1. The secret preflight credential
envelope, installation bootstrap envelope, packaged build marker and runner
protocol also remain v1 and are validated independently; none of their version
fields aliases the preflight schema version.

The receipt must not include raw provider bodies, response headers, access
tokens, certificates, kubeconfig content, credential identifiers, local secret
paths or unrestricted provider error text.

### Outcome rules

`PASSED` requires a complete verified evidence set and the kernel reason
`ALLOWED`.

`BLOCKED` requires authenticated evidence that establishes at least one stable
policy reason. The current kernel registry includes reasons such as:

- `REVIEW_NOT_APPROVED` and `REVIEW_COMMIT_MISMATCH`;
- `BUILD_FAILED` and `BUILD_COMMIT_MISMATCH`;
- `ARTIFACT_SIGNATURE_INVALID`, `ARTIFACT_QUARANTINED` and
  `TRANSFORM_OUTPUT_MISMATCH`;
- `TARGET_IDENTITY_MISMATCH` and `TARGET_STATE_MISMATCH`; and
- `EVIDENCE_STALE`, `ATTESTER_SCOPE_VIOLATION` and
  `AUTHORITY_EPOCH_MISMATCH`.

`INDETERMINATE` means no trustworthy policy answer was reached. The preflight
service needs a separate stable operational reason registry covering at least:

- `CONNECTION_NOT_READY`;
- `DISPATCH_INVALID`, `DISPATCH_EXPIRED` and `DISPATCH_REPLAYED`;
- `PROVIDER_AUTHENTICATION_FAILED`, `PROVIDER_UNAVAILABLE` and
  `PROVIDER_RESPONSE_INVALID`;
- `TRUST_SIGNAL_UNAVAILABLE`;
- `CLOCK_INVALID` and `STATE_UNAVAILABLE`; and
- `INTERNAL_ERROR`.

Operational failures must not be translated into kernel denial reasons. A real
negative signature verdict is `BLOCKED`; absence of an authoritative signature
verdict is `INDETERMINATE`.

## Failure behavior

| Condition | Result | Required behavior |
|---|---|---|
| Review, build, image or target evidence is an authenticated negative fact | `BLOCKED` | Preserve the fact and exact reason; perform no effect |
| The target UID, `resourceVersion`, container or current image changed while evidence was being collected | `INDETERMINATE` | Discard the incomplete evidence set and require a new check; never evaluate mixed target states |
| Provider timeout, outage, authentication failure, rate limit or ambiguous response | `INDETERMINATE` | Do not infer pass or policy failure; expose a safe retry action |
| Required build attestation, signature trust source or quarantine source is unavailable | `INDETERMINATE` | Do not synthesize a boolean |
| Dispatch is malformed, expired, replayed or bound to another runner/environment | `INDETERMINATE` | Make zero provider calls |
| Evidence is incomplete or cross-source identifiers do not join | `BLOCKED` only when authenticated evidence proves the mismatch; otherwise `INDETERMINATE` | Never return a partial pass |
| Response is lost after read-only collection | `INDETERMINATE` | Keep the original record and allow a fresh check; never claim a completed evaluation |

There is no “three of four passed” outcome. Individual rows may show what was
observed, but the top-level result remains indivisible.

## UI surfaces and copy

This vertical adds no new top-level navigation item.

### Settings → Connections

One compact environment card shows:

- environment name and version;
- GitHub repository and workflow;
- ECR account, region and repository;
- Kubernetes cluster, namespace, Deployment and container; and
- one status: **Not checked**, **Checking**, **Connected** or **Needs
  attention**.

Secrets are never rendered after entry. **Connected** is reserved for a real,
authenticated bounded-read test in the current environment version.

### Project settings

The project shows one field: **Deployment environment**. Changing it is an
administrative action and creates an audit event.

### Verify deployment sheet

Recommended copy:

- Title: **Verify deployment**
- Description: **Check that the approved code, build, image and current target
  still match.**
- Fields: **Pull request**, **Build run**, **Image digest**
- Read-only summary: **Target**
- Primary action: **Run checks**
- Secondary action: **Cancel**

Do not use “safe”, “secure”, “guaranteed”, “AI-approved” or “ready to deploy” as
the pass label.

### Result card

The card contains a plain-language title, four rows and one footer:

```text
Checks passed

Code review       Approved commit matches
Build             Successful run matches the commit
Image             Signed digest matches the build
Target            Deployment state is unchanged

Checked 14 seconds ago · Valid until 10:42 UTC
No deployment was performed.
```

For a denial, the title is **Deployment blocked** and the first actionable
reason appears under the affected row. For an operational failure, the title
is **Couldn't verify** and the action is **Try again** or **Fix connection**.

Technical identifiers, hashes, timestamps and evidence references remain
behind **View details**. **Export receipt** downloads a portable package with
the immutable receipt, redacted verification profile and public verification
keys. There is no **Deploy** button in this vertical.

## Implementation map

The smallest implementation should extend the existing boundaries instead of
adding a generic integration framework:

| Existing foundation | Role in this vertical |
|---|---|
| `crates/accordlock-runner-protocol/src/lib.rs` | `RunnerAction::ObserveSupplyChain`, environment binding, runner capabilities and short-lived dispatch validation |
| `crates/accordlock-runner-bridge/src/lib.rs` | Converts a validated observation dispatch into four canonical lookup identifiers |
| `crates/accordlock-runner-engine/src/lib.rs` | Authenticates the runner channel and coordinates read-only evidence collection |
| `crates/accordlock-provider-adapters/src/github.rs` | Strict GitHub review and Actions projections |
| `crates/accordlock-provider-adapters/src/ecr.rs` | Digest-only ECR projection and real trust-signal binding |
| `crates/accordlock-provider-adapters/src/kubernetes.rs` | Exact Deployment observation projection |
| `crates/accordlock-connectors/src/runtime.rs` | Four-source joins, freshness, monotonic checks and signed evidence |
| `crates/accordlock-kernel/src/lib.rs` | Deterministic policy evaluation |
| `schemas/reason-codes.json` | Current stable kernel denial reasons |

Implemented in the runner:

1. fixed-authority HTTPS with redirects disabled and bounded responses;
2. GitHub pull-review and Actions-run reads;
3. AWS ECR `BatchGetImage` signed with SigV4;
4. authenticated AWS EKS `DescribeCluster` discovery with exact ARN, endpoint
   and CA binding;
5. fresh `k8s-aws-v1` credentials derived from the same AWS identity, using an
   STS presign with `X-Amz-Expires=60`;
6. exact Kubernetes Deployment `GET` with pre-state drift detection;
7. signed build and artifact trust-record verification;
8. runner-engine, connector and deterministic-kernel composition; and
9. signed receipts, independent verification and package build markers.

Work still required for a production claim:

1. deploy the runner's implemented SQLite replay and trusted-time state on a
   protected local volume, and add durable connector-observation high-water
   state before multi-process production observation;
2. validate the protected desktop channel, first-use CI authority ceremony and
   installation-key bootstrap in a signed package;
3. retain redacted deterministic local-stub results;
4. run the real disposable GitHub, ECR and Kubernetes acceptance environment;
   and
5. complete an independent security review before a production claim.

The transport modules must not accept generic URLs, arbitrary methods, caller
headers, shell commands, cloud CLI arguments or MCP tool definitions.

## Acceptance tests

The feature is complete only when every test below passes.

### Zero-effect boundary

- The observation action has no representation for provider mutation.
- GitHub transport can perform only configured read operations.
- ECR transport can perform only exact digest-bound reads.
- Kubernetes transport can perform only `get` for the saved named Deployment.
- No test path invokes a shell, `git`, `gh`, `aws`, `kubectl`, generic HTTP or
  arbitrary MCP tool.
- A preflight always emits `effect: NONE` and
  `deployment_performed: false`.

### Dispatch and trust binding

- Invalid, expired, replayed or incorrectly signed dispatches produce zero
  provider calls.
- Runner, environment, registration, policy or profile substitution fails
  before provider calls.
- Renderer-supplied hosts, routes, policy facts, verdicts, timestamps, target
  UID and `resourceVersion` are rejected.
- Process restart does not reset replay or monotonic-observation protection.
- A pending dispatch left by a crash remains replay-blocking; operators cannot
  reinterpret storage uncertainty as proof that no work occurred.

### GitHub and build

- Wrong repository, workflow, pull request, head commit or run fails closed.
- Unresolved or insufficient review produces `REVIEW_NOT_APPROVED`.
- Failed, cancelled or commit-mismatched build produces the exact kernel reason.
- Missing, malformed or incomplete authenticated build attestation never
  becomes a successful build observation.
- Pagination, redirects, oversized responses, rate limits and schema drift are
  bounded and fail closed.

### ECR and image trust

- Tags are rejected before transport; only lowercase canonical SHA-256 digests
  reach ECR.
- Account, region, repository and digest substitution fails closed.
- Missing trust integration produces `INDETERMINATE`, not an invented
  signature or quarantine value.
- Authenticated invalid signature and quarantine facts produce the exact
  kernel denial reason.
- SigV4 and TLS identity are bound to the saved environment and are not
  caller-selectable.

### Kubernetes

- EKS discovery uses only `GET /clusters/<strict-name>` on the commercial
  regional AWS authority with SigV4 service `eks` and redirects denied.
- The authenticated response must contain the exact account, region, cluster
  name and ARN, and its canonical endpoint must match the enrollment pin.
- The response CA is decoded under strict size, PEM and certificate-count
  bounds and is the only trust root used for both Kubernetes reads.
- The request uses the authenticated endpoint and exact namespace, name and
  resource type.
- CA, server identity, cluster, namespace, Deployment, UID,
  `resourceVersion`, container or image substitution fails closed.
- Redirects, oversized bodies and invalid Kubernetes responses fail closed.
- The runner stores no Kubernetes bearer token. It creates a URL-safe,
  unpadded `k8s-aws-v1` token from a regional STS `GetCallerIdentity` presign,
  with `X-Amz-Expires=60` and signed `host;x-k8s-aws-id` headers.
- The resulting AWS identity must be mapped to Kubernetes RBAC that can get
  only the named Deployment; it cannot list Deployments, read Secrets or
  mutate any resource.

### Outcome and receipt

- A fully matching four-source fixture returns `PASSED` with `ALLOWED`.
- Each authenticated negative fact returns `BLOCKED` with the exact reason.
- Each transport, authentication, clock and state failure returns
  `INDETERMINATE` with no fabricated evaluation.
- No result reports partial success as a pass.
- Receipt hashes change when any decision-relevant field changes.
- Secrets and raw provider bodies never appear in serialization, `Debug`, logs,
  UI state, crash reports or exported receipts.
- The exported receipt verifies through an independent receipt verifier.

### UI and packaging

- The environment cannot show **Connected** when any live bounded-read test is
  missing or failed.
- Candidate URLs outside the saved repository and workflow are rejected
  locally.
- The result card always shows all four checks and **No deployment was
  performed.**
- There is no deployment control in the preflight surface.
- Packaged runner binaries and transport modules match the hashes or signatures
  expected by the desktop build.

### End-to-end release evidence

Before the product is described as connected or production-capable, retain:

- deterministic TLS-stub runs for pass, every denial class and every
  indeterminate class through the real runner, adapters, collector and kernel;
- one run against a private GitHub repository and real GitHub Actions build
  attestation;
- one run against a disposable ECR repository with the configured signature
  and quarantine trust source;
- one run against a disposable Kubernetes namespace or EKS sandbox;
- permission tests proving that every provider identity lacks mutation
  authority; and
- redacted, independently verifiable receipts for the successful check,
  representative blocks, stale target, credential denial and provider outage.

No fixture, screenshot or mocked response substitutes for this release
evidence.
