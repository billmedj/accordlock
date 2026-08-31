# AccordLock local live Kubernetes slice

This directory contains a fail-closed `kind` exhibit for the fixed
`DEPLOY_EKS_IMAGE_V1` profile. It uses a real Kubernetes Deployment object but
synthetic review, build, artifact, and target attestations signed with public,
deterministic local test keys.

It does not demonstrate production evidence collection, durable consumption,
key custody, EKS behavior, performance, practical utility, or external review.

## Quick start

This demonstration needs no AWS account and no real credential. On Windows,
install PowerShell 7, a running Linux-container Docker engine using cgroup v2,
`kubectl`, and the repository-pinned Rust toolchain. Kubernetes 1.35
does not start on cgroup v1; the runner checks this before any cluster mutation.
Install the reviewed kind v0.32.0 Windows binary into the ignored repository
cache, then run from the repository root:

```powershell
pwsh -NoProfile -File .\infra\local\k8s\install-kind.ps1
pwsh -NoProfile -File .\infra\local\k8s\run-live.ps1
```

The installer refuses to replace an existing binary and verifies the official
Windows AMD64 asset against SHA-256
`0bcb2d1cfedc1912d664014db716937e8a0e843e91c6807b4db2025dbc8989fa`.
The runner independently refuses any kind version other than v0.32.0. A kind
binary already installed on `PATH` is used only when `.local/bin/kind.exe` is
absent, and is subject to the same version check.

The command creates or reuses only the `accordlock` kind cluster. It never
replaces a mismatched cluster unless `-RecreateCluster` is supplied. Success is
recorded under `.local/live-k8s/runs/<run-id>/success.json`; any failed stage
produces `failure.json` and a retained command log.

Native commands remain time-bounded. On a host where security scanning or cold
disk I/O delays process startup, `-TimeoutScale 2` through `-TimeoutScale 6`
multiplies those bounds without changing the profile or skipping a check. The
selected scale is recorded in run metadata and every command event.

## Static lock check

The repository includes a standard-library-only test that catches drift among
the installer, runner, manifests, and digest locks without Docker or a cluster:

```powershell
python -m unittest discover -s .\infra\local\k8s -p 'test_*.py' -v
```

This check does not replace the live server-side dry run or effect validation.

## Current mediation boundary

The runner is not wired through `accordlock-dispatch`. After the local authorization is
consumed, the PowerShell process invokes `kubectl patch` with its existing
credential. It does not create the durable dispatch claim, commit
`ATTEMPT_IN_FLIGHT`, receive an `AuthorizedProviderAttempt`, or use an exclusive
credential broker and executor. This exhibit therefore tests authorization and
Kubernetes mutation plumbing separately. It does not establish complete
mediation, and the `kubectl` credential remains a direct bypass route.

The command and provider-request commitments computed by `accordlock-k8s` bind
the intended method, resource path, content type, and compact patch body. The
repository contains separate native executor and transport components, but this
runner does not invoke them and does not prove the exact transport bytes sent
by `kubectl`.

## What the runner does

`run-live.ps1` performs this sequence without skipping failed steps:

1. Require a reachable Docker daemon using cgroup v2 plus `kubectl`, Cargo, and
   `kind`. An incompatible cgroup v1 host is refused before cluster mutation.
2. Inspect the `accordlock` kind cluster and `kind-accordlock` kubeconfig context.
3. Refuse an incomplete or mismatched existing cluster. The runner verifies one
   running control-plane container, the pinned node image, kind ownership
   labels, the kubeconfig target, the Kubernetes node identity, and Ready state.
4. Create the cluster only when neither the cluster nor context exists. Delete
   and recreate it only when `-RecreateCluster` is explicitly supplied.
5. Refuse to modify an existing `accordlock-demo` namespace or `payments`
   ServiceAccount/Deployment unless all objects have the expected profile
   ownership label and the Deployment has the exact one-container shape.
6. Apply the pinned namespace and Deployment manifests, wait for the baseline,
   then re-inspect ownership and the fixed runtime shape before signing any
   snapshot.
7. Read the live Deployment, including its UID, resourceVersion, current image,
   reserved annotations, and complete object snapshot.
8. Invoke `accordlock live prepare`. The CLI constructs signed synthetic evidence,
   evaluates it in the kernel, signs the evaluation, issues and verifies a
   authorization, consumes it once through the selected state backend, and derives the
   exact JSON Patch from the signed template. The CLI writes the compact patch
   bytes directly, without PowerShell re-serialization or a trailing newline.
   The default is `InMemoryStore`;
   an explicit PostgreSQL mode verifies durable receipt and execution-outbox
   references.
9. Read the generated patch file once into process memory, submit that value as
   `--dry-run=server`, and validate the resulting admission candidate.
   Deterministic admission mutations outside the authorization are therefore rejected
   before persistence. The diagnostic pathname is not reopened as an execution
   input after this point.
10. Submit the same in-memory JSON Patch value with Kubernetes `test`
    preconditions.
11. Invoke `accordlock live validate` on the persisted PATCH response, before
    asynchronous controllers can create later state transitions. The CLI
    re-verifies both COSE signatures, all evaluation-to-authorization and receipt
    bindings, the original snapshot hash, the recomputed patch, and the
    persisted-response effect projection. `resourceVersion` must advance,
    `generation` must increment once, and `status`, creation state, deletion
    state, identity, desired state, and non-reserved annotations must otherwise
    remain exact. `managedFields` is explicitly outside this projection. In
    PostgreSQL mode it also reloads and re-verifies the exact stored receipt and
    pending outbox record.
12. Require every exported persisted-response validation flag, then create
    `validation.json`.
13. Wait for rollout, then query the eventual Deployment plus exhaustive
    ReplicaSet and Pod lists for the fixed `app=payments` Deployment selector.
    Authorization only declared Deployment-controller bookkeeping changes. Require the
    exact desired state, unchanged generation, authorization-bound image and
    annotations, observed rollout readiness, exactly one current ReplicaSet
    reproducing the Deployment template, zero-scaled historical ReplicaSets,
    exact Deployment UID ownership on every ReplicaSet, exact current
    ReplicaSet name and UID ownership on every Pod, a common controller template
    hash, and unchanged workload-bearing Pod fields. The three Kubernetes reads
    are sequential, so a controller race produces a failed consistency check,
    not an atomic snapshot claim.

Every native command has a bounded timeout. The runner prints timestamped stage
and command events. It does not attempt to restart Docker, repair kubeconfig, or
silently replace a cluster that it cannot identify.

## Run and retained diagnostics

From PowerShell at the repository root:

```powershell
& .\infra\local\k8s\run-live.ps1
```

Each invocation receives a fresh UTC-labelled directory with a random suffix;
an existing directory is never reused:

```text
.local/live-k8s/runs/<UTC timestamp>-<random id>/
```

It contains:

- `run-metadata.json`;
- `runner.log` with timestamped stages;
- `command-events.jsonl` with arguments, duration boundary, and exit status;
- one stdout and stderr log for every native command;
- `failure.json` on failure, or `success.json` on success;
- the before, session, exact patch body, PATCH response, eventual Deployment,
  exhaustive ReplicaSet and Pod lists, dry-run candidate validation,
  persisted-response validation, and eventual-effect validation artifacts as
  they become available.

Persisted-response validation happens before the asynchronous rollout check, so
a late failure may leave both `failure.json` and `validation.json`. A successful
claim is valid only for a run directory containing `success.json`,
`candidate-validation.json`, `validation.json`, `effect-validation.json`, and no
`failure.json`. Artifacts from earlier runs are retained and must not be treated
as evidence for a later failed invocation.

The runner never rolls back or deletes a cluster automatically after a failure.
`failure.json` records whether cluster mutation had started, and the log emits a
warning when manual inspection may be required. This preserves forensic state
and avoids an unsafe cleanup racing with an unknown failure.

## Optional durable PostgreSQL consumption

The default mode remains the bounded in-memory exhibit. To use PostgreSQL, put
the connection URL in a process environment variable and pass only that
variable's name:

```powershell
$env:ACCORDLOCK_LIVE_POSTGRES_URL = '<connection material>'
& .\infra\local\k8s\run-live.ps1 -StateBackend postgres
```

To run the repository migration before the durable consumption:

```powershell
& .\infra\local\k8s\run-live.ps1 `
  -StateBackend postgres `
  -MigratePostgres
```

`-PostgresUrlEnv ANOTHER_ENV_NAME` selects a different variable. The runner
records the variable name and requested backend, never its value. PostgreSQL
mode fails before Docker access if that variable is absent or empty. A
successful durable session must report `state_backend: "POSTGRESQL"`,
`durable_consumption: true`, a non-nil database `state_instance_id`, nonempty
receipt and outbox references, and a `PENDING_WITNESS` outbox status. Its
validation must additionally reload the same database identity and report
`state_records_reverified: true`. The in-memory mode must report
`state_backend: "IN_MEMORY"`, `durable_consumption: false`, and a null
`state_instance_id`.

Both persisted-response validation commands require an explicit trusted
`--state-backend`; they do not choose whether to reload PostgreSQL from the
mutable backend label inside `session.json`. A mismatch fails before database
access or effect validation.

## Explicit recreation

To deliberately delete and recreate only the named local `accordlock` cluster:

```powershell
& .\infra\local\k8s\run-live.ps1 -RecreateCluster
```

The destructive behavior is restricted to the explicit `accordlock` kind cluster
and occurs only when `-RecreateCluster` is supplied. Without that switch, any
cluster/context mismatch, stopped node, unexpected image, wrong ownership
label, or incompatible demo Deployment causes a refusal with retained
diagnostics.

## Direct CLI use

The current run directory is printed at runner startup. To prepare manually from
a captured JSON file:

```powershell
.\target\debug\accordlock.exe live prepare `
  --deployment .\.local\live-k8s\runs\<run-id>\before.json `
  --new-image docker.io/library/nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236 `
  --session-out .\.local\live-k8s\runs\<run-id>\session.json `
  --patch-out .\.local\live-k8s\runs\<run-id>\patch.json
```

Standard input is accepted by passing `--deployment -`. Validation accepts
`--after -` in the same way.

## Admission and controller boundary

The server-side dry-run is a preflight, not an atomic enforcement point. A
nondeterministic admission component could behave differently on the real
request. The actual persisted response is therefore validated again, but that
second check is detection after persistence. Production prevention requires a
validating admission component on the actual request path.

The synchronous persisted-response projection treats a change to
`metadata.annotations["deployment.kubernetes.io/revision"]` as unauthorized.
The runner validates that response as the exact persisted effect, except for the
API-server fields listed above. It does not misclassify later
Deployment-controller revision, status, resourceVersion, or managedFields
updates as admission mutations. Generation remains exact because controller
reconciliation is not a spec change. After rollout a second projection rejects
every other Deployment delta and validates the exact
Deployment-to-ReplicaSet-to-Pod ownership chain and active Pod workload fields
against the persisted template. `validate-effect` requires both
`--replica-sets` and `--pods`; the eventual-effect JSON schema is version 2 and
exports `rollout_ownership_valid`. A production effect receipt still needs an
independently reviewed provider profile and observation path; this local exhibit
does not claim to provide one.

## Test keys

The seeds are visible in `crates/accordlock-cli/src/live_k8s.rs`, and the session
labels them `LOCAL_DETERMINISTIC_TEST_KEYS_ONLY`. They provide reproducible
cryptographic plumbing, not secrecy or production trust anchors.
