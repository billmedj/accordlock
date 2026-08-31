# Local Readiness Report — 2026-08-30

## Scope

This report records what was reproduced on one Windows workstation without a
cloud account, provider credential, customer environment, or paid service. It
is local engineering evidence, not a production claim.

## Completed locally

### Execution lineage and task control

The agent runtime records and revalidates exact `ExecutionLineage` for every
completed controlled action. It commits the full validated chain:

1. approved task and policy epoch;
2. exact tool proposal and execution request;
3. exact pre-execution intent-evaluation hash;
4. authorization decision and consumed single-use authorization; and
5. completed execution record.

`ExecutionLineage` schema 2 stores commitments, bounded
task/session/workspace metadata, and trusted timestamps, not prompts, raw tool
arguments, command output, or provider credentials. It must still be handled
as sensitive local state. `TaskControlProjection` schema 2 carries the same
pre-execution evaluation hash. Audit schema v6 exposes the bounded projection
for access and review state, including whether it is lineage-bound or
reconstructed from a legacy record. It also derives categorical **Task check**
and **Task evidence** fields from the fully revalidated evaluation record.
`VERIFIED` requires at least one qualified evidence item and only supported
findings. Audit projection fails closed if a stored object, binding, timestamp,
or commitment is changed.

This is exact execution provenance. It is not a claim that the action preserves
the meaning of the user's request.

### Task-alignment records and provider boundary

The evaluation crate exposes two typed profiles. `PRE_EXECUTION` requires
request, plan, and action and cannot contain or invent a result.
`COMPLETE_TRACE` additionally requires an observed result. The selected profile
is bound through requests, evaluations, records, and canonical commitments.

`IntentConformanceRecord` schema version 2 is a strict, portable but untrusted
transport record. `verify_bindings_for` checks only replay and context
commitments. The authorization-sensitive path is `verify_evaluation_for`, which
re-runs the evaluator over the exact baseline decision, typed checkpoint,
requirements, transformations, evidence, ledger snapshot, trust policy, epoch
floors, and evaluation time. A self-consistent favorable record cannot replace
source evidence.

The request is a hash-only control plane. `EvidenceArtifactResolver` supplies a
separate `BoundedEvidenceMaterial` data plane, recomputes the committed bytes,
and enforces combined limits of 256 KiB for request, 512 KiB for plan, and
1 MiB for action or result. Missing or unavailable material maps to review;
scope, digest, oversize, resolver-policy, or disclosure failure maps to denial.
Raw bytes are redacted from debug output. Local-only material remains local.
`ALLOWLISTED_EXTERNAL` pins the provider, egress policy, provider trust root,
and egress-authority root. `ExternalEvidenceDisclosureGrant` schema version 1
is Ed25519/COSE signed and binds the exact request, task, trace, profile, stage,
provider, egress, provider root, challenge, authority key/root, and a maximum
300-second window. Verification yields an opaque, non-serializable capability.
`disclose_external` requires that capability and a trusted current time, and
rejects clock rollback or post-expiry use. The provider view exposes the exact
external scope.

The grant may be reused only inside its exact scope and window. One-shot use
requires an external atomic replay store. The library does not establish that
the declared network route or destination was enforced; that remains a live
egress-adapter or broker responsibility.

External response schema version 2 requires Ed25519/COSE verification of the
provider key ID and public-key trust root, fresh challenge, exact request and
response body, and issue/expiry interval capped at 300 seconds. Valid JSON
alone does not authenticate external evidence. The provider contract cannot
grant execution authority.

Goose now captures a bounded checkpoint from the actual assistant turn before
tool dispatch. It commits visible assistant text and ordered tool requests,
including each request ID, model-facing tool name, and argument digest. The
runtime combines that plan with the approved objective and exact proposal to
build and revalidate a pre-execution bundle. After execution it appends the
observed result digest and builds and revalidates the complete-trace bundle.
Both are durably persisted.

`AuthorizationDecision` schema 4 requires the digest of the exact
pre-execution record. `TaskControlProjection` schema 2 and `ExecutionLineage`
schema 2 repeat that commitment. The complete-trace digest remains
post-execution ledger and audit evidence; it does not retroactively grant
authority.

The connected runtime has no production `EvidenceArtifactResolver` or
`IntentEvidenceProvider`. Its evidence list is empty, so the evaluator returns
`REVIEW`; audit schema v6 projects that result as `REVIEW_REQUIRED`, and the
interface shows **Not verified**. The implementation records and revalidates
the integrity of the request-plan-action-result chain under its local inputs;
it does not prove that an action preserved the user's request.

### Rust implementation

`cargo test --workspace --locked --all-targets` completed successfully. Every enabled
workspace test passed. Tests that require a disposable PostgreSQL service
remain explicitly ignored in the ordinary run and were exercised separately
against the local database profiles below; helper process entries are also
intentionally ignored outside their parent tests.

The validated surface includes:

- typed pre-execution and complete-trace profiles, bounded evidence material,
  authenticated provider responses, and re-evaluated transport records;
- one-shot authorization and replay resistance;
- durable transaction, dispatch, revocation, recovery, and audit behavior;
- controlled filesystem, terminal, HTTPS, Kubernetes, ECR, EKS, and GitHub
  boundaries;
- Slack, Microsoft Teams, Telegram, and WhatsApp notification protocols;
- deterministic task-alignment and shared-resource policy evaluation; and
- failure, ambiguity, timeout, tamper, substitution, and concurrency cases.

The final Windows run also exposed and fixed a process-tree completion
deadlock. Leader-process polling no longer consumes the Job Object completion
notification needed to prove that the complete process tree has terminated.
The formerly blocked terminal integration test now completes in about five
seconds, and the full workspace suite passes with the fix.

### Formal specification

The standalone Lean project builds without placeholders or declared axioms. It
contains 81 theorems covering execution authorization, monotone transaction
state, intent preservation, resource reservations, replay resistance, audit
continuity, and end-to-end composition. Critical exported theorems were checked
with `#print axioms`.

These theorems establish properties of the formal definitions. They do not by
themselves prove that every operating-system, database, cloud, or user-interface
implementation detail refines those definitions.

### State-machine exploration

The pinned TLC 2.19 artifact was downloaded from the official release and
accepted only after its expected SHA-256 matched. Seven canonical TLA+
configurations and the complete single-acquisition search completed without an
invariant violation. The largest searches covered more than 20 million
generated states for the durable control queue and more than 3 million for
durable dispatch acquisition.

The single-acquisition run does not replace the intentionally expensive
two-acquisition or canonical three-acquisition searches. Those remain separate
deep-run evidence.

### Offline evaluation suite

AccordBench 0.3.0 is dependency-free and runs without network access. It
contains 73 strict JSONL cases, including 43 task-alignment cases and eight
explicit metamorphic relations, across transaction lifecycle, intent
preservation, shared resources, and safe autonomy. Its 24 schema, validator,
metric, and sensitivity tests pass.

The included fixture-oracle score is a scoring-pipeline self-check, not a model
or product performance claim. Independent annotation, calibration, live traces,
and representative customer distributions are still required.

### Desktop integration

The desktop audit projection consumes audit schema v6, exposes exact
execution-lineage, task-control, pre-execution evaluation, and complete-trace
commitments, and displays the bounded categorical results as **Task check** and
**Task evidence**. It distinguishes pre-authorized access from reviewed
actions, rejects invalid runtime data, and never converts an empty evidence set
into a verified result. The complete desktop suite passes 1,415 tests across
161 files, with 15 tests explicitly skipped. It was run in a single worker
under Node 24.19.0. After one publication-only comment edit, the affected
36-test suite, TypeScript type check, ESLint, Prettier, and the publication
guard also pass. Unrelated upstream workflows remain outside the public release
contract.

The existing Windows development package also passes the package-integrity
verifier: all 124 artifacts covered by the manifest match their recorded
digests. That package predates the 2026-08-30 source changes and does not contain
the current evaluation-record, execution-lineage, audit-v6, or
desktop-projection updates described in this report. A post-build inspection copy that was not
part of the package was moved intact to ignored recovery storage before
verification. Package integrity does not make it a current, signed, or
reproducible release build.

### Local Kubernetes profile

The repository now has a pinned, checksum-verified kind v0.32.0 installer and a
runner that refuses version drift before cluster mutation. Local results:

- installer and runner PowerShell parse: pass;
- local static profile checks: 4/4;
- Kubernetes admission tests: 12/12;
- EKS activation tests: 44/44.

The enterprise-runner path also has an account-free no-send exhibit. It
revalidates the exact authorized Deployment snapshot and its committed
preconditions, derives the compact JSON Patch with the request builder used by
the native executor, consumes the durable dispatch and approval replay slots,
and returns `NotSent`. A replay remains rejected after reopening the SQLite
runner state. The exhibit performs no provider I/O, obtains no credential, and
does not establish a Kubernetes or EKS deployment.

A real kind v0.32.0 cluster was created with the pinned Kubernetes 1.35 node
image. Its control-plane node reached `Ready`. The pinned namespace,
ServiceAccount, and Deployment baseline were applied, the baseline rollout
completed, and the runner revalidated the expected ownership labels and runtime
shape.

Two subsequent failure packages were retained. Neither reached the authorized
target patch:

1. `.local/live-k8s/runs/20260830T105008.927Z-1dbe59ae97d242038e1e9d68f9e88a65`
   records the successful cluster creation, node-health check, baseline rollout,
   and baseline revalidation. It then timed out while capturing the live
   pre-action Deployment, before preparation, server-side dry-run, or target
   mutation.
2. `.local/live-k8s/runs/20260830T111858.427Z-15036cff24194a42a8285fb1200b78ba`
   records a 120-second `docker info` timeout during the bounded Docker-access
   check. It stopped before any cluster mutation in that run.

The workstation blocker is a Docker Desktop 4.70.0 crash loop. A Docker Desktop
4.88.1 installer was downloaded and independently checked: its file and product
version are `4.88.1.237512`, its Authenticode signature from Docker Inc is valid,
and its SHA-256 is
`89fe3d80a326a2ad521de09b5a89ef04d10c60593604b344f11f433ca7f1f6f0`.
The upgrade did not complete because it stopped at the Windows UAC elevation
step. `LOCAL-001` therefore remains `OPEN`: no retained run contains the full
successful artifact set and a zero runner exit.

### Local PostgreSQL profile

A disposable PostgreSQL 17.4 cluster was initialized under the ignored local
project directory, bound only to `127.0.0.1:55432`, tested, and stopped cleanly.
The live run found and fixed reserved-word aliases in migration and runtime SQL,
then resynchronized the fail-closed catalog commitments with the final v14
schema.

Retained results:

- transactional and adversarial state suite: 61/61;
- bounded durable-control and dispatch suite: 23/23, with the separate
  257-entry deep scan excluded;
- v14 source and high-water guards: 3/3;
- real v13-to-v14 upgrade cases: 5/5; and
- durable CLI library and binary paths: 2/2.

The separate 257-entry scanner was also started against the disposable local
database. It compiled in 7.21 seconds and remained active without an error for
8 minutes 43 seconds, then was stopped to keep this verification pass bounded.
That attempt is neither a pass nor a failure; it requires a dedicated runner
with a materially longer timeout.

A second disposable profile was created on `127.0.0.1:55433` with a local test
CA, hostname verification, TLS 1.3, SCRAM-SHA-256, and required channel binding.
The profile refused a non-TLS connection, applied and validated all 14
migrations, passed its Rust integration test, and stopped cleanly. Its retained
proof has SHA-256
`e67567cab3a2153402ab3ac10dd04f76cd6e04e2310a9c64b44625b9a21abacf`.

### Repository hygiene

The repository validators reject retired internal terminology, private paths,
credentials, runtime artifacts, non-English product copy, malformed local
links, source-manifest drift, and inconsistent publication metadata. The source
manifest is regenerated only after the final local source set is stable.

## Still local, but blocked by workstation state

The following work needs no account and no paid service:

1. complete the verified Docker Desktop 4.88.1 upgrade with Windows UAC
   elevation;
2. rerun and retain one successful disposable kind evidence package;
3. run the two-acquisition and canonical three-acquisition state-space searches
   plus the 257-entry PostgreSQL scanner on a deliberate deep-run machine;
4. rebuild the desktop release package from a clean staging directory; and
5. reproduce the complete repository from a fresh local checkout once local
   commits exist.

## Claim boundary

The current codebase is a functional engineering alpha with a substantial
locally verified security core. It is not yet a production-ready enterprise
release. In particular, exact execution lineage must not be presented as a
live task-alignment guarantee. The assistant-turn plan and pre-execution evaluation
hash are now bound through authorization, task control, and execution lineage,
and a pinned local provider can qualify an explicit exact artifact digest.
That deterministic check establishes byte identity, not meaning. No production
resolver or qualified evidence provider supplies live natural-language
evidence. The open evidence gates are maintained in
[External evidence gates](EXTERNAL_GATES.md).
