# AccordLock local validation report — historical snapshot

> This report predates the AccordLock public-release cleanup. Product and
> identifier names were normalized later; the recorded results were not rerun
> against the current source tree. See this directory's README.

> Historical snapshot. Superseded by the dated 2026-08-16 product audit and
> reproduction report. Counts and implementation boundaries below describe the
> earlier local tree only.

**Date:** 2026-08-15  
**Status:** local engineering candidate, pre-G1  
**Repository state:** uncommitted local workspace; no remote release or immutable
source tag exists

`SOURCE_MANIFEST.sha256` records the SHA-256 of every non-ignored source file in
this snapshot. The manifest intentionally excludes itself, ignored build
outputs, local tools, and retained runtime artifacts.

## Outcome

The repository now contains an executable vertical slice for the fixed
`DEPLOY_EKS_IMAGE_V1` profile. It is no longer only a paper model or product
specification. The implemented local path is:

1. parse a strict, signed application request and derive tenant and actor from
   an ingress-key registry rather than from the proposal strings;
2. reject replay, unknown keys, invalid audience, expiry, identity mismatch,
   payload mutation, and unavailable replay state;
3. authenticate typed review, build, artifact, and target assertions;
4. recompute provenance standing and policy outcome in a deterministic kernel;
5. sign and verify a domain-separated evaluation;
6. issue and verify a short-lived action authorization bound to the deployment
   template and authority vector;
7. re-read authority and consume the authorization once in transactional state,
   including an opt-in PostgreSQL live path that reloads its receipt and outbox;
8. generate a Kubernetes JSON Patch bound to UID, resource version, prior
   image, container, and reserved annotations;
9. reject a post-admission object whose complete protected projection differs
   from the authorized projection.

This is evidence that the proposed interface can be made executable. It is not
evidence of production security, practical utility, market demand, independent
validation, or an Amazon EKS deployment.

## Implemented surfaces

| Surface | Local implementation | Current boundary |
|---|---|---|
| Protocol | Canonical CBOR arrays, typed records, exact authority vector, COSE Sign1 with Ed25519 and external-AAD domain separation | Provisional schema; no frozen interoperability release |
| Ingress | Strict signed request, registry-derived caller, audience/time/key checks, nonce replay guard, spoofing and unavailable-state rejection | Application signature only; replay state is in memory and no mTLS, workload identity, or network service exists |
| Kernel | Authenticated evidence verification, trust-source separation, deterministic policy and provenance evaluation, signed decision | Registered attester truth within its authorized scope remains trusted |
| State | In-memory and PostgreSQL adapters, exact authority recheck, monotone activation, single-use AUTHORIZATION_ID, grant accounting, durable time high-water, receipt and outbox; live prepare/validate can reverify PostgreSQL state | No complete production dispatch, crash recovery, replication, or failover protocol |
| Dispatch oracle | Physical-resource reservation, fenced lease, create-in-flight recovery, issuance and release checks, unknown-outcome quarantine, safe-expiry retention, and manual no-effect boundary | In-memory reference machine only; it accepts trusted time and provider-identity premises and performs no external operation |
| Kubernetes | Exact preconditioned patch and complete protected projection comparison | Fixed local profile; no account-backed EKS enforcement path |
| Differential exhibits | One positive flow and three adversarial scenarios compared with a deliberately basic policy baseline | Exhibits are marked `benchmark: false`; they are not empirical benchmark results |
| Conformance | Strict scenario corpus, negative JSON tests, field-mutation and cryptographic-domain tests | No independent implementation or external reproducer |
| Lifecycle model | Finite TLA+ model of issuance, authority rotation, expiry, consumption, replay, receipt, and outbox atomicity | Abstracts signatures, SQL, crashes, dispatch, admission, leases, and failover |

## Reproduced local results

The current source was checked with the pinned Rust toolchain and local
dependencies on 2026-08-15.

- `cargo fmt --all -- --check`: passed.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo test --workspace --locked`: 76 ordinary Rust tests passed; 3 opt-in
  PostgreSQL tests were ignored by this invocation as designed.
- The 3 PostgreSQL tests passed separately: serializable single-winner
  consumption, library live prepare/validate state, and the binary CLI path.
- `python -m unittest discover -s tests -v`: 8 tests passed.
- `python conformance/validate.py`: 7 scenario manifests and 18 legacy
  regression vectors passed strict structural validation; this does not execute
  them as CLI scenarios.
- `python scripts/validate_repository.py`: 11 JSON documents, 33 reason codes,
  and 13 CDDL/Rust canonical arrays passed consistency checks.
- Two executions of `accordlock-cli demo --scenario all` were byte-identical.
- TLC v1.7.4 explored 228 distinct states, generated 666 states to depth 10,
  and reported no invariant violation for the bounded model.

The ordinary Rust total includes 17 CLI tests, 5 conformance tests, 19 dispatch
tests, 12 ingress tests, 5 Kubernetes tests, 7 kernel tests, 3 protocol tests,
and 8 state tests. The separately activated PostgreSQL tests make 79 successful
Rust test executions across the two invocations.

## Differential scenarios presently demonstrated

| ID | Basic action policy | AccordLock result | Missing fact exposed |
|---|---|---|---|
| DP-000 | Allow | Allow, consume once, construct authorized patch | Positive control with complete local chain |
| DP-101 | Allow | Deny: `TRANSFORM_OUTPUT_MISMATCH` | Requested artifact is not the authenticated build output |
| DP-102 | Allow under stale cached approval | Deny current evaluation; reject old authorization at consumption | Review/authority state changed after authorization |
| DP-103 | Allow action | Reject post-admission object | A mutator inserted an unauthorized sidecar |

These are executable counterexamples to a basic action-and-identity policy.
They do not yet show that every named commercial baseline fails, nor establish
false-refusal or secure-utility rates.

## Material defects found and corrected during implementation

- Caller-supplied tenant or actor could have recreated the original trusted-fact
  injection defect. The kernel now takes a distinct `AuthenticatedCaller` and
  rejects proposal/context mismatch.
- The local ingress boundary now derives that caller from a registered Ed25519
  key, binds every proposal field, rejects replay, and fails closed when replay
  state is unavailable. This is not yet a network transport.
- Internally tagged evidence and attester-scope JSON accepted unknown fields.
  Strict deserialization and passing negative tests were added.
- The target projection commitment was present but not enforced by the kernel.
  A mismatch is now denied and covered by regression tests.
- The Kubernetes patch initially used a bare digest as an image value. It now
  emits the valid `repository@sha256:digest` form.
- Shell pipelines and infrastructure status checks could have reported green
  despite an upstream failure or the wrong PostgreSQL instance. The local
  runners now fail closed and the PostgreSQL helper cross-checks readiness,
  PID, and data directory.
- PostgreSQL originally stopped correctly while leaking the expected
  post-stop `pg_isready` exit code, causing a false runner failure. Cleanup now
  exits zero only after it proves the local server is down.
- The first dispatch oracle allowed a worker to resend bound-object creation
  after a crash and allowed credential retirement to stand in for proof of no
  prior effect. A distinct create-in-flight state now forces reconciliation,
  and unestablished no-effect claims remain in manual resolution. A separate
  internal AI-assisted re-audit found no remaining critical transition flaw
  within the oracle's stated premises.

These corrections are implementation evidence, not independent assurance.

## Explicitly not reproduced

- The Docker-backed `kind` runner did not complete. It now emits immutable
  per-run diagnostics and applies timeouts. Two non-destructive attempts ended
  at the bounded Docker preflight after 20 seconds, before any `kind` or
  `kubectl` command. The latest retained run contains `failure.json`, no
  `success.json`, and no `validation.json`; no live-cluster result is claimed.
- No AWS account, EKS cluster, IAM policy, KMS key, ECR assertion, GitHub App,
  GitHub Actions provenance, or production identity provider was exercised.
- No authenticated network transport, production connector, isolated signer,
  credential broker, executor, or complete crash/failover state machine exists.
- No AgentDojo, CaMeL, FIDES, OAP, AgentCore Policy, AGT, Cedar/AuthZEN, latency,
  false-refusal, secure-utility, or integration-cost benchmark was run.
- No customer workflow, paid pilot, external red team, cryptographic review, or
  independent reproduction exists.
- The current tests are authored and executed with extensive AI assistance and
  cannot be represented as independent validation.

## Next engineering frontier

The next local gate is not another paper and not a generic agent gateway. It is
to turn the current deterministic exhibit into one mediated deployment whose
security boundary survives a real process, database, and Kubernetes API:

1. execute the prepared `kind` run and preserve every input, signed object,
   admission response, rollout result, final projection, log, and hash;
2. terminate a real authenticated local transport into `accordlock-ingress`, and
   replace its memory replay guard with durable atomic state;
3. move the tested dispatch oracle into PostgreSQL transactions and connect its
   reservation, lease, in-flight, quarantine, and reconciliation phases to the
   live flow;
4. implement the isolated credential broker, one-shot executor handoff, exact
   provider request, and authenticated destination observations;
5. attack that boundary with crash, replay, aliasing, stale authority,
   admission mutation, credential-loss, and bypass tests;
6. only then replace synthetic assertions with one real GitHub, build, registry,
   and EKS evidence chain.

The actions that require accounts, customer access, or independent people are
tracked separately in the current `docs/ROADMAP.md`. They must not be marked complete
by local code or AI-generated review.
