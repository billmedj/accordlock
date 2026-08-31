# accordlock-evaluation

Native, provider-independent policy and intent-conformance primitives for
AccordLock. The crate records evidence and increases enforcement pressure; it
does not issue execution authority.

## Exact request-to-result traces

`IntentTrace` commits to one task's exact request, plan, action, and result plus
the ordered `TransformationStep` hashes joining them. Intermediate policy,
specification, execution, and observation steps are allowed. Verification
rejects a skipped or repeated mandatory checkpoint, a backwards transition, a
cross-task step, a substituted artifact, a broken parent hash, or an incomplete
path.

Every requirement and step is bound by deterministic, domain-separated CBOR.
Hashes provide identity and integrity only: matching hashes do not establish
that two texts have the same meaning.

### Safe runtime integration

`IntentTraceBuilder` is the preferred integration API. It is a typed state
machine: `start` accepts an exact task-bound request hash and requirement
statement hashes, then exposes only `append_plan`, `append_action`, and
`append_result` in that order. Each stage accepts a task-bound artifact hash and
timestamp. A cross-task artifact or timestamp rollback returns an error; a
skipped or reordered stage does not compile.

```rust
use accordlock_evaluation::{
    ActionArtifact, Digest32, IntentTraceBuilder, NormalizedScore, PlanArtifact,
    RequestArtifact, RequirementCommitment, ResultArtifact,
};

# fn example() -> Result<(), accordlock_evaluation::PolicyEvaluationError> {
let task_hash = Digest32::from_bytes([1; 32]);
let request = RequestArtifact::new(task_hash, Digest32::from_bytes([2; 32]))?;
let requirement = RequirementCommitment::new(
    Digest32::from_bytes([3; 32]),
    NormalizedScore::new(900_000)?,
)?;

let completed = IntentTraceBuilder::start(request, [requirement])?
    .append_plan(PlanArtifact::new(
        task_hash,
        Digest32::from_bytes([4; 32]),
        1_000,
    )?)?
    .append_action(ActionArtifact::new(
        task_hash,
        Digest32::from_bytes([5; 32]),
        1_100,
    )?)?
    .append_result(ResultArtifact::new(
        task_hash,
        Digest32::from_bytes([6; 32]),
        1_200,
    )?)?;

let (trace, requirements, transformations) = completed.into_parts();
# let _ = (trace, requirements, transformations);
# Ok(())
# }
```

The builder derives stable UUIDv8 identifiers, step parent hashes, canonical
requirement order, and trace bindings. `CompletedIntentTrace` contains the
verified `IntentTrace`, `TaskRequirement` records, and ordered
`TransformationStep` records for atomic persistence.

The API accepts only `Digest32`, `NormalizedScore`, and integer timestamps. It
cannot receive raw prompts, raw model outputs, provider tokens, or execution
credentials. The runtime must hash artifacts at its trusted boundary and store
the content separately under its own access policy.

## Evidence, provenance, and uncertainty

`IntentEvidence` is an append-only, versioned record for one requirement at one
mandatory stage. Each record commits to:

- the exact task, requirement, stage artifact, and transformation;
- the immutable trace identity and evidence-ledger identity, preventing replay
  against another trace or ledger;
- a categorical verdict and a bounded confidence interval;
- a provider-neutral method class;
- hashes of the exact method configuration, evaluator identity or model build,
  calibration material, and raw evidence content;
- its timestamp, sequence, and exact parent evidence hash.

`EvidenceProvenance` canonically binds the method class, exact method,
evaluator, and calibration tuple. `EvidenceTrustPolicy` contains a versioned,
task-scoped allowlist of complete provenance digests with a policy epoch and
validity window. Merely relabeling output as deterministic or calibrated is
therefore insufficient.

Allowlisted deterministic checks, human reviews, and external attestations use
`NOT_APPLICABLE` calibration with no calibration hash. Statistical-model and
language-model support requires `VERIFIED` calibration with a nonzero
calibration hash as well as admission by the current trust policy. An
uncalibrated score remains uncertain even when it is maximal. Expired
calibration, inconclusive evidence, or a threshold-crossing interval requires
review. A trusted contradiction or trusted interval wholly below the
requirement threshold blocks.

The trust rule is symmetric. Evidence from provenance not admitted by the
current policy is not interpreted as either support or contradiction: it emits
`UNVERIFIED_PROVENANCE` and requires review. This prevents untrusted content
from authorizing execution or becoming a denial oracle. Independent structural
failures, binding substitutions, and broken chains remain terminal denials.

`CalibrationStatus::Verified` and trust-policy membership are assertions by the
trusted policy boundary. This crate commits to them but does not fetch a
benchmark, verify an external signature, or prove that a judge was calibrated.
Callers must do those checks before admitting a provenance digest.

Lexical overlap, embedding similarity, and a model's self-reported confidence
are not treated as proof that intended meaning was preserved. They may be recorded as
provenanced evidence, but without a validated measurement procedure and
calibration they remain uncertain. Deterministic checks should be used only for
explicit machine-verifiable constraints, not relabeled as general intent
understanding.

## Pre-execution and complete-trace profiles

`IntentEvaluationProfile::PreExecution` evaluates the typed request, plan, and
action checkpoint before an effect runs. It neither requires nor invents a
result. `IntentEvaluationProfile::CompleteTrace` evaluates request, plan,
action, and result after observation. The profile is bound into requests,
evaluations, records, and canonical digests; substituting one profile or
checkpoint for the other fails verification. Missing qualified evidence still
requires review.

## Conservative aggregation

`IntentConformanceEvaluator` checks every requirement at every stage required
by the selected profile: request, plan, and action for pre-execution, plus
result for a complete trace. The caller supplies an `EvidenceLedgerSnapshot`
that commits to the trusted ledger identity, trace identity, epoch, evidence
count, head, capture time, and expiry. `EvidenceLedgerExpectation` adds the trusted minimum epoch and
evaluation time. A stale, rollback, reordered, truncated, cross-trace, or
substituted chain is invalid and blocks; this prevents evaluating only a
favorable historical prefix when the ledger contains a later contradiction.
An authoritative snapshot that proves the ledger is empty is valid, but every
missing profile-required stage assessment still requires approval.

The integration must obtain the snapshot and minimum epoch atomically from the
authoritative ledger. A cached epoch cannot prove that no newer contradictory
evidence exists. Snapshot capture time must also be after the trace and every
included evidence timestamp.

Aggregation is monotone:

- complete qualified support can only preserve the caller's baseline policy
  decision;
- any missing, stale, unverified, or inconclusive signal increases the decision
  to `REQUIRE_APPROVAL`;
- any trusted contradiction, trusted below-threshold result, scope mismatch, or
  invalid chain increases it to `DENY`;
- no score, evidence item, or aggregate can reduce `REQUIRE_APPROVAL` or `DENY`
  to `ALLOW`.

The returned summary exposes the trace hash, ledger snapshot hash, trust policy
hash, authoritative evidence head, sorted evidence bindings, stage-level
findings, and the monotone `PolicyEvaluation`. The summary itself has a
versioned, domain-separated canonical digest suitable for
`PolicyDecisionRecord::conformance_evaluation_hashes`; the constituent
requirement and transformation digests remain separately bound by that record.

`IntentConformanceRecord` is the strict, versioned JSON transport form of that
private evaluator summary. It denies unknown fields, carries the source
evaluation digest, and has its own domain-separated canonical digest.
`verify_bindings_for` checks only checkpoint and context commitments; it is not
an authorization check. Authorization integrations must call
`verify_evaluation_for`, which re-runs the evaluator over the exact
requirements, transformations, evidence, profile/checkpoint, and context and
compares the complete canonical result. A self-consistent forged `SUPPORTED`
record therefore cannot replace source evidence. Deserialization alone never
establishes trust.

Snapshot substitution and chain corruption remain distinct findings:
`LEDGER_SNAPSHOT_MISMATCH` identifies a stale, truncated, or replaced
authoritative snapshot, while `EVIDENCE_CHAIN_MISMATCH` identifies broken root,
sequence, parent, ledger, trace, or observation-time continuity.

## Provider boundary

`IntentEvidenceProvider` is a minimal synchronous integration trait with no
runtime or network dependency. Its control-plane `IntentEvidenceRequest`
contains commitments, profile/checkpoint scope, a fresh challenge, resolver
policy, and an explicit disclosure policy—not raw content. A trusted
`EvidenceArtifactResolver` resolves a task- and trace-scoped
`BoundedEvidenceMaterial` data plane and recomputes every commitment. Combined
material is capped by stage (256 KiB request, 512 KiB plan, 1 MiB action and
result). Local disclosure is local-only. External disclosure requires an
`ExternalEvidenceDisclosureGrant` signed by the exact Ed25519/COSE egress
authority pinned in the request. Verification yields an opaque capability bound
to the request digest, task, trace, evaluation profile, stage, provider, egress
policy, provider trust root, challenge, authority key/root, and a maximum
five-minute validity window. Raw hashes copied from a public request cannot open
the data plane. `disclose_external` also receives the current trusted time and
rejects clock rollback or use after expiry.

The provider-facing view exposes the exact provider, egress policy, provider
trust root, and expiry associated with the capability. This lets an adapter
check the authorized external scope without receiving a serializable bearer.

A verified grant may be reused only for its exact scope during its bounded
validity window. This crate does not claim one-shot consumption; an integration
that requires single use must atomically claim the signed grant in its replay
store before disclosure. This crate also does not enforce or observe the actual
network route. A live egress adapter or broker must enforce the committed route
and destination.

Missing or unavailable material maps to abstention/review, never allow. Scope,
digest, size, and disclosure failures map to deny. Debug output redacts all raw
material. The trusted resolver remains responsible for secret redaction and
sensitivity classification; this crate cannot detect every secret. It binds the
resolver's exact policy/profile hash so that policy substitution is detectable.

`IntentEvidenceResponse` binds the full evidence record, provenance,
calibration, source request, and response body. Local responses are valid only
for local-only requests. External responses require an Ed25519 COSE signature
over a domain-separated attestation binding the exact key id/public-key trust
root, request digest, challenge, body digest, issue time, and expiry (maximum
five minutes). JSON validation alone never authenticates external evidence;
`verify_external_for` is mandatory. Callers must then apply the evidence trust
policy. Provider output cannot confer authority.

### Deterministic local artifact evidence

`PinnedLocalArtifactResolver` and `LocalDeterministicEvidenceProvider` provide
a complete same-process reference path for explicit byte-identity constraints.
The resolver is pinned to one strict `LOCAL_ONLY` request and one exact set of
request, proposal, and context bytes. It reconstructs
`BoundedEvidenceMaterial`, rechecks every commitment and size bound, and never
prints raw material in debug output.

`ExactArtifactDigestRule` can support or contradict only one exact expected
digest for the request, proposal, or context artifact selected by the trusted
integration. Its method commitment covers the selected artifact and expected
digest. The provider has fixed `DETERMINISTIC_CHECK` provenance with
`NOT_APPLICABLE` calibration; callers cannot relabel it as a statistical or
language-model result. The exact provenance digest must be present in both the
provider request and the current evidence trust policy before support is
qualified by the evaluator.

`evaluate_local_evidence` runs request validation, resolution, local
disclosure, provider evaluation, and response revalidation. Missing or
temporarily unavailable material produces an explicit review outcome.
Malformed requests, external disclosure, hash or scope substitution, invalid
chain bindings, and provider-profile substitution return fail-closed errors.
The returned response is still evidence, not authority, and must be appended to
the authoritative evidence ledger before evaluation.

This path qualifies exact local artifact identity only. It does not infer
meaning, score paraphrases, inspect hidden model reasoning, or establish that a
plan satisfies a natural-language objective. Those claims require a separately
qualified measurement procedure, calibration data, representative corpora,
and an admitted provider provenance.

Every structural `Err` from validation or evaluation is fail-closed and must be
handled as `DENY` by an integration boundary. The current agent runtime captures
the assistant-turn plan, constructs and persists typed pre-execution and
complete-trace bundles, re-evaluates their records, and binds the pre-execution
record hash through authorization and execution lineage. Its live profile still
uses an empty evidence list and returns `REVIEW`; the deterministic local
artifact provider is not automatically applied to free-text objectives.

## Other policy primitives

The crate also provides integer resource requests, quotas, monotone
reservations, and the earlier single-step `ConformanceEvaluation` profile.
Every durable record has an explicit schema version and canonical commitment.

`PolicyDecisionRecord` binds the task and action, all conformance and resource
evidence hashes, the pre-existing policy decision, the resulting decision,
reason codes, policy epoch, and exact parent decision.

This crate contains no network provider calls, credentials, policy storage,
general meaning evaluator, or effect execution. It cannot determine meaning by
itself and cannot authorize an action.
