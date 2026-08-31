# Intent Conformance Specification

Status: public draft, version 1.1  
Scope: provider-independent evaluation of evidence that a pre-execution
checkpoint or completed task trace remains within a human-approved task
definition.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** in this document are to be interpreted as normative requirements.

## 1. Purpose

An autonomous system can hold valid credentials and still propose the wrong
action. Intent Conformance evaluates a separate question:

> Does the available, trusted evidence support that each stage required at this
> checkpoint remains within the approved task requirements?

The evaluator is an evidence input to authorization. It is not an authority
source. A favorable evaluation can preserve an existing policy decision; it
cannot create or broaden execution authority.

## 2. Security order

Decisions use this total order, from least to most restrictive:

```text
ALLOW < REVIEW < DENY
```

- **ALLOW** means that this evaluation adds no approval or blocking condition.
- **REVIEW** is explicit abstention. Automatic execution MUST pause.
- **DENY** is a blocking result. Execution MUST NOT proceed under the evaluated
  decision.

An implementation MAY encode `REVIEW` as `REQUIRE_APPROVAL` when the mapping is
one-to-one in APIs, records, logs, and user interfaces.

The final decision is the maximum of the trusted baseline decision and every
finding. No evidence-processing path may move a decision downward in this
order.

## 3. Evaluation inputs

An evaluation MUST receive the following immutable inputs.

### 3.1 Baseline decision

The baseline decision is produced by a trusted policy decision point before
Intent Conformance is considered. It MUST be one of `ALLOW`, `REVIEW`, or
`DENY`.

Intent Conformance MUST NOT convert baseline `REVIEW` to `ALLOW` or baseline
`DENY` to either `REVIEW` or `ALLOW`.

### 3.2 Task requirements

Each requirement MUST include:

- a stable task commitment;
- a stable requirement commitment;
- a minimum acceptance threshold when a confidence interval is used;
- a schema version.

The requirement set MUST be non-empty, canonical, duplicate-free, and bound to
the same task as the trace.

### 3.3 Evaluation profile and task trace

Every evaluation MUST select exactly one profile. The selected profile MUST be
bound into the checkpoint, provider requests, evaluation, transport record, and
their canonical commitments.

- `PRE_EXECUTION` contains exactly the `REQUEST`, `PLAN`, and `ACTION` stages.
  It is evaluated before an effect runs.
- `COMPLETE_TRACE` contains the `REQUEST`, `PLAN`, `ACTION`, and `RESULT`
  stages. It is evaluated after a result has been observed.

The ordered stages are:

1. `REQUEST` — the approved task statement;
2. `PLAN` — the proposed procedure;
3. `ACTION` — the proposed operation and its exact input;
4. `RESULT` — the observed result record.

The selected checkpoint MUST commit to:

- a trace identifier and task commitment;
- the complete sorted set of requirement commitments;
- one artifact commitment for each stage required by the selected profile;
- an ordered list of transformation-step commitments;
- the recording time and schema version.

The first transformation MUST start at the committed request. Each subsequent
transformation MUST name the prior step and use the prior target as its source.
Stages MUST advance in order. A `PRE_EXECUTION` checkpoint MUST reach `PLAN`
and `ACTION` without substitution or omission and MUST NOT contain or imply a
`RESULT`. A `COMPLETE_TRACE` checkpoint MUST additionally reach `RESULT`
without substitution or omission. Implementations MUST NOT synthesize a result
to satisfy a pre-execution check or label that checkpoint as a complete
request-to-result evaluation.

### 3.4 Evidence ledger snapshot

The evaluator MUST consume one authoritative, immutable ledger snapshot with:

- a snapshot identifier;
- ledger, task, and trace commitments;
- a positive epoch;
- evidence count and chain head;
- capture and expiry times.

The caller MUST also provide the expected ledger commitment, minimum accepted
epoch, and evaluation time. A snapshot with the wrong ledger, task, trace,
head, count, epoch, ordering, time, or validity window is invalid evidence.

An authoritative empty snapshot is valid input. It produces missing-evidence
findings and `REVIEW`; it is not fabricated as a successful evaluation.

### 3.5 Evidence trust policy

The trust policy MUST bind:

- a policy identifier;
- the task commitment;
- a positive policy epoch;
- a canonical allowlist of exact provenance commitments;
- a validity window.

The evaluator MUST receive a minimum accepted policy epoch. A stale, expired,
cross-task, malformed, or substituted trust policy produces `DENY`.

Self-declared method labels are not trust. An item described as deterministic,
human-reviewed, or calibrated is trusted only when its complete provenance
commitment is admitted by the current trust policy.

### 3.6 Evidence items

Each evidence item MUST bind all of the following:

- schema version and unique evidence identifier;
- task, trace, and ledger identities;
- sequence number and parent evidence commitment;
- requirement commitment and trace stage;
- exact subject artifact commitment;
- exact transformation-step commitment when the stage is not `REQUEST`;
- categorical evidence verdict;
- confidence interval;
- evaluation method class, method commitment, and evaluator commitment;
- calibration status and calibration commitment when applicable;
- evidence payload commitment;
- observation time.

Evidence items MUST form one append-only, task-local, trace-local ledger chain.
The root has sequence zero and no parent. Every successor increments the
sequence by one, commits to its exact parent, and has a nondecreasing observation
time.

The categorical evidence verdict is one of:

- `SUPPORTS`;
- `INCONCLUSIVE`;
- `CONTRADICTS`.

### 3.7 Evidence material and disclosure

Commitments alone do not provide an evaluator with the content needed to assess
a request, proposal, or context. A trusted artifact resolver MAY supply the
committed bytes through a separate, non-serializable data plane. When it does:

- the resolver MUST bind the material to the exact task, trace, profile, stage,
  source request, and resolver policy;
- the consumer MUST recompute the request, proposal, context, and resolver-
  policy commitments before disclosure;
- the combined canonical material MUST NOT exceed 256 KiB for `REQUEST`,
  512 KiB for `PLAN`, 1 MiB for `ACTION`, or 1 MiB for `RESULT`;
- local-only material MUST remain inside the trusted local boundary;
- an `ALLOWLISTED_EXTERNAL` policy MUST additionally commit the exact provider
  identity, egress policy, provider trust root, and `egress_authority_root`;
- external disclosure MUST require an authenticated disclosure capability
  issued by the egress authority pinned by that policy; and
- diagnostics MUST NOT expose raw material. Implementations SHOULD report only
  commitments and byte counts.

Missing or temporarily unavailable material produces `REVIEW`. Cross-task,
cross-trace, digest, size, resolver-policy, or disclosure failure produces
`DENY`. The resolver remains responsible for content classification and secret
redaction; commitment verification does not discover sensitive content.

The current external-disclosure authorization is
`ExternalEvidenceDisclosureGrant` schema version 1. It MUST be Ed25519/COSE
signed by the pinned egress authority and bind the exact source request, task,
trace, evaluation profile, stage, provider identity, egress policy, provider
trust root, challenge, authority key identifier, authority root, issue time, and
expiry. Its validity interval MUST NOT exceed 300 seconds.

Successful verification MUST return an opaque, non-serializable capability for
that exact request and scope. Opening external material MUST require both that
capability and a current trusted time. A time earlier than capability
verification or later than expiry MUST be rejected. The provider-facing view
MUST expose the authorized provider, egress policy, provider trust root, and
expiry so the receiving adapter can verify its exact scope.

The capability may be reused only within its exact scope and validity window.
This profile does not provide one-shot consumption. A deployment requiring
single use MUST atomically claim the signed grant in an external replay store
before disclosure. This library does not establish that bytes traversed the
declared network route; the live egress adapter or broker MUST enforce the
committed route and destination.

### 3.8 Provider authentication

A local provider response is valid only for a local-only request and trusted
same-process boundary. An external provider response MUST be authenticated;
valid JSON and matching fields are insufficient.

The current external profile uses an Ed25519 COSE signature over a
domain-separated attestation that binds:

- the provider key identifier and public-key trust root;
- the exact source-request commitment and its fresh challenge;
- the exact response-body commitment; and
- issue and expiry times.

The source-request commitment transitively binds the task, trace, requirement,
profile, stage, proposal, context, resolver policy, disclosure policy,
allowlisted provider, egress policy, provider trust root, and egress authority
root. The signed validity interval MUST NOT exceed 300 seconds. Consumers MUST
verify the signature, key identity, trust root, challenge, request binding,
response-body binding, and freshness before using external evidence. Provider
authentication establishes source and integrity under the configured trust
root; it does not establish that the provider's conclusion is correct.

## 4. Required evaluation procedure

An implementation conforming to this specification MUST perform these steps in
order.

When provider evidence is generated from committed material, the resolver,
disclosure, and provider-authentication requirements in Sections 3.7 and 3.8
MUST be satisfied before that evidence is admitted to the ledger.

1. Validate schemas, bounds, canonical collections, identifiers, commitments,
   confidence intervals, and time windows.
2. Verify exact continuity of the task trace.
3. Verify the trust policy against the task, evaluation time, and minimum epoch.
4. Verify the ledger snapshot against the expected ledger, task, trace, time,
   minimum epoch, count, and head.
5. Verify the complete evidence chain in ledger order.
6. Verify every evidence item against its exact task, requirement, stage
   artifact, and transformation step.
7. For every requirement and every stage required by the selected profile,
   classify all matching evidence. Absence is a finding; it MUST NOT be
   silently skipped.
8. Combine the baseline decision and all findings by taking the most
   restrictive decision.
9. Emit a canonical evaluation record containing the profile, outcome, decision,
   structured reasons, evidence commitments, ledger snapshot commitment, trust
   policy commitment, accepted epoch floors, and evaluation time.

Malformed trusted input may be returned as an evaluation error rather than a
decision. A caller MUST treat such an error as non-authorizing.

## 5. Finding classification

For a requirement threshold `T` and confidence interval `[L, E, U]`, where
`L <= E <= U`, the following table is normative.

| Condition | Conformance outcome | Decision pressure | Reason |
| --- | --- | --- | --- |
| Complete qualified support and `L >= T` | `SUPPORTED` | `ALLOW` | `SUPPORTED` |
| Required evidence is absent | `UNCERTAIN` | `REVIEW` | `MISSING_EVIDENCE` |
| Evidence verdict is `INCONCLUSIVE` | `UNCERTAIN` | `REVIEW` | `INCONCLUSIVE_EVIDENCE` |
| `L < T <= U` | `UNCERTAIN` | `REVIEW` | `CONFIDENCE_THRESHOLD_UNCERTAIN` |
| Evidence has unverified provenance | `UNCERTAIN` | `REVIEW` | `UNVERIFIED_PROVENANCE` |
| Supporting evidence has expired calibration | `UNCERTAIN` | `REVIEW` | `EXPIRED_CALIBRATION` |
| Supporting evidence has `U < T` | `NONCONFORMANT` | `DENY` | `BELOW_THRESHOLD` |
| Qualified evidence verdict is `CONTRADICTS` | `NONCONFORMANT` | `DENY` | `CONTRADICTORY_EVIDENCE` |
| Evidence is bound to another task, trace, requirement, stage, artifact, or step | `INVALID_EVIDENCE` | `DENY` | `SCOPE_MISMATCH` |
| Parent, sequence, ordering, count, or head is inconsistent | `INVALID_EVIDENCE` | `DENY` | `EVIDENCE_CHAIN_MISMATCH` or `LEDGER_SNAPSHOT_MISMATCH` |
| Trust policy identity, task, epoch, allowlist, or validity is inconsistent | `INVALID_EVIDENCE` | `DENY` | `TRUST_POLICY_MISMATCH` |

`ALLOW` in the table means “this finding adds no restriction.” It does not mean
that the evaluator grants permission to execute.

## 6. Uncertainty and abstention

`REVIEW` is a first-class security result, not an error and not a weak form of
`ALLOW`.

- Unknown, missing, uncalibrated, expired, or threshold-crossing evidence MUST
  produce `REVIEW` unless a stricter condition already requires `DENY`.
- Evidence from provenance not admitted by the current trust policy MUST
  produce `REVIEW` regardless of whether its conformance verdict is supportive,
  inconclusive, or contradictory. Untrusted content cannot authorize and
  cannot become a denial oracle. An independent binding, chain, snapshot, or
  trust-policy integrity failure may still require `DENY`.
- Once a finding produces `REVIEW`, later supportive findings in the same
  evaluation MUST NOT restore `ALLOW`.
- A new immutable ledger snapshot MAY be evaluated again. That is a new
  evaluation with a new committed input set, not a mutation of the old result.
- Timeout, evaluator failure, or unavailable evidence MUST NOT be coerced to
  support.
- A user interface MUST state what is unknown and what decision is required.

## 7. Structured reasons

Evaluation records MUST use stable reason identifiers, not free-text alone.
The core profile defines:

- `SUPPORTED`
- `MISSING_EVIDENCE`
- `INCONCLUSIVE_EVIDENCE`
- `UNVERIFIED_PROVENANCE`
- `EXPIRED_CALIBRATION`
- `CONFIDENCE_THRESHOLD_UNCERTAIN`
- `BELOW_THRESHOLD`
- `CONTRADICTORY_EVIDENCE`
- `SCOPE_MISMATCH`
- `EVIDENCE_CHAIN_MISMATCH`
- `LEDGER_SNAPSHOT_MISMATCH`
- `TRUST_POLICY_MISMATCH`

Every stage-level reason SHOULD identify its requirement, stage, and evidence
commitment. A global chain or policy reason MAY omit stage-level identifiers.
Reason collections MUST be canonical and duplicate-free.

Human-readable text MAY accompany a reason identifier, but changing that text
MUST NOT change the recorded decision or the canonical reason identity.

## 8. Commitments

A commitment is a digest over a deterministic, versioned canonical encoding.
Implementations MUST:

- bind every security-relevant field listed in this specification;
- use distinct type or protocol domains where records can otherwise be
  confused;
- reject unknown fields for security-bearing wire records;
- reject zero, missing, duplicate, unordered, or structurally invalid
  commitments where the schema forbids them;
- retain the exact commitments used by the policy decision and execution
  record.

A commitment establishes equality to committed bytes under stated
cryptographic assumptions. It does not establish that the content is true,
safe, complete, or faithful to a person's intent.

## 9. Invariants

A conforming implementation MUST preserve all of these invariants.

1. **No self-authorization.** Evidence never creates or expands authority.
2. **Restrict-only aggregation.** The final decision is never less restrictive
   than the baseline decision or any finding.
3. **Abstention persistence.** `REVIEW` cannot become `ALLOW` within one
   evidence sequence.
4. **Contradiction dominance.** Any valid contradiction makes the aggregate
   decision `DENY`.
5. **Complete coverage.** Every required requirement-stage pair is evaluated;
   missing evidence is explicit.
6. **Exact scope.** Evidence for one profile, task, trace, requirement,
   artifact, or transformation cannot be replayed into another.
7. **Chain integrity.** Omission, insertion, reordering, duplicated items, or a
   substituted head is detected.
8. **Current trust.** Stale ledger or trust-policy epochs cannot authorize.
9. **Inspectable decisions.** Every non-allowing result carries stable reasons
   sufficient to locate the failed or uncertain condition.
10. **Separate execution authority.** A dispatch boundary requires its own
    current, exact, single-use authorization in addition to an `ALLOW`
    evaluation.
11. **Authenticated external evidence.** An external response is unusable until
    its key identity, trust root, challenge, request, body, and freshness are
    cryptographically verified.

## 10. Consumer requirements

An authorization service consuming an Intent Conformance result MUST:

- treat a serialized evaluation record as untrusted input;
- verify the evaluation commitment and all expected context bindings;
- deterministically re-run the evaluation over the exact baseline decision,
  typed checkpoint, requirements, transformations, evidence, ledger snapshot,
  trust policy, epoch floors, and evaluation time, then compare the complete
  canonical result;
- treat `REVIEW`, `DENY`, invalid records, missing records, and verification
  errors as non-automatic;
- preserve any stricter policy decision already in force;
- bind accepted evaluation commitments into the authorization decision;
- bind the exact action, arguments, target state, authority epoch, and validity
  interval independently of conformance evidence;
- prevent replay through a single-use execution authorization;
- record the execution outcome, including an explicit unknown outcome when the
  effect cannot yet be determined.

In the reference API, `IntentConformanceRecord` schema version 2 exposes two
different verification paths. `verify_bindings_for` checks only replay and
context commitments and MUST NOT be used as an authorization check.
`verify_evaluation_for` performs the required deterministic re-evaluation. A
self-consistent `SUPPORTED` record that passes binding verification but does
not match the supplied evidence is non-authorizing.

## 11. User-interface requirements

The primary interface SHOULD show only the decision and the shortest useful
explanation:

- `Supported` for `ALLOW` when qualified evidence covers the declared
  checkpoint;
- `Review required` for `REVIEW`;
- `Outside task` only when a task mismatch is established;
- `Blocked` for another denial or invalid control input.

After a reviewed action completes, the interface MAY show `Reviewed` beside
the execution outcome. This means that the exact action received the required
approval. It MUST NOT be presented as automatic conformance evidence.

Detail views SHOULD expose the affected requirement, trace stage, evidence
source, confidence interval when present, reason identifier, and evaluation
commitment. Technical identifiers SHOULD be collapsed by default and available
for audit or export.

The interface MUST NOT describe an incomplete trace as verified end to end. It
MUST distinguish a simulated preview from a live evaluation and an evaluation
from an execution authorization.

## 12. Non-claims

This specification does not claim to:

- discover a person's unstated or objectively correct intent;
- prove that natural-language requirements are complete or unambiguous;
- prove that a model, evaluator, human reviewer, or external attestation is
  truthful or correctly calibrated;
- make a confidence score into authority;
- infer meaning from a cryptographic digest;
- establish semantic truth from an evaluator verdict or provider signature;
- verify cryptographic primitive implementations or key management;
- prove that any Rust implementation refines the Lean model;
- verify database isolation, operating-system mediation, network controls,
  cloud-provider behavior, or user-interface behavior;
- guarantee liveness, fairness, availability, latency, or absence of false
  reviews and false denials;
- authorize a pre-execution action from evidence that only exists after the
  action;
- replace an independent security review and production validation.

The formal model proves a subset of the invariants above for its abstract
definitions. The implementation and system-level obligations require their own
tests and assurance evidence. See [TRACEABILITY.md](TRACEABILITY.md).
