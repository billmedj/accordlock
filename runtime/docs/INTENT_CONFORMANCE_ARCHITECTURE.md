# Intent Conformance Architecture

**Status:** implementation boundary for the engineering alpha  
**Last reviewed:** 2026-08-30

## Purpose

AccordLock separates three questions that ordinary agent harnesses often mix:

1. **Access:** is this operation inside authority approved for the task?
2. **Conformance:** does qualified evidence support that the proposed work
   preserves the approved request and constraints?
3. **Execution:** did the exact authorized operation run, and what result was
   observed?

No answer is allowed to stand in for another. Credentials do not prove
conformance. A favorable evaluator output does not grant access. A completed
process does not prove that its intended external effect occurred.

## Current local boundary

The source tree currently contains:

- a provider-independent evidence engine with restrict-only aggregation,
  abstention, provenance policy, calibration bindings, and stable findings;
- typed `PRE_EXECUTION` request-plan-action checkpoints and immutable
  `COMPLETE_TRACE` request-plan-action-result traces;
- a bounded artifact resolver and explicit local or allowlisted-external
  disclosure boundary;
- a pinned local resolver and deterministic exact-artifact provider for
  machine-verifiable byte-identity constraints;
- cryptographically authenticated external provider responses and a transport
  record that must be re-evaluated before authorization;
- a strict task-policy boundary for local automatic reads and exact one-time
  approval for other protected actions;
- durable authorization, execution, recovery, and audit records; and
- an offline categorical conformance benchmark.

Session audit profile 6 now projects each fully re-evaluated record as a
bounded task check. The projection contains only its profile, categorical
status, qualified-evidence count, and stable finding reasons. `VERIFIED`
requires at least one admitted evidence record and only supported findings.
Zero evidence is always shown as `Not verified`; no digest-only or empty
assessment can be presented as semantic support.

The connected Goose path now captures a bounded checkpoint from the actual
assistant turn before dispatch. The checkpoint contains visible assistant text
and the ordered tool requests, including each request identifier, tool name,
and argument digest. It excludes hidden reasoning, transport metadata, and
tool results. The exact request selected for dispatch must occur once in that
checkpoint and must match the proposal's tool identity and argument digest.

The runtime uses the approved task objective, that plan checkpoint, and the
exact tool proposal to build, revalidate, and persist a typed pre-execution
bundle. After execution it appends the observed result digest, then builds,
revalidates, and persists the complete bundle. Audit schema 6 exposes the
pre-execution evaluation hash and bounded task-check projection at action
start, then the pre-execution and complete-trace hashes and projections at
completion.

This local bridge deliberately has an empty evidence set. The evaluator
therefore returns `REVIEW`, not semantic support. No production material
resolver or qualified evidence provider is connected. The exact pre-execution
record hash is required by `AuthorizationDecision` schema 4, copied into
`TaskControlProjection` schema 2, and retained by `ExecutionLineage` schema 2.
Changing the record therefore invalidates the authorization and completed
lineage commitments. The complete-trace hash remains post-execution evidence
in the ledger and audit projection; it does not retroactively alter authority.

The evaluator's `REVIEW` result and the structural authorization outcome remain
separate. The structural policy may still allow bounded `developer/read` and
`developer/tree` operations automatically. The current live record allows
cryptographic object-continuity checks and records explicit abstention; it does
not prove that an action preserves the user's meaning.

The local deterministic provider can qualify an explicitly configured digest
constraint with fixed `DETERMINISTIC_CHECK` provenance and
`NOT_APPLICABLE` calibration. Its pinned resolver rechecks the exact local
request, proposal, context, scope, disclosure policy, and size bounds. Missing
or unavailable material yields review; malformed or substituted material fails
closed. This provider is a reference path for machine-verifiable constraints,
not a semantic evaluator, and it is not automatically applied to the current
free-text task objective.

## Target production flow

The complete product path is:

```text
human-approved task contract
  -> actual agent plan commitment
  -> exact proposed action and verified context
  -> PRE_EXECUTION checkpoint
  -> bounded artifact resolver
  -> authenticated evidence provider response
  -> immutable evidence-ledger snapshot
  -> restrict-only pre-execution evaluation
  -> independent task-policy decision
  -> exact single-use execution authorization
  -> credential-holding runner
  -> observed result and execution lineage
  -> COMPLETE_TRACE evaluation and audit projection
```

Every arrow carries a versioned, domain-separated commitment. A later record
must name the exact earlier record that it consumes. Replacing a plan, action,
target, policy epoch, evidence item, authorization, or result changes the final
commitment and fails verification.

The local runtime currently implements the request-plan-action checkpoint,
empty-evidence evaluation, authorization correlation, result append, complete
evaluation, direct pre-execution hash binding in the authorization decision and
execution lineage, durable persistence, and audit-hash projection. The
resolver, authenticated provider, and authoritative non-empty evidence ledger
in the diagram remain production work.

## Pre-execution and complete-trace profiles

The two profiles have different claims.

### Pre-execution profile

`IntentEvaluationProfile::PreExecution` requires exactly `REQUEST`, `PLAN`, and
`ACTION`. Its typed checkpoint cannot contain a result. It can inspect the
approved request, actual agent plan, exact proposed action, and verified current
context before an effect runs; it cannot use or invent a result.

- `SUPPORTED` preserves an independently granted task-policy decision.
- `UNCERTAIN`, missing evidence, or unavailable evaluation requires review.
- `NONCONFORMANT` or invalid bound evidence prevents dispatch.

Support never adds a tool, target, credential, network destination, or cloud
permission that the task policy did not already grant.

In the current live local profile, there is no qualified evidence and therefore
no `SUPPORTED` outcome. The record deterministically requires review. That
record's hash is bound into the structural authorization decision, while the
decision's allow or deny outcome continues to come from the independent task
policy.

### Complete-trace profile

After execution, the observed result is appended as a separate artifact.
`IntentEvaluationProfile::CompleteTrace` requires `REQUEST`, `PLAN`, `ACTION`,
and `RESULT` for audit, reconciliation, and later policy improvement.
Post-execution evidence cannot retroactively authorize the action.

## Evidence material and provider contract

The provider request is a hash-only control plane. It commits to:

- the approved request;
- the actual plan;
- the exact proposed action;
- verified context;
- the requested evaluation profile; and
- the applicable task and trace identities.

An `EvidenceArtifactResolver` supplies the separate data plane as
`BoundedEvidenceMaterial`. Construction recomputes the committed request,
proposal, context, and resolver-policy hashes; binds task, trace, profile, and
stage; and enforces combined stage limits of 256 KiB for request, 512 KiB for
plan, and 1 MiB for action or result. Raw material is redacted from debug
output. Missing or unavailable material requires review. Scope, integrity,
oversize, resolver-policy, or disclosure failure denies.

Material marked `LOCAL_ONLY` can be opened only inside the trusted local
boundary. `ALLOWLISTED_EXTERNAL` pins the provider, egress policy, provider
trust root, and `egress_authority_root`. Hashes alone do not open the material.
`ExternalEvidenceDisclosureGrant` schema version 1 must be Ed25519/COSE signed
by that authority and bind the exact request, task, trace, profile, stage,
provider, egress policy, provider root, challenge, authority key/root, and a
validity window no longer than 300 seconds. Verification returns an opaque,
non-serializable capability.

`disclose_external` requires that capability and a current trusted time. It
rejects clock rollback and post-expiry use. The provider view exposes the exact
provider, egress policy, provider trust root, and expiry alongside the material
bound to the request. A grant is reusable only inside that exact scope and
window; one-shot disclosure requires an external atomic replay store. The live
egress adapter or broker remains responsible for enforcing the actual network
route and destination.

The resolver is responsible for secret redaction and content classification;
the evaluation crate verifies commitments and limits, not whether bytes contain
a secret.

The provider returns a strict record containing a categorical verdict, exact
subject and requirement bindings, method and evaluator commitments, calibration
state when required, payload commitment, and observation time.

An external response is not trusted because its JSON validates. Response schema
version 2 requires Ed25519/COSE verification of a domain-separated attestation
that binds the provider key ID and public-key trust root, request digest,
challenge, response-body digest, issue time, and expiry. The interval is capped
at 300 seconds. Because the signed request digest includes disclosure policy,
the signature also binds the allowlisted provider and egress-policy commitments.
Local
responses are accepted only for local-only requests.

Providers are evidence sources, not policy decision points:

- deterministic checks, admitted human review, and admitted external
  attestations use exact provenance profiles;
- statistical and language-model methods additionally require current
  calibration evidence;
- provenance not admitted by the current trust policy produces review, even
  when the provider claims a contradiction; and
- malformed, stale, replayed, cross-task, or chain-inconsistent records are
  non-authorizing.

The same model that proposes an action may supply evidence, but self-review is
not privileged. Its provenance and calibration remain visible and policy may
require an independent provider.

## Evaluation-record contract

`IntentConformanceRecord` schema version 2 is an untrusted transport record,
not a portable authorization token. `verify_bindings_for` confirms only that
the record names the caller's exact checkpoint, ledger snapshot, trust policy,
epochs, time, and evidence head. That check is non-authorizing.

An authorization integration must call `verify_evaluation_for`. It re-runs the
evaluator over the exact baseline decision, typed checkpoint, requirements,
transformations, evidence, and context, then compares the complete canonical
record. A fabricated but internally consistent `SUPPORTED` record therefore
cannot substitute for source evidence.

## User-interface contract

Primary copy remains short:

- `Within approved access` — structural task-policy checks passed;
- `Review required` — the system abstained or the action needs exact approval;
- `Reviewed` — that exact action received the required one-time approval;
- `Outside task` — a task mismatch was established;
- `Blocked` — another enforcement or integrity check prevented execution.

Technical details remain collapsed by default. Audit and export may expose
reason identifiers, provenance, calibration, ledger and policy epochs,
evaluation commitments, authorization commitments, and execution lineage.
The interface does not use a scalar score as a status.

The visible audit labels are `Task check` and `Task evidence`. They are derived
only after the runtime revalidates the exact request, plan, action, evaluator
record, and ledger bindings. This projection is evidence, not permission, and
cannot expand the approved tool, workspace, network, or credential scope.

## Local engineering exit criteria

The live conformance junction is locally complete only when all of these are
demonstrated in one deterministic integration suite:

1. the desktop captures the exact approved request and actual assistant-turn
   plan separately;
2. the action proposal binds its complete arguments and verified target state;
3. committed material is resolved within its disclosure policy and stage size
   bound, and external disclosure uses a verified, current egress-authority
   capability;
4. an external provider response is cryptographically authenticated, stored in
   an immutable ledger, and evaluated through the provider-independent engine;
5. the pre-execution evaluation record is re-evaluated over the exact source
   inputs and its commitment is present in `AuthorizationDecision` and the
   completed `ExecutionLineage`, while the complete-trace commitment remains
   post-execution evidence;
6. missing, inconclusive, untrusted, contradictory, substituted, stale, and
   replayed evidence produces the specified review or denial;
7. the runner executes only the exact single-use authorization;
8. the result closes a separate execution lineage and `COMPLETE_TRACE` record;
9. the audit projection can reverify the complete chain; and
10. no current UI label or public claim exceeds the retained evidence.

Representative accuracy, false-review rates, production latency, cloud
mediation, independent review, and customer acceptance remain external
evidence even after this local integration passes.

This architecture measures conformance to declared requirements under explicit
evidence and trust assumptions. It does not discover unstated intent or
establish semantic truth.
