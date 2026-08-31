# Decision Taxonomy and Layer Boundaries

Status: public draft, version 1.0

AccordLock uses three related taxonomies. They answer different questions and
MUST NOT be substituted for one another.

## 1. Benchmark classifications

AccordBench `IC_*` codes label the semantic phenomenon represented by one
published reference case. They are fixture annotations, not runtime authority
and not proof that a deployed evaluator handles unseen requests.

| AccordBench classification | Candidate evidence verdict | Core finding after trust checks |
| --- | --- | --- |
| `IC_EXACT_MATCH`, `IC_SAFE_IMPLICATION`, `IC_EQUIVALENT_REPRESENTATION` | `SUPPORTS` | `SUPPORTED` only when provenance, calibration, scope, and threshold checks pass |
| `IC_AMBIGUOUS_REQUEST`, `IC_REQUIRED_DATA_MISSING`, `IC_EQUIVALENCE_UNVERIFIED` | `INCONCLUSIVE` | `INCONCLUSIVE_EVIDENCE`, or `MISSING_EVIDENCE` when no result exists |
| Any benchmark denial classification | `CONTRADICTS` | `CONTRADICTORY_EVIDENCE` after exact binding and trust-policy validation |

`IC_SCOPE_EXPANSION` describes a semantic change in a benchmark case.
`SCOPE_MISMATCH` describes evidence bound to the wrong task, trace,
requirement, stage, artifact, or transformation. They are not aliases.

## 2. Evidence-engine findings

The provider-independent evaluator consumes bound evidence and emits:

- an outcome: `SUPPORTED`, `UNCERTAIN`, `NONCONFORMANT`, or
  `INVALID_EVIDENCE`;
- a monotone decision: `ALLOW`, `REVIEW`, or `DENY`; and
- one or more stable finding reasons defined by
  [INTENT_CONFORMANCE_SPEC.md](INTENT_CONFORMANCE_SPEC.md).

These values describe the supplied evidence under a named trust policy. They
do not create execution authority. Missing evidence is `REVIEW`; malformed or
cross-bound evidence is non-authorizing.

## 3. Live execution-control reasons

Runtime reason codes describe what the execution boundary did. Examples:

- `POLICY_CONFORMANT` means the exact action passed the currently connected
  structural task-policy checks;
- `ACTION_APPROVAL_ACCEPTED` means a human approved that exact action for one
  use;
- an action denial records the enforcement reason that prevented dispatch.

The current automatic desktop path is displayed as `Within approved access`.
It MUST NOT be displayed as `Matches task`, because the live path does not yet
consume a complete, qualified request-plan-action-result evidence record.
`Reviewed` means that exact approval occurred; it does not retroactively turn
the action into automatically supported semantic evidence.

## 4. Mapping rule for a future live semantic path

A runtime MAY report full intent conformance only when all of the following
are true:

1. the human-approved request, actual agent plan, exact proposed action, and
   observed result are separately committed in their real roles;
2. every required stage is covered by qualified evidence;
3. the evidence ledger and trust policy pass exact freshness, provenance, and
   scope verification;
4. the core outcome is `SUPPORTED` and the final monotone decision is
   `ALLOW`; and
5. the evaluation commitment is bound into the authorization and execution
   lineage.

Until that path is connected, structural access checks, human approval, and
semantic evidence remain distinct in schemas, audit records, and interface
copy.

## 5. Scores

Confidence intervals can qualify one evidence item when the method requires
calibration. A score is never a decision, an authorization, or a primary UI
status. AccordBench conformance is categorical and exact.
