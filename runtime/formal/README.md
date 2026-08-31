# AccordLock formal assurance core

This directory is a standalone Lean 4 model of AccordLock's intent-bound
execution transaction. It has no third-party Lean dependencies and imports no
exploratory proof foundations from elsewhere in the workspace.

The public assurance package has three parts:

- [INTENT_CONFORMANCE_SPEC.md](INTENT_CONFORMANCE_SPEC.md) defines the normative
  provider-independent evidence contract, decisions, abstention behavior,
  reasons, commitments, invariants, and non-claims;
- [TRACEABILITY.md](TRACEABILITY.md) maps public security definitions to Lean
  theorems, Rust types, executable tests, and current interface surfaces;
- [DECISION_TAXONOMY.md](DECISION_TAXONOMY.md) separates benchmark
  classifications, evidence-engine findings, and live execution-control
  reasons;
- `AccordLockFormal/*.lean` contains the machine-checked abstract proofs.

The specification is broader than the Lean model. The traceability matrix marks
every place where a normative requirement is implemented or tested but not yet
represented by a Lean theorem.

The live Rust path now captures a bounded checkpoint from the actual assistant
turn and builds, revalidates, and persists typed pre-execution and
complete-trace bundles. Its current evidence list is empty, so the evaluator
returns `REVIEW`. `AuthorizationDecision` schema 4,
`TaskControlProjection` schema 2, and `ExecutionLineage` schema 2 bind the exact
pre-execution evaluation hash. That implementation does not establish a
refinement from these Lean definitions, does not supply qualified semantic
evidence, and does not prove that an action preserved a user's meaning.

## Lean modules

| Module | Abstract property family |
| --- | --- |
| `AuthorityEpoch` | Exact principal, epoch, request, plan, action, argument, target-state, and time bindings |
| `AuthorizationInstance` | Exact action-manifest integrity and invalidation after plan or argument changes |
| `CapabilityIntegrity` | No authority amplification, single-use execution grants, and replay rejection |
| `TransactionLifecycle` | Prepared, authorized, claimed, dispatched, reconciled, compensated, and finalized phase ordering |
| `EvidenceMonotonicity` | Restrict-only evidence, explicit abstention, contradiction dominance, and abstention persistence |
| `EffectKnowledge` | Applied, not-applied, unknown, and compensated outcomes with safe retry and reconciliation rules |
| `ResourceReservation` | Componentwise natural-number resource bounds and composition |
| `EndToEnd` | One dispatch boundary combining authority, artifact, grant, lifecycle, decision, and capacity requirements |

## What is proved

For the abstract definitions in this directory, Lean checks that:

- an authorization is bound to one principal, policy epoch, configuration
  epoch, request, plan, action, argument set, and target-state snapshot;
- stale epochs, changed target state, expired authorization, changed plans, and
  changed arguments are rejected;
- an execution grant cannot add authority and cannot be reused after its
  identifier is recorded as consumed;
- transaction phases cannot skip authorization or claim, a lost response enters
  explicit unknown outcome knowledge, and unknown outcomes cannot be blindly
  redispatched;
- intent-conformance and other advisory evidence are restrict-only: support
  preserves the policy decision, uncertainty requires review, contradiction
  denies, and a sequence of findings cannot increase authority;
- once evaluation has abstained, subsequent supportive findings in the same
  sequence cannot silently restore automatic execution;
- exact natural-number resource reservations compose component by component;
- the final dispatch theorem combines current authority, artifact integrity,
  one-time execution authority, lifecycle phase, decision, and resource
  capacity into a single invariant.

## Complementary state-machine models

The repository's TLA+ suite in `../models/` covers operational state transitions
that the Lean core deliberately abstracts away:

1. `AuthorizationLifecycle`
2. `DispatchClaim`
3. `PhysicalReservation`
4. `AdmissionAuthorization`
5. `BrokerJournal`
6. `TerminalRetirement`
7. `DurableControlQueue`
8. `DurableDispatchAcquisition`

These models cover bounded instances of issuance, monotonic trusted time,
single-use consumption, durable claims and leases, exclusive reservations,
admission binding, unknown-outcome recovery, terminal retirement, control-queue
recovery, and dispatch acquisition. Their configurations, checked invariants,
bounds, and limitations are documented in `../models/README.md`.

Lean proofs and TLA+ checks are complementary. Neither is evidence that the
Rust implementation refines the model unless a separate refinement argument is
provided.

## Reproduce

Prerequisite: Lean 4 through `elan`. The exact toolchain is pinned in
`lean-toolchain`.

```powershell
cd formal
lake build
./verify.ps1
```

`verify.ps1`:

1. scans every Lean source for `sorry` or `axiom`;
2. builds every module with the pinned installed toolchain when available;
3. reports the number of checked theorem declarations.

On Windows, verification reuses the pinned installed toolchain directly and
does not require an update check. `ACCORDLOCK_LAKE` may name an alternative
trusted `lake` executable.

## Exact claim boundary

The Lean results establish properties only of the abstract definitions in this
directory. They do **not** prove:

- that the Rust implementation refines the Lean model;
- correctness of cryptographic primitives, signatures, hashes, canonical
  serialization, or key management;
- database isolation, operating-system mediation, filesystem or network
  enforcement;
- Kubernetes, cloud-provider, external model, or connector behavior;
- truthfulness or calibration of evidence sources;
- completeness or correctness of a human task description;
- semantic truth or intent preservation for a live desktop request; the
  connected trace currently carries no qualified provider evidence;
- liveness, fairness, performance, availability, or production readiness.

Those obligations require protocol conformance tests, implementation-level
tests, bounded state-machine checks, system tests, deployment evidence, and
independent security review.

No result in this package treats a model-generated score as authority. Evidence
can only preserve or reduce authority granted by an independent policy decision.
