# Assurance Traceability Matrix

This matrix connects each public security definition to its strongest current
assurance artifact. It is deliberately explicit about gaps: a Rust test is not
a Lean proof, a model invariant is not an implementation refinement, and a
preview screen is not a live control.

Paths are relative to the AccordLock repository root. Desktop surfaces refer to
the current product shell in the adjacent desktop application.

## Status vocabulary

- **Implemented** — repository code exists for the stated type or behavior.
- **Abstract proof** — Lean proves the property for the definitions in
  `formal/`; no Rust refinement is claimed.
- **Preview** — the interface demonstrates the interaction with simulated data.
- **Live** — the installed desktop path is connected to a runtime behavior.
- **Not exposed** — the implementation exists below the interface but is not
  yet available as a trustworthy user-facing control.
- **Not modeled** — no Lean theorem currently represents that implementation
  property.

The live product now carries three implementation artifacts that must not be
confused with semantic truth or a formal refinement proof:

- `TaskControlProjection` schema 2 reports whether a completed action stayed
  within pre-approved access or received exact human review and binds the exact
  pre-execution intent-evaluation hash. It does not establish that the action
  preserved the user's meaning.
- `ExecutionLineage` schema 2 binds the exact task, policy, proposal, request,
  pre-execution intent-evaluation hash, decision, authorization, and completion
  record for one execution. The runtime revalidates object continuity and
  detects substitution.
- `AgentPlanCheckpoint` commits the visible assistant text and ordered tool
  requests from the actual assistant turn. The runtime uses it to build and
  revalidate typed pre-execution and complete-trace bundles.

The stricter intent-conformance profiles, portable record, bounded material
resolver, and authenticated provider boundary exist in the core library. The
live bridge currently supplies no qualified provider evidence, so both bundles
contain an empty evidence list and deterministically return `REVIEW`. Their
pre-execution hash is required by `AuthorizationDecision` schema 4 and carried
through the current task-control and execution-lineage commitments. Audit
schema 5 exposes the pre-execution and complete-trace hashes. The complete hash
is post-execution evidence only. A separate structural policy can still
authorize bounded automatic reads. None of these implementation facts
establishes that an action preserved the user's meaning.

## Matrix

| Research definition | Lean theorem | Rust type or function | Executable test | Current UI surface |
| --- | --- | --- | --- | --- |
| **Restrict-only decision aggregation.** Evidence may preserve or increase restriction, never reduce it. | `evidence_cannot_reduce_strictness`; `evidence_sequence_cannot_reduce_strictness` in `formal/AccordLockFormal/EvidenceMonotonicity.lean` (**abstract proof**) | `EnforcementDecision::escalate`; `PolicyEvaluation`; `PolicyEvaluator::aggregate` in `crates/accordlock-evaluation/src/policy.rs` (**implemented**) | `aggregate_decision_is_monotone_for_every_baseline`; `aggregate_takes_the_monotone_maximum`; `valid_scores_and_reservations_do_not_override_policy_approval` | Decision Sheet shows the baseline task contract (**preview**). The aggregate reason set is **not exposed**. |
| **Explicit abstention.** Missing, unknown, or inconclusive evidence requires review and cannot silently become allow later in the same evaluation. | `unknown_evidence_never_allows`; `review_evidence_sequence_never_allows`; `unknown_in_sequence_never_allows`; `unknown_evidence_blocks_automatic_dispatch` (**abstract proof**) | `EnforcementDecision::RequireApproval`; `EvidenceVerdict::Inconclusive`; `IntentConformanceOutcome::Uncertain`; `IntentFindingReason::{MissingEvidence, InconclusiveEvidence, ConfidenceThresholdUncertain}` (**implemented**) | `uncalibrated_model_scores_remain_uncertain_even_when_maximal`; `missing_stage_and_expired_calibration_require_review`; `authoritative_empty_snapshot_is_review_required_not_invalid` | Permission sheet pauses before one exact call under the live access policy (**live local path**). Semantic-evaluation abstention and its reason are **not exposed**. |
| **Contradiction dominance.** One valid contradiction blocks the aggregate decision. | `contradiction_denies`; `denial_is_absorbing`; `contradiction_in_front_denies`; `contradictory_evidence_blocks_automatic_dispatch` (**abstract proof**) | `EvidenceVerdict::Contradicts`; `IntentConformanceOutcome::Nonconformant`; `EnforcementDecision::Deny` (**implemented**) | `one_contradiction_dominates_all_favorable_scores`; `inconclusive_evaluation_requires_approval_and_violation_blocks` | Permission sheet can deny an exact call (**live local path**). Requirement-level contradiction details are **not exposed**. |
| **Exact task and action binding.** Authority applies only to the committed request, plan, action, arguments, and target state. | `bound_request`; `bound_plan`; `bound_action`; `bound_arguments`; `bound_target_state`; `matching_manifest_preserves_*`; `ready_request_has_exact_*` (**abstract proof**) | `ExecutionRequest`; `AuthorizationDecision` schema 4; `ExecutionAuthorization`; `IntentTrace`; `IntentEvidence::verify_bindings`; runtime `AgentPlanCheckpoint` validation (**implemented**) | `authorization_repeats_and_verifies_every_security_binding`; `stage_replay_and_artifact_substitution_are_rejected`; `evidence_cannot_replay_across_trace_identity`; runtime plan/proposal and intent-hash substitution tests | Decision Sheet presents the task and scope (**preview**). Permission sheet presents exact tool identity and bounded input (**live local path**). Audit v5 exposes the intent-evaluation and execution-lineage hashes (**live local path**). |
| **Ordered intent trace continuity.** Request, plan, action, and result commitments form one non-substitutable transformation path. Pre-execution stops at action and cannot imply a result. | `matching_manifest_preserves_request`; `matching_manifest_preserves_plan`; `matching_manifest_preserves_action`; `changed_plan_invalidates_manifest` provide a **partial abstract proof**. Typed profile separation and full four-stage continuity are **not modeled** in Lean. | `AgentPlanCheckpoint`; `PreExecutionLiveIntentBundle`; `CompleteLiveIntentBundle`; `IntentEvaluationProfile`; `PreExecutionIntentTrace::verify_bindings`; `IntentTrace::verify_bindings`; `TransformationStep` (**implemented**) | `strict_pre_execution_is_exact_and_never_allows_automatic_execution`; `complete_trace_binds_result_record_and_profile`; `exact_trace_rejects_skipped_or_substituted_checkpoints` | The live runtime builds, revalidates, and persists both typed bundles. Audit v5 exposes their hashes, not the plan text or full trace. With no qualified evidence, the evaluation is `REVIEW` (**live local path**). |
| **Exact executed-object lineage.** One completed action binds the task, session, run, workspace, policy epoch, objective, task policy, tool proposal, execution request, pre-execution intent-evaluation hash, authorization decision, single-use authorization, execution record, and trusted times. | **Not modeled** in Lean. | `ExecutionLineage` schema 2; `CompletedExecutionEvidence::build`; `CompletedExecutionEvidence::validate_for` in `crates/accordlock-agent-runtime/src/execution_trace.rs` (**implemented**) | `lineage_binds_every_complete_transaction_stage`; `substituted_objects_and_lineage_fields_are_rejected`; `cross_task_substitution_is_rejected_even_with_matching_capability`; `completed_action_exposes_and_revalidates_the_execution_lineage` | Audit v5 exposes the verified execution-lineage and intent-evaluation hashes for a completed action (**live local path**). The complete-trace hash remains separate completion evidence. |
| **Profile-complete requirement coverage.** Every requirement is checked at every stage required by `PRE_EXECUTION` or `COMPLETE_TRACE`; absence is a finding. | **Not modeled** in Lean. | `IntentEvaluationProfile::required_stages`; `IntentConformanceEvaluator::assess_stages`; `IntentFindingReason::MissingEvidence`; runtime live-intent bundles (**implemented**) | `pre_execution_rpa_is_complete_without_inventing_a_result_and_is_not_replayable`; `missing_stage_and_expired_calibration_require_review`; `authoritative_empty_snapshot_is_review_required_not_invalid`; runtime strict-bundle tests | Audit v5 exposes only the resulting evaluation hashes. Requirement-stage coverage and findings remain **not exposed**. |
| **Portable, context-bound evaluation.** A serialized evaluation must be canonical, internally consistent, and bound to the exact profile, checkpoint, evidence ledger, trust policy, epochs, time, and evidence head. Authorization additionally requires deterministic re-evaluation over the source inputs. | **Not modeled** in Lean. | `IntentConformanceRecord::{from_evaluation, validate, verify_bindings_for, verify_evaluation_for, digest}`; `PreExecutionLiveIntentBundle::revalidate`; `CompleteLiveIntentBundle::revalidate` (**implemented**) | `external_record_round_trips_verifies_context_and_has_stable_digest`; runtime objective, plan, proposal, result, profile, record, and intent-hash substitution tests | `AuthorizationDecision` schema 4, `TaskControlProjection` schema 2, and `ExecutionLineage` schema 2 bind the revalidated pre-execution record hash. Audit v5 also exposes the complete-trace hash (**live local path**). |
| **Bounded and authorized evidence disclosure.** A provider can inspect committed content only through an exact task/trace scope, stage-specific size limit, and explicit disclosure policy. External access additionally requires an Ed25519/COSE grant from the pinned egress authority, verified into an opaque capability and rechecked against trusted time. | **Not modeled** in Lean. | `EvidenceArtifactResolver`; `BoundedEvidenceMaterial`; `PinnedLocalArtifactResolver`; `EvidenceDisclosurePolicy::AllowlistedExternal`; `ExternalEvidenceDisclosureGrant`; `VerifiedExternalEvidenceDisclosure`; `BoundedEvidenceMaterial::{disclose_local, disclose_external}` (**implemented contract**) | `resolver_rejects_wrong_hash_cross_task_oversize_and_disclosure`; `unavailable_abstains_to_review_and_debug_redacts_content`; `unavailable_material_abstains_and_integrity_failures_deny`; `resolver_debug_never_contains_local_artifacts`; external disclosure substitution tests | The pinned local resolver exercises exact local-only material disclosure. No production semantic resolver or live egress broker is connected to the runtime. External grant replay storage and route enforcement remain integration responsibilities (**not exposed**). |
| **Authenticated provider boundary.** Local responses are limited to local-only requests. External responses bind the exact key ID/trust root, challenge, source request, response body, and freshness window through Ed25519/COSE; provider output grants no authority. | **Not modeled** in Lean. | `IntentEvidenceRequest`; `IntentEvidenceResponse::{from_local_evidence, from_external_evidence, verify_for, verify_external_for}`; `LocalDeterministicEvidenceProvider`; `IntentEvidenceProvider` (**implemented contract**) | `exact_local_artifact_produces_bound_deterministic_support`; `exact_digest_mismatch_is_a_qualified_contradiction_not_similarity`; `substituted_profile_and_invalid_chain_binding_fail_closed`; external authentication tests | The deterministic local provider qualifies exact byte identity only and is not automatically applied to live free-text objectives. No production semantic provider is connected (**not exposed**). |
| **Append-only evidence integrity.** Omission, reordering, substitution, duplicate evidence, or a wrong ledger head is detected. | **Not modeled** in Lean. | `EvidenceLedgerSnapshot`; `EvidenceLedgerExpectation`; `IntentEvidence::verify_successor_of`; `IntentConformanceEvaluator::verify_evidence_chain`; `IntentConformanceRecord::verify_bindings_for` (**implemented**) | `authoritative_head_detects_omission_and_reordering`; `stale_or_rollback_ledger_snapshot_is_rejected`; `canonical_summary_binds_snapshot_epoch_and_policy`; `external_record_round_trips_verifies_context_and_has_stable_digest` | The runtime persists a bound empty-evidence snapshot and audit v5 exposes its evaluation hash (**live local path**). Non-empty evidence-ledger inspection and export are **not exposed**. |
| **Trusted evidence provenance.** Method labels and scores count only when exact provenance and current calibration are admitted by policy. | The restrict-only consequence is modeled by `supporting_evidence_preserves`; provenance admission itself is **not modeled**. | `EvidenceProvenance`; `EvidenceTrustPolicy`; `EvidenceMethodKind`; `CalibrationStatus`; `IntentEvidence::provenance_digest`; `IntentEvidenceResponse::{verify_for, verify_external_for}` (**implemented**) | `self_declared_deterministic_method_is_not_trusted_without_policy_admission`; `canonical_evidence_commitment_covers_provenance_and_calibration`; `external_auth_rejects_wrong_key_signature_challenge_replay_and_freshness` | No current desktop surface exposes evidence provenance or calibration. Audit v5's task-control provenance describes how the access/review projection was derived, not evidence-provider trust. |
| **Stable decision explanations.** Every review or denial is linked to canonical reason identifiers and exact evidence context. | **Not modeled** in Lean. | `DecisionReason`; `IntentFindingReason`; `IntentFinding`; `IntentConformanceEvaluation`; `IntentConformanceRecord`; `TaskControlProjection` (**implemented**) | `canonical_summary_binds_snapshot_epoch_and_policy`; `decision_record_rejects_downgrade_and_noncanonical_bindings`; `reviewed_action_projects_the_exact_task_control` | Permission sheet explains why a tool call paused, and audit v5 exposes access/review reason, control provenance, and intent-evaluation hashes (**live local path**). Semantic finding identifiers and evidence links are **not exposed**. |
| **Current authority context.** Principal, policy epoch, configuration epoch, validity interval, and target snapshot must still match. | `bound_principal`; `bound_policy_epoch`; `bound_configuration_epoch`; `stale_policy_epoch_rejected`; `stale_configuration_epoch_rejected`; `changed_target_state_rejected`; `expired_authorization_inactive` (**abstract proof**) | `ExecutionRequest`; `AuthorizationDecision`; `ExecutionAuthorization::verify_for_request` (**implemented**) | `authorization_repeats_and_verifies_every_security_binding`; `memory_store_rejects_expiration_and_clock_rollback` | Decision Sheet shows scope and data boundary (**preview**). Epochs and target-state commitments are **not exposed** by default. |
| **Single-use execution authority.** An execution authorization cannot add scope and cannot be replayed after consumption. | `usable_grant_cannot_amplify_context`; `consumed_grant_rejected`; `grant_cannot_be_replayed`; `consumed_ready_grant_blocks_dispatch` (**abstract proof**) | `ExecutionAuthorization`; atomic authorization store in `crates/accordlock-agent-protocol/src/store.rs` (**implemented**) | `non_authorizing_decision_cannot_create_a_usable_authorization`; `memory_store_is_atomic_one_shot_and_preserves_replay_tombstone` | Permission sheet offers `Allow once` and explicitly omits a permanent allow option (**live local path**). Consumption evidence is **not exposed**. |
| **Transaction phase ordering.** Authorization, claim, and dispatch occur in order; a finalized transaction cannot dispatch again. | `authorization_requires_prepared`; `claim_requires_authorization`; `dispatch_requires_claim`; `cannot_dispatch_before_claim`; `finalized_is_terminal`; `finalized_transaction_cannot_dispatch` (**abstract proof**) | `AuthorizationDecision`; `ExecutionAuthorization`; `ExecutionRecord`; `ExecutionLineage` plus the runtime transaction state (**implemented across protocol/runtime**) | `execution_record_closes_the_exact_chain`; `lineage_binds_every_complete_transaction_stage`; runtime transaction and recovery suites | Running steps and completion receipt exist with demonstration data (**preview**). Runtime-backed audit v5 exposes completed-action lineage, task-control status, and bound evaluation hashes (**live local path**), but not every durable lifecycle transition. |
| **Unknown-outcome reconciliation.** A lost response records unknown outcome; retry waits for evidence of non-application. | `lost_response_records_unknown`; `unknown_effect_blocks_retry`; `only_unknown_effect_requires_reconciliation`; `cannot_blindly_redispatch_unknown_effect`; `reconciliation_restores_effect_knowledge` (**abstract proof**) | `ExecutionOutcome`; `ExecutionRecord` and broker outcome records (**implemented**) | `execution_record_closes_the_exact_chain`; broker recovery and reconciliation suites | No current desktop screen exposes an unknown outcome or reconciliation workflow (**not exposed**). |
| **Componentwise resource limits.** Reserved use fits every resource dimension and independently valid reservations compose. | `resource_fit_is_transitive`; `combined_local_limits_compose`; `two_reservations_respect_combined_limits`; `resource_overflow_blocks_dispatch` (**abstract proof**) | `ResourceRequest`; `ResourceQuota`; `ResourceReservation`; `PolicyEvaluator::evaluate_resources` (**implemented**) | `reservations_are_integer_bounded_and_parent_chained`; `resources_require_exact_quota_and_reservation`; `valid_scores_and_reservations_do_not_override_policy_approval` | Resource budgets and reservations are **not exposed** in the current desktop. |
| **Combined dispatch boundary.** Dispatch requires current exact authority, an intact action manifest, a usable single-use authorization, claimed lifecycle state, `ALLOW`, and sufficient resources. | `intent_bound_dispatch_invariant` plus the `ready_request_*` theorem family (**abstract proof**) | `AuthorizationDecision`; `ExecutionAuthorization`; `PolicyEvaluation`; runtime dispatch acquisition, execution records, and `ExecutionLineage` (**implemented across crates**) | `authorization_repeats_and_verifies_every_security_binding`; `policy_decision_digest_binds_every_runner_handoff_field`; `execution_record_closes_the_exact_chain`; `substituted_objects_and_lineage_fields_are_rejected` | Decision Sheet, Permission sheet, running view, Receipt, and audit v5 expose parts of the live boundary. The separate structural authorization decision binds the current empty-evidence `REVIEW` record hash; that binding is integrity evidence, not semantic support. |

## Model coverage outside Lean

The TLA+ suite under `models/` checks state-machine invariants that are
complementary to the Lean core:

- `AuthorizationLifecycle` — issuance, expiry, one-time consumption, and atomic
  receipt/outbox creation;
- `DispatchClaim` — monotonic trusted time, authenticated claim samples, and
  no claim resurrection;
- `PhysicalReservation` — exclusive reservation and non-reusable fencing;
- `AdmissionAuthorization` — exact admission bindings and single durable write;
- `BrokerJournal` — mutation authority, unknown outcomes, read-only
  reconciliation, and generation fencing;
- `TerminalRetirement` — terminal evidence, retirement, and atomic release;
- `DurableControlQueue` — intake, policy evaluation, issuance, consumption,
  status revision, and recovery;
- `DurableDispatchAcquisition` — FIFO acquisition, stable claims, lease
  generations, downstream bindings, recovery, and cleanup.

These models do not prove the Rust implementation, SQL transactions,
cryptographic libraries, external services, or desktop behavior. Their exact
bounds and limitations are documented in `models/README.md`.

## Release-blocking traceability gaps

The matrix exposes six gaps that must remain visible in public claims:

1. no machine-checked refinement from Lean or TLA+ definitions to Rust;
2. no Lean model of the evidence ledger, profile-complete requirement coverage,
   material resolver, signed external-disclosure grant, authenticated provider
   boundary, portable evaluation record, or runtime execution lineage;
3. no production material resolver or qualified provider produces live,
   independently verifiable conformance evidence; the connected plan capture
   and bundles currently use an empty evidence list and return `REVIEW`;
4. live records are built, revalidated, persisted, and cryptographically bound
   through `AuthorizationDecision`, `TaskControlProjection`, and
   `ExecutionLineage`, but the current record contains no qualified evidence
   and therefore returns `REVIEW`;
5. audit schema 5 exposes evaluation hashes but the desktop does not expose
   full conformance evidence, requirement
   coverage, calibration, evidence provenance, unknown-outcome reconciliation, or
   resource reservations;
6. no external validation shows that semantic evaluators, thresholds, and
   confidence intervals are accurate for representative customer workloads.

These are assurance and integration gaps, not permission to weaken the existing
fail-closed behavior. Until gaps 3 and 4 are closed, public claims may describe
the structural status as **within approved access** or **reviewed**, and may say
that the intent evaluator abstained. They must never present the current record
as proof that an action preserved the user's intent.
