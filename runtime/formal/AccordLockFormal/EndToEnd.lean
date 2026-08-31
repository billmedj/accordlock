import AccordLockFormal.AuthorizationInstance
import AccordLockFormal.CapabilityIntegrity
import AccordLockFormal.TransactionLifecycle
import AccordLockFormal.EvidenceMonotonicity
import AccordLockFormal.EffectKnowledge
import AccordLockFormal.ResourceReservation

/-!
Composition theorem for an intent-bound execution transaction.
-/

namespace AccordLockFormal

/-- All trusted checks required immediately before an effectful dispatch. -/
structure DispatchRequest where
  authorization : AuthorizationInstance
  manifest : ActionManifest
  grant : ExecutionGrant
  currentContext : AuthorityContext
  now : Nat
  consumedGrantIds : List GrantId
  phase : TransactionPhase
  decision : Decision
  demand : ResourceVector
  capacity : ResourceVector
deriving Repr

/-- The conjunction enforced at the dispatch boundary. -/
def ReadyToDispatch (request : DispatchRequest) : Prop :=
  BoundTo request.authorization request.currentContext ∧
  ActiveAt request.authorization request.now ∧
  ManifestMatches request.manifest request.authorization ∧
  GrantUsable request.grant request.authorization request.consumedGrantIds ∧
  request.phase = .claimed ∧
  request.decision = .allow ∧
  Fits request.demand request.capacity

def EvidenceCleared (request : DispatchRequest)
    (finding : EvidenceFinding) : Prop :=
  applyEvidence request.decision finding = .allow

theorem ready_request_is_current {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    BoundTo request.authorization request.currentContext :=
  ready.1

theorem ready_request_is_active {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    ActiveAt request.authorization request.now :=
  ready.2.1

theorem ready_manifest_matches {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    ManifestMatches request.manifest request.authorization :=
  ready.2.2.1

theorem ready_grant_is_usable {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    GrantUsable request.grant request.authorization
      request.consumedGrantIds :=
  ready.2.2.2.1

theorem ready_request_has_exact_action {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    request.manifest.actionDigest = request.currentContext.actionDigest := by
  exact Eq.trans (matching_manifest_preserves_action (ready_manifest_matches ready))
    (bound_action (ready_request_is_current ready))

theorem ready_request_has_exact_arguments {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    request.manifest.argumentsDigest =
      request.currentContext.argumentsDigest := by
  exact Eq.trans
    (matching_manifest_preserves_arguments (ready_manifest_matches ready))
    (bound_arguments (ready_request_is_current ready))

theorem ready_request_has_current_target {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    request.authorization.context.targetStateDigest =
      request.currentContext.targetStateDigest :=
  bound_target_state (ready_request_is_current ready)

theorem ready_request_respects_resources {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    Fits request.demand request.capacity :=
  ready.2.2.2.2.2.2

theorem consumed_ready_grant_blocks_dispatch {request : DispatchRequest}
    (consumed : request.grant.grantId ∈ request.consumedGrantIds) :
    ¬ ReadyToDispatch request := by
  intro ready
  exact (ready_grant_is_usable ready).2 consumed

theorem stale_policy_blocks_dispatch {request : DispatchRequest}
    (stale : request.authorization.context.policyEpoch ≠
      request.currentContext.policyEpoch) :
    ¬ ReadyToDispatch request := by
  intro ready
  exact stale_policy_epoch_rejected stale (ready_request_is_current ready)

theorem changed_target_blocks_dispatch {request : DispatchRequest}
    (changed : request.authorization.context.targetStateDigest ≠
      request.currentContext.targetStateDigest) :
    ¬ ReadyToDispatch request := by
  intro ready
  exact changed_target_state_rejected changed (ready_request_is_current ready)

theorem resource_overflow_blocks_dispatch {request : DispatchRequest}
    (overflow : ¬ Fits request.demand request.capacity) :
    ¬ ReadyToDispatch request := by
  intro ready
  exact overflow (ready_request_respects_resources ready)

theorem unknown_evidence_blocks_automatic_dispatch (request : DispatchRequest) :
    ¬ EvidenceCleared request .unknown := by
  exact unknown_evidence_never_allows request.decision

theorem contradictory_evidence_blocks_automatic_dispatch
    (request : DispatchRequest) :
    ¬ EvidenceCleared request .contradicts := by
  simp [EvidenceCleared, contradiction_denies]

theorem finalized_transaction_cannot_dispatch {request : DispatchRequest}
    (terminal : request.phase = .finalized) :
    ¬ ReadyToDispatch request := by
  intro ready
  have claimed : request.phase = .claimed := ready.2.2.2.2.1
  rw [terminal] at claimed
  contradiction

/-- The dispatch boundary jointly preserves the action, arguments, target state,
authority lifetime, grant uniqueness, and resource bound. -/
theorem intent_bound_dispatch_invariant {request : DispatchRequest}
    (ready : ReadyToDispatch request) :
    request.manifest.actionDigest = request.currentContext.actionDigest ∧
    request.manifest.argumentsDigest = request.currentContext.argumentsDigest ∧
    request.authorization.context.targetStateDigest =
      request.currentContext.targetStateDigest ∧
    ActiveAt request.authorization request.now ∧
    request.grant.grantId ∉ request.consumedGrantIds ∧
    Fits request.demand request.capacity := by
  exact ⟨ready_request_has_exact_action ready,
    ready_request_has_exact_arguments ready,
    ready_request_has_current_target ready,
    ready_request_is_active ready,
    (ready_grant_is_usable ready).2,
    ready_request_respects_resources ready⟩

end AccordLockFormal
