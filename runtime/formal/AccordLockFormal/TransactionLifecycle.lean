/-!
Deterministic execution-transaction lifecycle.
-/

namespace AccordLockFormal

/-- Durable phases of one execution transaction. -/
inductive TransactionPhase where
  | prepared
  | authorized
  | claimed
  | dispatched
  | effectKnown
  | effectUnknown
  | compensated
  | finalized
deriving DecidableEq, Repr

/-- Events accepted by the lifecycle. -/
inductive TransactionEvent where
  | authorize
  | claim
  | dispatch
  | observeEffect
  | loseResponse
  | reconcileEffect
  | compensate
  | finalize
deriving DecidableEq, Repr

/-- Illegal transitions return `none`; no caller can skip a required phase. -/
def advance : TransactionPhase → TransactionEvent → Option TransactionPhase
  | .prepared, .authorize => some .authorized
  | .authorized, .claim => some .claimed
  | .claimed, .dispatch => some .dispatched
  | .dispatched, .observeEffect => some .effectKnown
  | .dispatched, .loseResponse => some .effectUnknown
  | .effectUnknown, .reconcileEffect => some .effectKnown
  | .effectKnown, .compensate => some .compensated
  | .effectKnown, .finalize => some .finalized
  | .compensated, .finalize => some .finalized
  | _, _ => none

theorem authorization_requires_prepared {phase : TransactionPhase}
    (h : advance phase .authorize = some .authorized) :
    phase = .prepared := by
  cases phase <;> simp [advance] at h ⊢

theorem claim_requires_authorization {phase : TransactionPhase}
    (h : advance phase .claim = some .claimed) :
    phase = .authorized := by
  cases phase <;> simp [advance] at h ⊢

theorem dispatch_requires_claim {phase : TransactionPhase}
    (h : advance phase .dispatch = some .dispatched) :
    phase = .claimed := by
  cases phase <;> simp [advance] at h ⊢

theorem response_loss_requires_dispatch {phase : TransactionPhase}
    (h : advance phase .loseResponse = some .effectUnknown) :
    phase = .dispatched := by
  cases phase <;> simp [advance] at h ⊢

theorem reconciliation_requires_unknown_effect {phase : TransactionPhase}
    (h : advance phase .reconcileEffect = some .effectKnown) :
    phase = .effectUnknown := by
  cases phase <;> simp [advance] at h ⊢

theorem cannot_dispatch_before_claim :
    advance .authorized .dispatch = none := by
  rfl

theorem cannot_blindly_redispatch_unknown_effect :
    advance .effectUnknown .dispatch = none := by
  rfl

theorem reconciliation_restores_effect_knowledge :
    advance .effectUnknown .reconcileEffect = some .effectKnown := by
  rfl

theorem finalized_is_terminal (event : TransactionEvent) :
    advance .finalized event = none := by
  cases event <;> rfl

theorem prepared_to_finalized_path :
    advance .prepared .authorize = some .authorized ∧
    advance .authorized .claim = some .claimed ∧
    advance .claimed .dispatch = some .dispatched ∧
    advance .dispatched .observeEffect = some .effectKnown ∧
    advance .effectKnown .finalize = some .finalized := by
  decide

theorem lost_response_recovery_path :
    advance .dispatched .loseResponse = some .effectUnknown ∧
    advance .effectUnknown .reconcileEffect = some .effectKnown ∧
    advance .effectKnown .finalize = some .finalized := by
  decide

end AccordLockFormal
