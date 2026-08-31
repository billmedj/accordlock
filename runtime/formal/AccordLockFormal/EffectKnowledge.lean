/-!
Effect knowledge and safe retry rules.
-/

namespace AccordLockFormal

inductive DispatchResult where
  | confirmedApplied
  | confirmedNotApplied
  | responseLost
deriving DecidableEq, Repr

inductive OutcomeKnowledge where
  | applied
  | notApplied
  | unknown
  | compensated
deriving DecidableEq, Repr

def recordDispatchResult : DispatchResult → OutcomeKnowledge
  | .confirmedApplied => .applied
  | .confirmedNotApplied => .notApplied
  | .responseLost => .unknown

/-- Another dispatch is safe only after positive evidence of non-application. -/
def SafeToDispatchAgain : OutcomeKnowledge → Prop
  | .notApplied => True
  | _ => False

def RequiresReconciliation : OutcomeKnowledge → Prop
  | .unknown => True
  | _ => False

inductive EndpointObservation where
  | applied
  | notApplied
deriving DecidableEq, Repr

def reconcile : OutcomeKnowledge → EndpointObservation → OutcomeKnowledge
  | .unknown, .applied => .applied
  | .unknown, .notApplied => .notApplied
  | known, _ => known

theorem lost_response_records_unknown :
    recordDispatchResult .responseLost = .unknown := by
  rfl

theorem unknown_effect_blocks_retry :
    ¬ SafeToDispatchAgain .unknown := by
  simp [SafeToDispatchAgain]

theorem applied_effect_blocks_retry :
    ¬ SafeToDispatchAgain .applied := by
  simp [SafeToDispatchAgain]

theorem confirmed_non_application_allows_retry :
    SafeToDispatchAgain .notApplied := by
  simp [SafeToDispatchAgain]

theorem only_unknown_effect_requires_reconciliation (state : OutcomeKnowledge) :
    RequiresReconciliation state ↔ state = .unknown := by
  cases state <;> simp [RequiresReconciliation]

theorem applied_observation_resolves_unknown :
    reconcile .unknown .applied = .applied := by
  rfl

theorem negative_observation_resolves_unknown :
    reconcile .unknown .notApplied = .notApplied := by
  rfl

theorem reconciliation_does_not_overwrite_known_applied
    (observation : EndpointObservation) :
    reconcile .applied observation = .applied := by
  cases observation <;> rfl

end AccordLockFormal
