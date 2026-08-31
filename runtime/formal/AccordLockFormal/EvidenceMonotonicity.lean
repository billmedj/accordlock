/-!
Restrict-only evidence evaluation. Evidence may preserve or reduce authority;
it cannot turn a stricter decision into a more permissive one.
-/

namespace AccordLockFormal

/-- Increasing strictness: allow < review < deny. -/
inductive Decision where
  | allow
  | review
  | deny
deriving DecidableEq, Repr

/-- The evidence interface does not pretend that an unknown is a pass. -/
inductive EvidenceFinding where
  | supports
  | unknown
  | contradicts
deriving DecidableEq, Repr

def strictness : Decision → Nat
  | .allow => 0
  | .review => 1
  | .deny => 2

/-- Evidence is applied as a restriction to an existing policy decision. -/
def applyEvidence : Decision → EvidenceFinding → Decision
  | prior, .supports => prior
  | .allow, .unknown => .review
  | .review, .unknown => .review
  | .deny, .unknown => .deny
  | _, .contradicts => .deny

def applyAll : Decision → List EvidenceFinding → Decision
  | prior, [] => prior
  | prior, finding :: rest => applyAll (applyEvidence prior finding) rest

theorem supporting_evidence_preserves (decision : Decision) :
    applyEvidence decision .supports = decision := by
  cases decision <;> rfl

theorem unknown_evidence_never_allows (decision : Decision) :
    applyEvidence decision .unknown ≠ .allow := by
  cases decision <;> decide

theorem contradiction_denies (decision : Decision) :
    applyEvidence decision .contradicts = .deny := by
  cases decision <;> rfl

theorem denial_is_absorbing (finding : EvidenceFinding) :
    applyEvidence .deny finding = .deny := by
  cases finding <;> rfl

theorem evidence_cannot_reduce_strictness (decision : Decision)
    (finding : EvidenceFinding) :
    strictness decision ≤ strictness (applyEvidence decision finding) := by
  cases decision <;> cases finding <;> decide

theorem evidence_sequence_cannot_reduce_strictness (decision : Decision)
    (findings : List EvidenceFinding) :
    strictness decision ≤ strictness (applyAll decision findings) := by
  induction findings generalizing decision with
  | nil => exact Nat.le_refl _
  | cons finding rest ih =>
      exact Nat.le_trans (evidence_cannot_reduce_strictness decision finding)
        (ih (applyEvidence decision finding))

/-- Once evaluation has abstained, later supporting evidence cannot silently
restore automatic execution within the same evidence sequence. -/
theorem review_evidence_sequence_never_allows (findings : List EvidenceFinding) :
    applyAll .review findings ≠ .allow := by
  intro allowedResult
  have monotone := evidence_sequence_cannot_reduce_strictness .review findings
  rw [allowedResult] at monotone
  simp [strictness] at monotone

/-- An unknown finding creates an abstention that cannot be erased by later
findings in the same evaluation. -/
theorem unknown_in_sequence_never_allows (decision : Decision)
    (rest : List EvidenceFinding) :
    applyAll decision (.unknown :: rest) ≠ .allow := by
  intro allowedResult
  have normalized : applyAll (applyEvidence decision .unknown) rest = .allow := by
    simpa [applyAll] using allowedResult
  have monotone := evidence_sequence_cannot_reduce_strictness
    (applyEvidence decision .unknown) rest
  rw [normalized] at monotone
  cases decision <;> simp [applyEvidence, strictness] at monotone

theorem denial_absorbs_evidence_sequence (findings : List EvidenceFinding) :
    applyAll .deny findings = .deny := by
  induction findings with
  | nil => rfl
  | cons finding rest ih =>
      simp [applyAll, denial_is_absorbing, ih]

theorem contradiction_in_front_denies (decision : Decision)
    (rest : List EvidenceFinding) :
    applyAll decision (.contradicts :: rest) = .deny := by
  simp [applyAll, contradiction_denies, denial_absorbs_evidence_sequence]

end AccordLockFormal
