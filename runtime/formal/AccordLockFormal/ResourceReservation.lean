/-!
Exact, componentwise resource reservations. Natural-number accounting avoids
floating-point ambiguity in authority-affecting limits.
-/

namespace AccordLockFormal

/-- Three representative shared-resource dimensions. -/
structure ResourceVector where
  cpuMilli : Nat
  memoryMiB : Nat
  operationUnits : Nat
deriving DecidableEq, Repr

def ResourceVector.zero : ResourceVector :=
  { cpuMilli := 0, memoryMiB := 0, operationUnits := 0 }

def ResourceVector.add (left right : ResourceVector) : ResourceVector :=
  { cpuMilli := left.cpuMilli + right.cpuMilli
    memoryMiB := left.memoryMiB + right.memoryMiB
    operationUnits := left.operationUnits + right.operationUnits }

/-- Every resource dimension must fit; no scalar score can hide one overflow. -/
def Fits (usage capacity : ResourceVector) : Prop :=
  usage.cpuMilli ≤ capacity.cpuMilli ∧
  usage.memoryMiB ≤ capacity.memoryMiB ∧
  usage.operationUnits ≤ capacity.operationUnits

structure ResourceReservation where
  reservationId : Nat
  demand : ResourceVector
deriving DecidableEq, Repr

def aggregateReservations : List ResourceReservation → ResourceVector
  | [] => ResourceVector.zero
  | reservation :: rest =>
      ResourceVector.add reservation.demand (aggregateReservations rest)

def ReservationsAdmissible (reservations : List ResourceReservation)
    (capacity : ResourceVector) : Prop :=
  Fits (aggregateReservations reservations) capacity

theorem zero_resources_fit (capacity : ResourceVector) :
    Fits ResourceVector.zero capacity := by
  constructor
  · exact Nat.zero_le _
  constructor
  · exact Nat.zero_le _
  · exact Nat.zero_le _

theorem resources_fit_themselves (resources : ResourceVector) :
    Fits resources resources := by
  exact ⟨Nat.le_refl _, Nat.le_refl _, Nat.le_refl _⟩

theorem resource_fit_is_transitive {usage reservation capacity : ResourceVector}
    (first : Fits usage reservation) (second : Fits reservation capacity) :
    Fits usage capacity := by
  exact ⟨Nat.le_trans first.1 second.1,
    Nat.le_trans first.2.1 second.2.1,
    Nat.le_trans first.2.2 second.2.2⟩

theorem combined_local_limits_compose {usageA usageB capacityA capacityB : ResourceVector}
    (fitA : Fits usageA capacityA) (fitB : Fits usageB capacityB) :
    Fits (ResourceVector.add usageA usageB)
      (ResourceVector.add capacityA capacityB) := by
  exact ⟨Nat.add_le_add fitA.1 fitB.1,
    Nat.add_le_add fitA.2.1 fitB.2.1,
    Nat.add_le_add fitA.2.2 fitB.2.2⟩

theorem left_usage_within_aggregate (left right : ResourceVector) :
    Fits left (ResourceVector.add left right) := by
  exact ⟨Nat.le_add_right _ _, Nat.le_add_right _ _, Nat.le_add_right _ _⟩

theorem component_within_shared_capacity {left right capacity : ResourceVector}
    (combined : Fits (ResourceVector.add left right) capacity) :
    Fits left capacity := by
  exact resource_fit_is_transitive (left_usage_within_aggregate left right) combined

theorem empty_reservations_admissible (capacity : ResourceVector) :
    ReservationsAdmissible [] capacity := by
  exact zero_resources_fit capacity

theorem aggregate_cons (reservation : ResourceReservation)
    (rest : List ResourceReservation) :
    aggregateReservations (reservation :: rest) =
      ResourceVector.add reservation.demand (aggregateReservations rest) := by
  rfl

theorem two_reservations_respect_combined_limits
    (first second : ResourceReservation)
    (firstLimit secondLimit : ResourceVector)
    (firstFits : Fits first.demand firstLimit)
    (secondFits : Fits second.demand secondLimit) :
    Fits (aggregateReservations [first, second])
      (ResourceVector.add firstLimit secondLimit) := by
  simpa [aggregateReservations, ResourceVector.add, ResourceVector.zero] using
    combined_local_limits_compose firstFits secondFits

end AccordLockFormal
