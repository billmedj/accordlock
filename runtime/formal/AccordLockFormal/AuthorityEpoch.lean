/-!
Copyright 2026 AccordLock contributors. Licensed under Apache-2.0.

Exact authority-context binding. An authorization is valid for one principal,
policy epoch, configuration epoch, intent chain, argument set, and target state.
-/

namespace AccordLockFormal

abbrev Digest := Nat
abbrev PrincipalId := Nat
abbrev AuthorizationId := Nat

/-- Every value that can change the meaning or authority of an action. -/
structure AuthorityContext where
  principalId : PrincipalId
  policyEpoch : Nat
  configurationEpoch : Nat
  requestDigest : Digest
  planDigest : Digest
  actionDigest : Digest
  argumentsDigest : Digest
  targetStateDigest : Digest
deriving DecidableEq, Repr

/-- A durable authorization instance issued for an exact authority context. -/
structure AuthorizationInstance where
  authorizationId : AuthorizationId
  context : AuthorityContext
  issuedAt : Nat
  expiresAt : Nat
deriving DecidableEq, Repr

/-- Exact context equality is the authority boundary. -/
def BoundTo (authorization : AuthorizationInstance)
    (current : AuthorityContext) : Prop :=
  authorization.context = current

/-- The authorization can only be used inside its half-open validity interval. -/
def ActiveAt (authorization : AuthorizationInstance) (now : Nat) : Prop :=
  authorization.issuedAt ≤ now ∧ now < authorization.expiresAt

/-- Issuance precedes expiry. -/
def WellFormedAuthorization (authorization : AuthorizationInstance) : Prop :=
  authorization.issuedAt < authorization.expiresAt

theorem bound_principal {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.principalId = current.principalId := by
  exact congrArg AuthorityContext.principalId h

theorem bound_policy_epoch {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.policyEpoch = current.policyEpoch := by
  exact congrArg AuthorityContext.policyEpoch h

theorem bound_configuration_epoch {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.configurationEpoch = current.configurationEpoch := by
  exact congrArg AuthorityContext.configurationEpoch h

theorem bound_request {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.requestDigest = current.requestDigest := by
  exact congrArg AuthorityContext.requestDigest h

theorem bound_plan {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.planDigest = current.planDigest := by
  exact congrArg AuthorityContext.planDigest h

theorem bound_action {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.actionDigest = current.actionDigest := by
  exact congrArg AuthorityContext.actionDigest h

theorem bound_arguments {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.argumentsDigest = current.argumentsDigest := by
  exact congrArg AuthorityContext.argumentsDigest h

theorem bound_target_state {authorization : AuthorizationInstance}
    {current : AuthorityContext} (h : BoundTo authorization current) :
    authorization.context.targetStateDigest = current.targetStateDigest := by
  exact congrArg AuthorityContext.targetStateDigest h

theorem stale_policy_epoch_rejected {authorization : AuthorizationInstance}
    {current : AuthorityContext}
    (stale : authorization.context.policyEpoch ≠ current.policyEpoch) :
    ¬ BoundTo authorization current := by
  intro h
  exact stale (bound_policy_epoch h)

theorem stale_configuration_epoch_rejected
    {authorization : AuthorizationInstance} {current : AuthorityContext}
    (stale : authorization.context.configurationEpoch ≠
      current.configurationEpoch) :
    ¬ BoundTo authorization current := by
  intro h
  exact stale (bound_configuration_epoch h)

theorem changed_target_state_rejected {authorization : AuthorizationInstance}
    {current : AuthorityContext}
    (changed : authorization.context.targetStateDigest ≠
      current.targetStateDigest) :
    ¬ BoundTo authorization current := by
  intro h
  exact changed (bound_target_state h)

theorem expired_authorization_inactive (authorization : AuthorizationInstance)
    (now : Nat) (expired : authorization.expiresAt ≤ now) :
    ¬ ActiveAt authorization now := by
  intro h
  exact (Nat.not_lt_of_ge expired) h.2

theorem authorization_inactive_before_issuance
    (authorization : AuthorizationInstance) (now : Nat)
    (early : now < authorization.issuedAt) :
    ¬ ActiveAt authorization now := by
  intro h
  exact (Nat.not_le_of_gt early) h.1

end AccordLockFormal
