import AccordLockFormal.AuthorityEpoch

/-!
Single-use, non-amplifying execution grants.
-/

namespace AccordLockFormal

abbrev GrantId := Nat

/-- A grant contains no ambient authority: it repeats one authorization binding. -/
structure ExecutionGrant where
  grantId : GrantId
  authorizationId : AuthorizationId
  context : AuthorityContext
deriving DecidableEq, Repr

/-- The grant conveys exactly the authorization instance it references. -/
def GrantMatches (grant : ExecutionGrant)
    (authorization : AuthorizationInstance) : Prop :=
  grant.authorizationId = authorization.authorizationId ∧
  grant.context = authorization.context

/-- A grant is usable only if it matches and has not already been consumed. -/
def GrantUsable (grant : ExecutionGrant)
    (authorization : AuthorizationInstance) (consumed : List GrantId) : Prop :=
  GrantMatches grant authorization ∧ grant.grantId ∉ consumed

theorem usable_grant_matches_authorization {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId}
    (h : GrantUsable grant authorization consumed) :
    grant.authorizationId = authorization.authorizationId :=
  h.1.1

theorem usable_grant_cannot_amplify_context {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId}
    (h : GrantUsable grant authorization consumed) :
    grant.context = authorization.context :=
  h.1.2

theorem usable_grant_preserves_action {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId}
    (h : GrantUsable grant authorization consumed) :
    grant.context.actionDigest = authorization.context.actionDigest := by
  exact congrArg AuthorityContext.actionDigest
    (usable_grant_cannot_amplify_context h)

theorem usable_grant_preserves_target {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId}
    (h : GrantUsable grant authorization consumed) :
    grant.context.targetStateDigest =
      authorization.context.targetStateDigest := by
  exact congrArg AuthorityContext.targetStateDigest
    (usable_grant_cannot_amplify_context h)

theorem consumed_grant_rejected {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId}
    (used : grant.grantId ∈ consumed) :
    ¬ GrantUsable grant authorization consumed := by
  intro h
  exact h.2 used

theorem grant_cannot_be_replayed {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId} :
    ¬ GrantUsable grant authorization (grant.grantId :: consumed) := by
  intro secondUse
  exact secondUse.2 (List.Mem.head consumed)

theorem wrong_authorization_rejected {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId}
    (wrong : grant.authorizationId ≠ authorization.authorizationId) :
    ¬ GrantUsable grant authorization consumed := by
  intro h
  exact wrong h.1.1

theorem changed_grant_context_rejected {grant : ExecutionGrant}
    {authorization : AuthorizationInstance} {consumed : List GrantId}
    (changed : grant.context ≠ authorization.context) :
    ¬ GrantUsable grant authorization consumed := by
  intro h
  exact changed h.1.2

end AccordLockFormal
