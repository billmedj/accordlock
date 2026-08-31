import AccordLockFormal.AuthorityEpoch

/-!
Intent-artifact integrity for one authorization instance.
-/

namespace AccordLockFormal

/-- Canonical artifacts produced before dispatch. -/
structure ActionManifest where
  requestDigest : Digest
  planDigest : Digest
  actionDigest : Digest
  argumentsDigest : Digest
deriving DecidableEq, Repr

/-- The manifest must reproduce the intent chain embedded in the authorization. -/
def ManifestMatches (manifest : ActionManifest)
    (authorization : AuthorizationInstance) : Prop :=
  manifest.requestDigest = authorization.context.requestDigest ∧
  manifest.planDigest = authorization.context.planDigest ∧
  manifest.actionDigest = authorization.context.actionDigest ∧
  manifest.argumentsDigest = authorization.context.argumentsDigest

theorem matching_manifest_preserves_request {manifest : ActionManifest}
    {authorization : AuthorizationInstance}
    (h : ManifestMatches manifest authorization) :
    manifest.requestDigest = authorization.context.requestDigest :=
  h.1

theorem matching_manifest_preserves_plan {manifest : ActionManifest}
    {authorization : AuthorizationInstance}
    (h : ManifestMatches manifest authorization) :
    manifest.planDigest = authorization.context.planDigest :=
  h.2.1

theorem matching_manifest_preserves_action {manifest : ActionManifest}
    {authorization : AuthorizationInstance}
    (h : ManifestMatches manifest authorization) :
    manifest.actionDigest = authorization.context.actionDigest :=
  h.2.2.1

theorem matching_manifest_preserves_arguments {manifest : ActionManifest}
    {authorization : AuthorizationInstance}
    (h : ManifestMatches manifest authorization) :
    manifest.argumentsDigest = authorization.context.argumentsDigest :=
  h.2.2.2

theorem changed_plan_invalidates_manifest {manifest : ActionManifest}
    {authorization : AuthorizationInstance}
    (changed : manifest.planDigest ≠ authorization.context.planDigest) :
    ¬ ManifestMatches manifest authorization := by
  intro h
  exact changed (matching_manifest_preserves_plan h)

theorem changed_arguments_invalidate_manifest {manifest : ActionManifest}
    {authorization : AuthorizationInstance}
    (changed : manifest.argumentsDigest ≠
      authorization.context.argumentsDigest) :
    ¬ ManifestMatches manifest authorization := by
  intro h
  exact changed (matching_manifest_preserves_arguments h)

end AccordLockFormal
