# AccordLock authorization kernel

`accordlock-kernel` is the deterministic authorization oracle used by the local
AccordLock candidate. It evaluates authenticated evidence against trusted policy
without consulting an AI model. It does not retrieve evidence, operate a key,
consume authorizations, or execute provider actions.

## Activated attester registry

Raw `Vec<RegisteredAttester>` values are not accepted by `KernelContext`.
`ActivatedAttesterRegistry::new` requires a nonempty, bounded registry whose
entries are strictly sorted by issuer and key identifier, whose scopes are
strictly sorted and duplicate-free, and whose identities and Ed25519 keys pass
the local profile. A public key may occur only once.

The registry root is SHA-256 over a domain-separated, length-framed canonical
encoding of every security-relevant field, including tenant, environment,
issuer, key identifier, public key, principal, grade, status, and scopes. The
computed root must equal the supplied registry authority root. `KernelContext`
then requires the registry's complete authority-domain state, including epoch
and activation identifier, to equal `active_authority.registry`.

The root proves equality with committed registry bytes. It does not prove that
the registered parties are honest, independent, correctly scoped by an
operator, or truthful in a particular assertion.

`KernelContext` fields are private. The productive constructor consumes an
opaque, non-cloneable `ControlEvaluationWork` returned by durable state. Caller
identity, scope, proposal, evaluation nonce, ingress window, active authority,
and `now` therefore cannot be supplied by the worker: `now` is exactly the
state-owned lease claim time. The constructor rejects malformed lease lineage,
clock rollback, expiry, scope/identity substitution, and any ingress-registry,
policy, or attester-registry authority mismatch. It also requires
`lease_until > claimed_at`.

`evaluate_control` consumes the context, evaluates only its embedded proposal,
requires an evaluator key committed by the active kernel-configuration root,
and returns the exact one-shot work capability with a signed evaluation so no
mutable unsigned attestation crosses the product boundary. The public legacy
`evaluate` operation rejects durable contexts. The older
`from_authenticated_ingress`/`evaluate` pair remains a synchronous local
harness path during migration; it is not the v13 worker boundary.

The exact signed proposal is retained in the context. Legacy `evaluate` rejects a
different proposal, even when tenant and actor strings happen to match. The
constructor separately checks the canonical policy root, activated attester
registry domain, nonzero authority roots and activation identifiers, caller
binding, and evaluation nonce.

The accepted ingress expiry is also included in the minimum that produces the
signed evaluation's `consume_before`. An evaluation therefore cannot authorize
issuance beyond the request-authentication window without changing signed
bytes. The issuer's trusted time must still be checked against that bound.

## Authorization verification

The authorization API separates two different statements:

- `verify_authorization_signature` checks only the deterministic COSE profile,
  execution-authorization domain, signature, and equality with the wrapper's canonical
  payload. It does not authorize execution.
- `verify_authorization_in_explicit_context`, and the equivalent entry point
  `verify_authorization`, additionally require an
  `ExplicitAuthorizationVerificationContext` containing caller-provided time, expected
  executor audience, and a complete authority vector. Success returns an opaque
  `ContextVerifiedAuthorization` marker.

Contextual verification checks schema v2 and its signed single-use profile,
non-nil identifiers, validity relative to the supplied time, a nonempty deadline
window, exact audience and authority, the authorization-signer root in the supplied
authority, canonical template hash, policy-root binding, bounded sorted
principals, nonempty operation and resource identities, and nonzero security
commitments. Neither the explicit context nor `ContextVerifiedAuthorization` proves
that the supplied time or authority is current. A productive dispatch path must
start from durable single-use consumption, obtain the exclusive state-backed
dispatch claim, revalidate current authority, grant, revocation, clock, lease,
deadline, receipt, and outbox bindings, then commit the one-shot
`ATTEMPT_IN_FLIGHT` marker. A naked historical `DispatchSnapshot` is not
execution authority, and even the durable attempt marker does not prove that a
provider effect occurred.
