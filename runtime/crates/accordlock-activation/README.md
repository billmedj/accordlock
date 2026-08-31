# accordlock-activation

`accordlock-activation` is a deliberately isolated, synthetic verifier for the
three live deployment-boundary attestations that the EKS enforcement slice
still lacks:

- the exact live RBAC closures of the three separate broker-management
  identities;
- an authenticated webhook-caller origin boundary; and
- the Kubernetes API audience exercised against the exact live route.

The crate is a leaf. It depends on the protocol and immutable EKS-profile
crates, but not on state or enforcement. Nothing in this crate unlocks the
production enforcement path.

## What is signed

One attestation binds all of the following in deterministic, domain-separated
bytes:

- a bounded `ActivationScope` copied exactly, without trimming, case folding,
  or other normalization;
- the existing commitment to every field of the complete `EksRouteProfile`;
- the three distinct configured management subjects and RBAC commitments;
- the release commitment and a non-nil deployment activation identifier;
- the complete `AuthorityVector`, including every root, epoch, and activation
  identifier;
- three named, non-zero, pairwise-distinct proof commitments (there is no
  boolean verdict field);
- an independently expected payload bundle commitment and raw artifact-set
  commitment, plus a positive bounded artifact count;
- a non-nil anti-replay `evidence_id`, `observed_at`, and a short exclusive
  `valid_until`; and
- the exact activated signer-registry root, epoch, activation identifier, and
  full commitment.

The registered collector and operator are different identities, key IDs, and
Ed25519 public keys. They sign the same canonical claims under different COSE
external-AAD purposes. A collector signature cannot be moved into the operator
approval slot.

## Verification boundary

`ActivatedLiveBoundaryRegistry::verify_current` performs checks in this order:

1. bounded structural and canonical-commitment validation;
2. exact expected scope, route, management, release, activation, authority,
   three-proof, bundle, and current-registry comparisons;
3. collector and operator role/key/identity binding and both purpose-separated
   signatures;
4. trusted-current-time, attestation lifetime, and signer lifetime checks; and
5. process-local `evidence_id` consumption as the final operation.

Consequently, a malformed claim, mismatch, or invalid signature never mutates
the replay guard. The returned `VerifiedLiveDeploymentBoundaries` is opaque,
non-clonable, and non-serializable.

Possession of that value proves only that the supplied cryptographic envelopes,
bindings, current registry, trusted clock, and process-local replay guard passed
this verifier. It does **not** prove that the committed artifacts are truthful,
that the raw bytes were collected from EKS, that all workload zones were
enumerated, or that an external control remains in force.

## Deliberate production hold

This crate contains no EKS/Kubernetes/AWS collector, no raw-artifact store, no
offline-bundle decoder, no database-backed or distributed replay protocol, no
registry loader, and no integration with `accordlock-enforcement`. The included
signing helper and memory replay guard exist for synthetic verification and
tests only.

In particular, the Python activation validator's
`CANDIDATE_EVIDENCE_CLAIMS_VALIDATED` result is never accepted as input and
cannot be converted from a boolean into a live proof. A future production
collector must attest authenticated raw artifacts, an independent operator
must approve the exact same claims, and a durable current-registry/replay
transaction must be designed before any enforcement integration.
