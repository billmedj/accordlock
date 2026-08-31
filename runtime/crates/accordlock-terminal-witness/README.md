# `accordlock-terminal-witness`

This leaf crate defines two purpose-separated, canonical, Ed25519/COSE witness
profiles:

- an exact terminal effect observation; and
- retirement of the exact credential bound to that attempt.

Every verified result is opaque and can be produced only after verification
against an activated, canonical registry. Registry entries bind verifier keys
to one scope, cluster, issuer identity, evidence purpose, validity/cutoff
interval, authority version, and authorizing-root commitment. The deterministic
state-binding registry commitment covers both the canonical material root and
the exact registry epoch plus activation ID. Reusing the same keys in another
activation therefore produces a different commitment. A future trusted
control-plane path can bind that full commitment into AccordLock's mediation
authority; `material_root()` is exposed separately and is not a substitute.

The exact-effect profile is limited to
`KubernetesDeploymentUpdatedV1`. It binds the complete frozen attempt tuple,
route commitment, all six required effect bindings (including the token
digest), exact admission linkage, complete response/post-state observation,
API-server resource identity/version, and observation interval. There is
deliberately no constructible `NO_EFFECT`, absence, HTTP-rejection,
GET-old-state, or generic no-change witness profile.

Credential retirement always includes an authenticated exact Secret-deletion
observation and either exact post-deletion `TokenReview` rejection evidence or
a conservative safe-after value computed from a complete immutable policy
snapshot. `TerminalAttemptBinding::commitment()` covers the complete canonical
attempt. The `TokenReview` request commitment is a fixed, bearer-free payload
commitment derived from that attempt plus the exact credential; it is never a
caller value or a hash of JSON containing the raw bearer. The Secret-deletion
commitment is likewise derived from the attempt, credential, journal entry,
exact journal request/result/provider-evidence commitments, and the trusted
completion time. Verification requires those exact durable expectations. A
caller cannot directly supply any of these commitments, the safe-after value,
or observer-selected policy maxima.

Both signed profiles expose bounded, deterministic canonical claims and exact
persistence-envelope bytes. Strict restart decoding rejects wrong
schema/role/arity, indefinite or non-minimal CBOR, trailing data, oversized
claims/COSE, and any claims that do not round-trip byte-for-byte. Decoding
creates only an unverified artifact; the activated registry must still produce
the opaque `Verified*` value.

## Non-claims

This crate does **not** establish that an observer tells the truth, provision
or protect production signing keys, activate its own trust root, contact
Kubernetes, authenticate an API server, perform TokenReview, delete a Secret,
persist evidence, mutate AccordLock state, release a physical reservation, or make
terminalization safe by itself. A verifier registration is trusted only when a
separate authenticated control-plane path activates its registry commitment.

In particular, these artifacts are not authorization and expose no state
release API. Future durable state integration must still compare every field
with immutable attempt state, require both witness profiles, use trusted time,
retain the signed bytes, and commit terminal history plus reservation release
atomically with exact ambiguity recovery.
