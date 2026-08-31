# `accordlock-ingress`

This crate supplies the local application-layer authentication boundary between
an agent process and the AccordLock kernel.

An ingress request contains strict JSON claims plus a COSE Sign1 object. The
signature uses Ed25519 and the external-AAD domain
`accordlock:v1:authenticated-ingress-request`. The fixed canonical CBOR payload
commits to the audience, time window, nonce, request ID, declared tenant and
actor, and every deployment-template field.

The server treats the envelope `key_id` only as a registry lookup hint. COSE
verification requires the same protected key ID. An `ActivatedIngressRegistry`
maps that key to tenant, actor, validity, status, and allowed audiences. Its
domain-separated canonical root commits to every registration and must equal an
exact principal-registry authority state, including root, epoch, and activation
identifier. Entries are bounded, strictly sorted by key ID, and duplicate key
IDs or public-key aliases are rejected. Registry construction also validates
the Ed25519 public-key encoding, rejects weak public keys, and applies the
protocol key-ID profile before serving requests.

A signed proposal with a different tenant or actor is rejected; those request
strings never create trusted caller context. Successful authentication returns
an opaque, non-serializable `AuthenticatedIngressRequest` with private fields
and no public constructor. It preserves the exact proposal, registry-derived
caller, key ID, nonce, authentication time, signed expiry, and complete
principal-registry authority state for kernel revalidation.

The kernel carries the preserved signed expiry into the signed evaluation's
`consume_before` minimum. If the initial issuance snapshot is already at or
after that bound, issuance fails before signing. If time crosses the bound after
that snapshot, final state recording rejects the transient signature, and no
signed authorization is returned or recorded. This does not make the process-local
replay guard durable or establish a production transport.

Acceptance is fail-closed and ordered as follows:

1. enforce a 64 KiB request limit, then parse strict JSON and reject unknown fields;
2. select a registered key;
3. verify the domain-separated signature and exact canonical payload;
4. enforce schema, reject a nil nonce, then enforce key status, key validity, audience, request lifetime, and
   containment of the signed request window inside the registered key window;
5. compare proposal tenant and actor with the registry-derived caller;
6. record the trusted clock observation for the exact audience replay scope before applying
   request/key current-time checks, without consuming the nonce on rejection;
7. atomically consume the signed nonce;
8. return the opaque ingress result for one kernel-context construction.

`MemoryReplayGuard` is process-local and exists for tests and local demos. Its
high-water and nonce tuples are separated by the exact configured audience, and
expired tuples become reusable only at the exact expiry boundary. It is not
crash-safe, shared across replicas, or suitable for production.

`accordlock-ingress-state` supplies the narrow adapter to the lineage-bound,
serializable PostgreSQL ledger in `accordlock-state`. That adapter makes nonce
consumption durable and atomic across replicas and fails closed on storage or
commit uncertainty. It is not yet wired into a production ingress network
service or the Kubernetes admission webhook. The replay interface represents unavailable or
indeterminate state separately from a known replay, but both conditions deny
the request. The local guard also treats a backward clock step as indeterminate
instead of evicting and later reaccepting a nonce. A production adapter still
needs a trusted monotonic time policy. A public API may collapse those internal categories into one
generic authentication failure to avoid exposing an oracle.

The local guard records the time for an exactly authenticated request before
the temporal checks. An expired signed request observed at time `t` therefore
cannot become acceptable after a rollback below `t`. Unknown keys, bad
signatures, payload mismatches, wrong audiences, and caller-binding failures do
not advance this high-water state.

This crate does not implement or claim mTLS, SPIFFE, cloud workload identity,
HTTP routing, distributed key registration/revocation, rate limiting, or
production transport security. It establishes only a concrete, independently
testable application-signature boundary that those systems can terminate into.
