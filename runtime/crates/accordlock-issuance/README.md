# `accordlock-issuance`

This crate is the state-backed authorization-issuance boundary for the local candidate.
The productive `issue_or_recover` operation consumes an opaque, non-cloneable
`ControlIssuanceWork`; it accepts no proposal, scope, grant identifier, signed
evaluation, clock, or authority as independent call arguments. State validates
the exact ISSUE lease/fence/decision and current grant, and returns an opaque
snapshot whose `issued_at` is fixed to the durable claim time. The issuer then
verifies the active evaluator and authorization-signer roots, derives identifiers
internally, and deterministically signs ExecutionAuthorization v2.

The final state operation atomically records or exactly recovers the expected
authorization, links it to the control submission/status, and advances ISSUE to
CONSUME. It rechecks the active lease, authority, grant, revocation, time, and
every signed field. Recovery succeeds only when the durable record, signature,
signer material, identifiers, and control lineage equal the freshly derived
record byte-for-byte; no second variant is signed. An ambiguous commit returns
an explicit error and never releases signed bytes or a consume capability.

The older `issue` operation is retained only for synchronous v12/local harness
migration. It has a split record boundary and is not the productive v13 path.

The current `SigningIdentity` is a software key held in process memory. The
crate does not provide HSM/KMS custody, workload authentication, a network
signer service, role-enforced domain separation, rotation ceremonies, or proof
that other trusted in-process code cannot call generic signing primitives.
Public deterministic CLI seeds are test material. Any production unsignability
claim therefore depends on a separately implemented and reviewed key-confinement
boundary.
