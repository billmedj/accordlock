# accordlock-service

`accordlock-service` is a transport-independent application composition boundary.
It is not an HTTP server, a persistence layer, or a production executor.

## Submission boundary

There is one action intent and one only: `AgentProposal` inside the signed
`accordlock-ingress` request. The former parallel `SubmitIntent`, public tenant and
actor identity types, caller-selected grant lookup, and generic proof object
have been removed.

The public flow is exact:

1. `SubmissionEnvelope::from_bytes` owns and bounds the unchanged signed bytes.
2. `AccordLockService::submit` gives those bytes to its fixed `TrustedIngress` TCB
   adapter.
3. The adapter must strictly decode, authenticate, bind, freshness-check, and
   replay-consume the signed envelope. It returns the non-constructible
   `accordlock_ingress::AuthenticatedIngressRequest`.
4. The service moves that opaque capability into `TrustedWorkflow`.
5. `TrustedAuthorizer::authorize` consumes the capability by value. A real
   adapter can therefore move it directly into
   `KernelContext::from_authenticated_ingress`; it never needs to clone it,
   reduce it to public identity strings, or reconstruct it.
6. Both authorization outcomes return an adapter-private authenticated
   submission scope for status recording. This scope is not an execution
   capability. It exists only because the ingress capability has already been
   consumed by the kernel path.

Grant selection, current policy, evidence, authority state, clocks, keys,
authorizations, credentials, claims, provider routes, and executable commands remain
trusted adapter state. They are not public request fields.

## Status boundary

`StatusLookup` contains only a receipt lookup key. It conveys no read or
execution authority. `StatusEnvelope` pairs the lookup with bounded signed
authentication bytes. The fixed ingress adapter must bind those bytes to the
exact lookup and return its own opaque `AuthenticatedStatusScope` type.

The status store receives both that authenticated scope and the lookup. Its
key must include every isolation dimension (at least tenant and environment,
and actor when policy requires it). A lookup in another valid scope returns
the same public `StatusNotFound` result as an absent record. The facade also
rejects any store result whose receipt ID differs from the requested lookup.

`SubmissionReceipt` and `StatusView` contain only request/receipt identifiers,
a closed state, and an optional coarse reason. Neither exposes an ingress
capability, authorization, authorization, credential, dispatch claim, command,
signature, nonce, or state mutation method.

## Trusted orchestration

`TrustedPipeline` fixes five dependencies at construction:

1. `TrustedClock`
2. `TrustedAuthorizer`
3. `TrustedCommitter`
4. `TrustedDispatcher`
5. `TrustedStatusStore`

For an authorized request, the pipeline obtains trusted time independently at
evaluation, commit, and dispatch and rejects intra-request rollback. The
authorizer emits an opaque authorization and a private status scope. The
committer consumes the authorization and returns an opaque committed authorization.
The dispatcher consumes the authorization. Only the private status scope survives to
the projection store.

Detailed trusted failures collapse to coarse public errors. In particular,
authentication and replay rejection are public request rejection, while
indeterminate ingress state is a control-availability failure.

## Required production wiring

This crate still needs real adapters and composition:

- a `TrustedIngress` adapter around the durable `accordlock-ingress` replay path,
  with a trusted server clock and exact error classification;
- a separate canonical, signed, replay-protected status-authentication schema;
- a `TrustedAuthorizer` that consumes `AuthenticatedIngressRequest` through
  the real kernel and selects grants/evidence/current authority server-side;
- the durable authorization issuer/committer, private worker/outbox, and mediated EKS
  executor;
- a status store physically separated from execution authority and keyed by
  the complete authenticated scope;
- recovery, takeover, observability, rate limiting, and operational controls.

## Current limits

- No HTTP, TLS, gRPC, MCP, or CLI transport.
- No production authentication or status-authentication adapter.
- No real database, durable outbox, or recovery worker in this crate.
- No signing, Kubernetes mutation, provider credential, or live dispatch
  implementation in this crate.
- No multi-process recovery, high availability, benchmark, deployment, or
  independent security review.
- The tests use the real signed proposal ingress and a deliberately local mock
  status authenticator/store; they are boundary tests, not production wiring.

Run:

```text
cargo test -p accordlock-service --all-targets
cargo test -p accordlock-service --doc
cargo clippy -p accordlock-service --all-targets -- -D warnings
cargo fmt --check
```
