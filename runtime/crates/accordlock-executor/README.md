# `accordlock-executor`

This crate is the local native EKS effect boundary for the
`DEPLOY_EKS_IMAGE_V1` profile. It is intentionally narrower than an EKS
operator, a generic Kubernetes client, or a policy engine.

## What it enforces

`ExclusiveEksExecutor::execute` consumes, by value:

1. the opaque, non-clonable `AuthorizedProviderAttempt` returned only after
   the state-backed `ATTEMPT_IN_FLIGHT` transition; and
2. a non-clonable `ExclusiveBearer` plus the authorization-bound
   `DeploymentTemplate`.

The executor then:

1. requires the executor and transport to expose the same complete
   `EksRouteProfile`, then matches the attempt and template to the route's
   cluster, API server, namespace, Deployment name/UID, ServiceAccount UID,
   and Kubernetes token audience;
2. re-derives the template hash, operation hash, fixed native-command
   commitment, and provider-wire commitment;
3. hashes the bearer and compares it with the attempt binding;
4. performs a native GET, authenticates the API-server identity, validates all
   bound preconditions, and compares the complete pre-state snapshot
   commitment;
5. acquires a process-wide, per-physical-resource high-water fence;
6. checks trusted time against the state-derived dispatch deadline, claim
   lease, and exact credential `[nbf, exp)` interval at the last local point
   before PATCH, using the committed acquisition lease rather than the stable
   claim lease, then requires token, dispatch deadline, and acquisition lease
   all to outlive the transport's complete operation-timeout upper bound plus
   rooted clock uncertainty;
7. passes a one-shot authorization into the native transport; after TLS and
   immediately before its first HTTP byte the guard resamples trusted time and
   revalidates the strict horizon, then calls PATCH once with the exact compact
   JSON bytes committed by `accordlock-k8s`;
8. exposes the re-derived `provider_request_commitment` to the transport for a
   future admission binding;
9. authenticates and parses the exact PATCH response body, validates the
   complete authorized delta in that response, and produces typed
   `EksEffectObservation` and `ExactEffectEvidence` values; and
10. permanently quarantines the process-local resource after an ambiguous
    send or an unverifiable success response.

There is no shell path, caller-selected HTTP method, caller-selected provider
path, caller-selected media type, or caller-selected PATCH body.

## Native transport contract

`NativeEksTransport` has exactly two operations:

- a read-only GET of the bound Deployment;
- one PATCH with `application/json-patch+json` and exact committed bytes.

The transport is part of the trusted computing base. It must authenticate the
configured API-server identity, return the exact response body, classify a
mutation failure conservatively, and never retry a PATCH. A production adapter
must return its immutable `EksRouteProfile`; structural mismatch is rejected
before GET or PATCH. It must also expose a truthful upper bound for the full
PATCH operation; a zero, overflowing, or near-expiry bound fails closed before
the bearer is written. For PATCH it must consume the supplied pre-write guard
after authenticating TLS/ALPN/peer pinning and immediately before the first
application write. Guard failure is `DefinitelyNotSent`; any failure after the
guard passes is `OutcomeUnknown`.
The trait exists so the security boundary can be tested without `kubectl`, a
shell, a live cluster, or hidden command construction.

The current executor does not issue a separate final GET after PATCH. A
non-success status received after the send therefore does not establish
no-effect, even when it is authenticated; it quarantines the local resource as
an unknown outcome.

## What this does not prove

This crate does **not** close PA-08 by itself.

- The fence is monotone and exclusive only among cooperating executor
  instances in one process. It is neither durable across process restarts nor
  enforced by Kubernetes.
- The `local_fence` sent to the transport is telemetry. It is not represented
  as destination-attested evidence.
- `provider_request_commitment` is exposed for a future admission profile, but
  the current API server does not verify or consume it.
- Once `ATTEMPT_IN_FLIGHT` exists, a subsequent authority change cannot be
  rechecked through the current state API. The executor can enforce the
  already-derived deadline, not destination-time authority currentness.
- Rust ownership does not prove that another process, administrator, issuer,
  or copied configuration lacks the destination credential. Exclusive bearer
  custody is an operational deployment invariant.
- A transport implementation can violate its trait contract. Production trust
  requires implementation review, TLS identity validation, least-privilege
  RBAC, process isolation, and bypass-denial tests.

Closing the remaining boundary requires a destination admission mechanism
that validates the durable claim, canonical physical key, deadline, fence or
generation, and `provider_request_commitment`, then durably consumes a unique
admission UID before allowing the mutation. It also requires that no alternate
credential can bypass that mechanism.

## Adversarial tests

The unit suite covers:

- exact byte emission and typed evidence construction;
- template substitution;
- bearer substitution;
- deadline expiry after the final GET and before PATCH;
- insufficient token lifetime for PATCH timeout plus clock uncertainty;
- a clock jump during TLS rejected by the post-TLS guard with zero PATCH bytes;
- takeover using a live acquisition tuple even when stable-token lease fields
  describe the expired prior generation;
- stale process-local fences;
- ambiguous-send quarantine;
- no retry after known non-delivery;
- authenticated API-server substitution;
- cluster, DNS/SNI, socket, CA, namespace, Deployment UID, ServiceAccount UID,
  and token-audience route substitution;
- malformed success responses;
- unauthorized response deltas; and
- pre-state snapshot drift.

## Workspace integration

The crate is a root workspace member. Run:

```text
cargo test -p accordlock-executor
cargo clippy -p accordlock-executor --all-targets -- -D warnings
```

The crate has deliberately not added a CLI or a live network adapter. Those
would create a new productive credential path and must be reviewed together
with deployment isolation and destination admission.
