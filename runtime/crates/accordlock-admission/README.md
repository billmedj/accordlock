# `accordlock-admission`

This crate is the pure destination-side admission profile for
`DEPLOY_EKS_IMAGE_V1`. It validates one bounded Kubernetes `AdmissionReview`,
recomputes the AccordLock mutation bindings, and asks an `AdmissionLedger` to
atomically authorize or recover one exact admission UID.

It is an executable specification plus a transactional-state adapter. It is
not yet a deployed Kubernetes webhook and does not by itself close PA-08.

## Productive entry point

`StateAdmissionEngine` is the request-facing library boundary intended for the
future HTTPS webhook. It is configured once with a trusted destination
profile, tenant/environment scope, and observer-identity commitment. Its
per-request method accepts only:

- bounded `AdmissionReview` bytes; and
- a `TransactionalState` backend.

It accepts no HTTP-supplied marker, runtime, authority, clock value, claim ID,
fence, template, physical identity, or provider commitment. It extracts the
canonical transaction ID and execution authorization ID from the final object's reserved
annotations as routing inputs only. State then returns a non-serializable
`AdmissionContext` containing the in-flight claim, signed template, physical
reservation, provider commitment, current authority, trusted time, deadline,
and fence. The engine builds its internal marker and runtime from that opaque
context. `StateBackedAdmissionLedger` obtains a fresh context and the final
state transaction repeats all currentness and replay checks before ALLOW.

`AdmissionEngine::evaluate`, `AdmissionMarker::for_model`,
`AdmissionRuntime::for_model`, and `InMemoryAdmissionLedger` remain the pure
conformance surface. They are not the productive webhook API.

## Inputs checked

For a non-dry-run `UPDATE` of one `apps/v1` Deployment, the engine checks:

- strict `AdmissionReview` framing with unknown typed fields rejected;
- a 1 MiB review limit and 512 KiB limits for each old/new object;
- the exact executor service-account username and exact authenticated group
  set;
- Deployment group, version, kind, resource, operation, name, and namespace;
- absence of a subresource and an object/oldObject pair;
- the authenticated marker's tenant/environment scope, transaction, authorization,
  durable claim ID, physical key, deadline, authority version, and fence;
- canonical template, operation, and provider-request commitments re-derived
  from the trusted template;
- exact old-to-new mutation behavior through `accordlock-k8s`, including UID,
  resourceVersion, prior image, reserved annotations, final image, transaction,
  authorization, and operation hash; and
- non-zero executor and webhook-observer identity commitments before the
  atomic ledger call.

The engine does not observe the original HTTP PATCH bytes. It re-derives the
expected `provider_request_commitment` and proves that the admitted old/new
object delta is the one bound to the attempt. This is a payload admission
binding, not an independent wire capture.

## Atomic ledger contract

`AdmissionLedger::authorize_or_recover` receives one complete
`AdmissionAuthorizationClaim`. A production implementation must perform all
checks and writes in one transaction:

- exact same UID and exact same complete claim may recover idempotently;
- same UID with different material is denied;
- the same transaction with a second UID is denied;
- durable claim-ID reuse is denied;
- provider-request commitment replay is denied;
- a fence not greater than the physical-resource high-water mark is denied;
- deadline expiry and current-authority mismatch are denied; and
- storage ambiguity fails closed.

`StateBackedAdmissionLedger` maps a validated review to
`TransactionalState::authorize_admission_or_recover`. The state adapter
independently reloads and revalidates the signed authorization, durable claim,
physical reservation, current authority and grant, trusted time, frozen
deadline, and provider request commitment. PostgreSQL and in-memory state
implement the same interface. The in-memory implementation remains only a
conformance oracle and local-development adapter.

## Dry-run behavior

The pure conformance API can validate `dryRun: true` against a previously
authenticated model marker without consuming its ledger and returns
`DRY_RUN_VALIDATED`.

The productive `StateAdmissionEngine` instead denies dry-run before any state
call with `ACCORDLOCK_DRY_RUN_REQUIRES_SIDE_EFFECT_FREE_STATE`. Loading a current
`AdmissionContext` advances the trusted-time high-water mark, so treating that
load as a side-effect-free dry run would be false. This fail-closed behavior is
covered by a test that verifies the state high-water mark is unchanged. A
future read-only, authenticated context API could support richer dry-run
validation without changing this contract silently.

## Deterministic response

After a valid bounded admission UID is recovered, every failure becomes a
stable deny code such as `ACCORDLOCK_DEADLINE`, `ACCORDLOCK_AUTHORITY`,
`ACCORDLOCK_FENCE`, or `ACCORDLOCK_MUTATION_MISMATCH`. Allowed responses distinguish
`AUTHORIZED`, `RECOVERED`, and `DRY_RUN_VALIDATED` in a deterministic audit
annotation. Compact JSON serialization is deterministic for these fixed
structures and sorted maps.

An `ALLOW` means only that this admission request passed the profile and, for a
real request, that its UID was atomically recorded. It does not prove that the
API server persisted the mutation, that controllers completed a rollout, or
that AccordLock may release any credential or finalize an effect. Those require
separate authenticated observations.

## Required production webhook profile

The future deployment should use:

- `failurePolicy: Fail`;
- `sideEffects: NoneOnDryRun` for the current design, because real admissions
  write the ledger while dry-run admissions do not; use `None` only in a future
  design with no external ledger write in the webhook path;
- a short explicit `timeoutSeconds` validated against storage latency;
- an authenticated TLS channel from the Kubernetes API server, with webhook
  server identity and API-server/client identity verified;
- a namespace/object selector that covers every protected Deployment path;
- RBAC and admission configuration preventing alternate service accounts,
  credentials, webhook bypass, or direct mutation paths;
- PostgreSQL atomic persistence for the ledger contract; and
- monitoring that treats timeout, storage ambiguity, malformed requests, and
  unavailable authority state as denial.

The correct `sideEffects` declaration must be confirmed against the final
adapter. The pure library itself has no external side effect except through the
injected ledger on non-dry-run requests.

## Constructors and trust boundary

`AdmissionMarker::for_model` and `AdmissionRuntime::for_model` exist only for
the pure model and conformance tests. They authenticate nothing. Productive
code must use `StateAdmissionEngine`, whose marker and runtime are private
values constructed from `AdmissionContext`. Merely deserializing equivalent
fields from HTTP would be a trust-boundary violation.

## Still required

- HTTP/TLS webhook adapter;
- Kubernetes `MutatingWebhookConfiguration` or validating equivalent with
  fail-closed deployment policy;
- bypass-denial integration tests in a real EKS-compatible cluster;
- crash, timeout, retry, failover, and database-recovery tests; and
- a post-persistence observation path.

Until those pieces exist and are independently tested, PA-08 remains open.
