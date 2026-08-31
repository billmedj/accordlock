# `accordlock-webhook`

This crate is the bounded HTTPS transport for the Kubernetes admission
profile. It exposes exactly one admission route, plus separate liveness and
readiness routes. It does not construct security facts from HTTP fields.

## Transport contract

- `POST /validate` requires exactly one `Content-Type: application/json`
  header and a body no larger than 1 MiB.
- A short route deadline covers body buffering as well as evaluation. The
  synchronous admission application runs on Tokio's blocking pool behind a
  separate bounded in-flight semaphore.
- A malformed request returns a generic non-2xx response. Storage ambiguity,
  timeout, panic, or control-plane unavailability returns `503`. With a
  Kubernetes `failurePolicy: Fail`, each of those cases denies the API call.
- Successful application output is the typed deterministic
  `AdmissionReviewResponse` from `accordlock-admission`.
- Responses disable caching and MIME sniffing. Request and response bodies are
  never logged by this crate.
- `GET /livez` reports process liveness. `GET /readyz` is delegated to the
  installed application and must remain false until its state, keys, authority,
  and destination profile are ready. `POST /validate` also fails closed while
  readiness is false, including during graceful shutdown.

A timeout cannot cancel a Rust blocking task that has already entered the
state transaction. The task retains its in-flight authorization until it exits, and
the HTTP response remains fail-closed. If the transaction committed after the
timeout, Kubernetes retry is resolved only through the exact admission-UID
recovery protocol; no generic retry is inferred safe.

## TLS

`prepare_server_tls` reads each PEM file once with a 1 MiB bound, constructs
Rustls from those exact in-memory bytes, and passes the opaque prepared object
to `serve_prepared_tls_until`. Changing a path after preparation therefore
cannot change the certificate served by that process. Certificate rotation
requires preparing a new TLS configuration (normally by replacing the pod).

Kubernetes must validate the server certificate through the
`ValidatingWebhookConfiguration.clientConfig.caBundle`; for a Service target,
the certificate needs the `<service>.<namespace>.svc` DNS name.

TLS server authentication does not authenticate the caller to the webhook.
Managed EKS does not automatically provide a portable client-certificate
profile for custom webhooks, and `AdmissionReview.userInfo` is only trustworthy
when the request really originated at the API server. A network-reachable
caller can forge that JSON field and attempt to consume a live admission
authorization. The productive deployment therefore requires a private path
restricted to the EKS control-plane source, strict webhook registration/RBAC,
and any actually supported control-plane client authentication. This crate does
not claim generic mTLS or solve request-origin authentication by itself.

## Logical observer identity

Evidence identity is deliberately independent of the rotating TLS certificate.
`ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY` is mandatory and must use the canonical form
`urn:accordlock:observer:<segment>[:<segment>...]`, for example
`urn:accordlock:observer:acme:production:cluster-a:admission`. Segments are bounded
lowercase ASCII labels containing letters, digits and interior hyphens. Empty
segments, whitespace, Unicode and non-canonical case or syntax are rejected.

The process derives a length-framed, domain-separated SHA-256 commitment from
that exact canonical identifier and supplies it to the admission engine. The
identifier must name the logical webhook service, remain stable across pod and
certificate rotations, and be changed only as an explicit identity-lifecycle
event. Its global uniqueness and authorized provisioning are deployment
assumptions; the hash does not establish either. It also does not prove TLS-key
custody or authenticate the caller.

## Boundary still required

`StateAdmissionApplication` is the productive library adapter. It accepts only
review bytes, then delegates to `StateAdmissionEngine`, which parses only the
transaction/AUTHORIZATION_ID routing annotations, loads an opaque current admission context
from `accordlock-state`, and commits through the state-backed ledger. It starts
not-ready; its separate process-local readiness switch can be enabled only
after bootstrap checks. Readiness grants no authority. A request-facing path
never deserializes an `AdmissionMarker`, authority vector, fence, claim, or
deadline.

This crate does not yet prove cluster reachability, certificate custody, high
availability, or EKS bypass resistance. Those require a deployed integration
test and external review.

## Composition process

The `accordlock-webhookd` binary is a strict composition root. It accepts all
profile material from named environment variables, requires absolute TLS
and credential paths, requires the explicit canonical logical observer
identity above, prepares TLS independently, and calls
`TlsPostgresStore::validate_schema()` in a blocking worker before becoming
ready. It never auto-migrates the database.

The database profile has no connection-string input. It requires a DNS server
name, port, database, user, password file, explicit CA PEM file, bounded connect
timeout and, optionally, one pinned target IP plus a client-certificate/key
pair. TLS, DNS/SNI verification, read-write server selection and
SCRAM-SHA-256-PLUS channel binding are fixed inside `accordlock-state`. Password
and private-key input buffers are overwritten after the state connector has
parsed/copied them; the PostgreSQL library necessarily retains its own password
copy for the store lifetime.

This makes remote authenticated database transport implementable. It is not a
live handshake result, credential-rotation system, HA guarantee, certificate-
custody proof, deployed webhook, or EKS bypass-resistance result.
