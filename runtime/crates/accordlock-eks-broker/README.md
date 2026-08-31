# Fixed EKS attempt-credential broker

This crate implements the narrow Kubernetes control-plane cycle used to mint
one attempt credential for `DEPLOY_EKS_IMAGE_V1`:

1. consume a non-clonable I/O or GET-only authority issued by the durable
   broker journal;
2. reload rooted, durable attempt facts through the scope-fixed
   `StateBackedAttemptAuthority` for the journal-derived canonical Secret name;
3. create one immutable, empty, `Opaque` Secret with exact binding labels and
   durably commit its authenticated server UID;
4. reconcile that exact name and server UID without retrying an ambiguous
   create;
5. create one ServiceAccount `TokenRequest` bound to that Secret and durably
   commit only its redacted digest, expiry, and response evidence before the
   bearer can leave the broker;
6. obtain a durable acquisition/token-journal-bound review I/O authority,
   submit the bearer to `TokenReview`, and commit authenticated or rejected
   evidence; authenticated review returns the sole opaque
   `ReviewedDispatchCredential` accepted by the attempt CAS;
7. delete the Secret with a UID precondition, burn the send authority into
   durable uncertainty even after HTTP acknowledgement, and reconcile GET-404;
8. retain an explicit retirement decision based on the conservative
   post-deletion propagation delay plus clock uncertainty.

If an authenticated review commits but its response is lost, the failure
retains an opaque post-begin recovery selector alongside the original
journaled bearer. `recover_reviewed_token` performs no HTTP: it reloads the
exact authenticated proof, rechecks token digest/AUTHORIZATION_ID/times, journal lineage,
current acquisition, rooted policy/activation and the strict I/O horizon, then
returns the same one-shot credential. An in-flight or rejected review cannot
use this path.

No productive create or token operation accepts `AttemptLookup`, a claim token,
caller verdict, or caller-supplied route/policy facts. It starts from the exact
`DispatchAcquisitionAuthority`; state atomically prepares/adopts and crosses
the journal to `IN_FLIGHT` in one transaction. Cleanup and reconciliation use
only exact frozen journal selectors or state-derived restart requests. Raw
network helpers remain private.

All journal begin operations additionally require the unique non-clonable
`BrokerJournalCapability` issued to trusted enforcement bootstrap and never
exposed by the broker facade. CREATE/TOKEN/DELETE observations and review
claims are data, not authority: even if constructed or deserialized by another
safe-Rust caller, they cannot obtain an I/O authority without that store-bound
capability. State clones share its one issuer, so only one productive broker
composition exists in that object graph. This is an in-process bootstrap TCB,
not a claim that independently opened PostgreSQL processes share one global
capability; DB-role/session isolation remains separate hardening work.

## Durable mutation journal

State freezes tenant/environment scope, transaction and execution authorization ID, claim ID,
global fence, physical Deployment identity, complete route commitment,
deterministic Secret name, bound UID where applicable, operation, and token
lifetime/clock-uncertainty policy. `INTENT -> IN_FLIGHT` occurs durably before
the broker receives its sole mutation authority. The broker rechecks the
opaque audit against the current journal row, route, physical resource, name,
UID, operation, and policy immediately before the exchange.

Any local, credential-source, transport, provider-status, parse, or validation
failure after authority consumption calls `mark_broker_io_unknown`; if that
state write is itself ambiguous, the linear authority is still gone and the
row remains irreversibly in-flight. Create and delete can thereafter obtain
only GET reconciliation authority. Token issuance has no resend and no GET
reconciliation path. A token bearer is returned only after
`commit_broker_token_issue` succeeds; an error drops and overwrites its broker
buffers. DELETE 200/202 is only an acknowledgement and always transitions to
UNKNOWN, never to absence.

Create-absent and delete-present observations remain `RECONCILE_ONLY`, retain
an incremented reconciliation generation and allow another authenticated GET.
Create-matching and delete-absent commit; a conflicting object terminates the
operation. Pending and completed broker results contain audits/receipts, never
another authority. Response evidence commits to the HTTP request commitment,
authenticated channel, API-server identity, status, and body.

A durable delete-absence observation is not itself immediate bearer
retirement. Restart assessment uses the opaque state-authenticated absence
time and rooted lifecycle policy, remaining pending until deletion propagation
hard max plus clock uncertainty has elapsed. A durable TokenReview rejection is
validated for exact binding and ordering but cannot shorten that bound because
its commit time does not prove the provider observation time.

`StateBackedAttemptAuthority<S>` fixes `EksDestinationRegistryState` to one
tenant/environment `Scope`. Its current loader rejects revocation, deadline
expiry, authority drift and stale destination activation; its frozen loader is
available only for the immutable create/delete journal lineage proven by
state. The resulting `TrustedAttemptRecord` carries the complete EKS route and
physical resource, ServiceAccount subject/UID/audience, effective attempt RBAC,
terminal-witness registry commitment, credential-lifecycle policy ID/value and
commitment, all three management identity/RBAC bindings, authorization-derived
template/operation/execution/provider commitments, and the exact resource,
mediation and destination activation identities. The broker compares route,
lifecycle policy and all three management bindings structurally with its fixed
configuration.

`CurrentEksAttempt` is deliberately non-clonable and is consumed inside the
adapter. It is a checked data snapshot, not recovery authority: neither it nor
`TrustedAttemptRecord` can reconstruct a dispatch machine, claim token or retry
right. A token-issue outcome that becomes uncertain remains uncertain.

Every HTTP path has a one-shot state/time barrier after the management source,
TCP connection, TLS authentication, ALPN, and peer pinning, immediately before
the first HTTP application byte. CREATE,
TokenRequest and ordinary TokenReview reload the exact current record.
DELETE and reconciliation GET reload the exact frozen record and then compare
the complete current journal audit, including entry ID and reconciliation
generation, with the authority that entered the operation. Productive sends
also resample trusted time and require the complete transport timeout plus
rooted clock uncertainty to end strictly before acquisition lease, dispatch
deadline, and credential expiry where applicable. A mismatch sends zero HTTP.
If a productive journal authority was already IN_FLIGHT, the broker
burns it to UNKNOWN. Authenticated responses retain their post-response
current/frozen checks before a result can be committed or returned.

No local transaction remains open across a Kubernetes network exchange. The
post-TLS guard is the local send linearization point: rejection closes the
socket as `DefinitelyNotSent`; from the first write onward failures are
`OutcomeUnknown`. Changes ordered after that boundary do not retroactively
revoke the consumed capability, so provider-side fencing remains outside this
crate.

## Management-authority separation

The broker does not accept one ambient or union-privileged Kubernetes bearer.
`BrokerManagementIdentities` requires three pairwise-distinct authenticated
identity subjects and three pairwise-distinct commitments to their installed
RBAC objects:

1. a Secret-lifecycle identity for create/get/delete in the one configured
   namespace;
2. a ServiceAccount-token identity for `create` on the `serviceaccounts/token`
   subresource of the one exact attempt ServiceAccount;
3. a separate TokenReview identity for `create` on
   `authentication.k8s.io/tokenreviews`.

Every source request contains a typed `BrokerManagementOperation`. Its binding
includes the complete EKS route commitment plus the exact Secret name (and UID
for delete), or the exact ServiceAccount name/UID, audience and bound Secret,
or the reviewed attempt-token commitment. The returned `ManagementBearer`
must echo that operation and the configured authority identity exactly. The
broker rejects a wrong operation or identity before it calls the HTTP layer.
The bearer is not clonable and is zeroed after its single exchange.

The Kubernetes installation must place only AccordLock's empty bound Secrets in a
dedicated namespace and enforce their canonical name, strict labels, empty
data and immutable profile with admission. The Secret Role must be scoped to
that namespace and only the `secrets` resource with the required lifecycle
verbs. Standard RBAC cannot express the broker's dynamic Secret-name pattern
or constrain ordinary create by object name, so admission and the broker's
fixed path are mandatory. The TokenRequest Role must grant only `create` on
`serviceaccounts/token` for the exact configured attempt ServiceAccount;
bootstrap must prove the generated authorization attributes retain that name.
TokenReview must be granted to its separate identity. None of these identities
may receive Deployment mutation, `pods/exec`, impersonation, wildcard
resources, wildcard verbs, secret data read outside the dedicated lifecycle
scope, or permission to modify RBAC/admission.

The non-secret authorization commitments are equality anchors for audited
provisioning artifacts; they do not let this crate inspect Kubernetes' live
authorization graph. A compromised credential source could lie about metadata
or rewrap the same raw secret, so independent issuance and live RBAC/admission
verification remain bootstrap requirements.

The native adapter uses one pinned socket, one DNS name, explicit DER trust
anchors, rustls certificate and DNS verification, and HTTP/1.1. It performs no
DNS lookup, proxying, redirect following, connection reuse, or automatic
retry. Every mutating operation is a single application-data emission. A
failure after emission starts is `OutcomeUnknown`.

Destination configuration has one source: `accordlock_eks_profile::EksRouteProfile`.
The broker derives API-server identity, DNS/SNI name, port, pinned socket,
namespace, attempt ServiceAccount name/UID, and Kubernetes API audience from
that value. Supplied DER roots must reproduce the profile's exact CA-set
commitment. The native HTTP client owns the same profile and the broker
rechecks structural equality before authority resolution and immediately
before every exchange.

Raw management and attempt tokens are redacted from `Debug` and errors and are
overwritten on drop. TokenReview JSON is streamed around the borrowed token so
the broker does not build another complete token-bearing request buffer.
The response buffer that contains a newly issued token is also overwritten.
Rust, rustls, the allocator, the operating system, the API server, and the
credential issuer can retain copies that this crate cannot prove absent.

JWT signatures are not verified a second time locally. The authenticated API
server's TokenReview result is the signature, issuer, revocation, and
authentication oracle for the exact echoed token. Local JWT decoding is used
only after that result to bind the subject, audience, ServiceAccount UID,
Secret name/UID, credential AUTHORIZATION_ID, and temporal claims. For the Kubernetes
v1.32+ profile, `TokenReview.user.extra` must contain exactly one
`authentication.kubernetes.io/credential-id` value in canonical `AUTHORIZATION_ID=<UUID>`
form, and that UUID must equal the JWT `authorization_id`.

The server may return a token lifetime shorter or longer than
`expirationSeconds`. The broker validates the returned expiration and JWT
`exp` against a separately configured server upper bound, never against the
requested duration alone.

Kubernetes documents that authentication of a Secret-bound token may continue
for up to roughly 60 seconds after the Secret receives a deletion timestamp.
A successful DELETE or GET-404 is therefore not credential-retirement proof by
itself. The configured conservative invalidation delay cannot be below 60
seconds. TokenReview rejection does not bypass this propagation bound.

The tests cover the pure codecs plus an in-memory durable-journal integration:
exact create/token receipts, DELETE acknowledgement to UNKNOWN, repeated
present/absent GET generations, pre-send/transport/provider/parse failures,
commit races, operation/route/name/UID/policy substitution, bearer drop on
commit error, authority rotation and deadline expiry caused inside
`ManagementCredentialSource::credential` with zero HTTP, scope-fixed state
adapter failure, and the public no-bypass compile failure. PostgreSQL CAS,
multi-process and OS-race coverage lives in `accordlock-state`.

This journal prevents AccordLock from automatically resending an ambiguous
mutation; it cannot make Kubernetes provider I/O exactly once. It also does
not release the terminal physical-resource reservation. The crate does not
claim a live EKS test, DNS-security proof, OCSP/CRL checking, immediate token
revocation, exclusive process custody, provider-side exactly-once behavior,
terminal reservation release, or independent review.
