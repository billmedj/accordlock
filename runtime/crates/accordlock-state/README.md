# `accordlock-state`

This crate implements the transactional consumption boundary. It has three
adapters with the same state behavior:

- `InMemoryStore`, for deterministic conformance tests only;
- `PostgresStore`, a loopback-only `NoTls` PostgreSQL profile for local/CI;
- `TlsPostgresStore`, an authenticated TLS PostgreSQL profile for a remote
  database.

Consumption accepts only a tenant/environment scope, server transaction ID,
and authorization `authorization_id`. It reloads the issued authorization, active `AuthorityVector`, grant,
deadline inputs, and trusted time from state. It does not accept caller-provided
authority, grant counters, clock values, or deadlines.

The successful PostgreSQL consumption transaction performs all of the following
before one commit:

1. requires exact equality with the active authority vector;
2. compare-checks durable database-time high-water state;
3. checks `not_before <= database_time < consume_before`;
4. checks the grant validity, revocation, and maximum-use counter;
5. deterministically computes the dispatch deadline;
6. consumes the grant use and one-time `authorization_id`;
7. advances the time high-water mark;
8. inserts the consumption receipt and execution outbox entry.

Trusted database time is sampled only after the authority, high-water, authorization,
and grant rows are locked. Receipt and outbox reads re-check their JSON against
the scalar columns, full tenant/environment/AUTHORIZATION_ID/transaction identity, and the
stored issued authorization. A row that is present but internally divergent fails as
an invalid state record.

The API exposes two consumption operations with deliberately different replay
behavior:

- `consume` is strict. A committed AUTHORIZATION_ID is rejected as `AlreadyConsumed`.
- `consume_or_recover` is the idempotent commit boundary. If the caller retries
  the same `ConsumeKey` after losing a PostgreSQL commit response, it reloads
  the issued authorization, receipt, and outbox in one query and returns them only when
  every identity, scalar, frozen deadline, and JSON field agrees. The returned
  receipt and outbox are the previously stored values, not newly synthesized
  replacements.

A retry with another transaction identifier remains `TransactionMismatch`,
even if its AUTHORIZATION_ID was consumed. Corrupt or incomplete durable state fails closed.
If a database error prevents both consumption and exact recovery, the result is
`ConsumptionOutcomeUnknown`; a caller may retry only the unchanged
`ConsumeKey`. This closes an in-process lost-commit-response ambiguity. It does
not persist a client request intent or reconstruct identifiers lost in a
process crash.

`migrate()` serializes concurrent migration attempts with a transaction-scoped
advisory lock, applies `0001` through `0014` atomically, and verifies the exact
migration ledger, normalized SQL checksums, and definitions of the added
integrity constraints. Applied migrations are not silently re-run or repaired.
Migration `0003` creates a durable random state-lineage identifier used to bind
exported live sessions to their PostgreSQL state store. Migration `0004` adds
the signed issuance profile. Migration `0005` adds the exclusive dispatch
claim, monotone fence, lease, and durable `ATTEMPT_IN_FLIGHT` boundary.
Migration `0006` adds the global reservation keyed by the canonical physical
Deployment identity, so two authorizations, tenants, workers, or processes cannot own
the same target concurrently. Migration `0007` adds the one-shot admission
authorization ledger bound to the exact in-flight claim, fence, request, and
object commitments. Migration `0008` binds `ATTEMPT_IN_FLIGHT` and admission to
the exact credential token digest, Kubernetes `ServiceAccount` UID, canonical
credential ID, validity interval, and credential-binding commitment. Migration
`0009` adds the durable broker-operation journal for the one Secret create, one
bound `TokenRequest`, and exact-UID Secret cleanup. Migration `0010` adds the
audience-scoped ingress time high-water and nonce ledger, bound to the durable
state lineage. Migration `0011` adds the rooted EKS destination activations and
globally injective physical-owner registry described below. Migration `0012`
adds immutable terminal-witness registry material rooted by that v11
activation, the exact final Secret-deletion observation, signed terminal
history, and atomic retirement of an active claim reservation. Migration
`0013` adds durable authenticated submission intake, status and event history,
a fenced three-phase control-work queue, and atomic control-plane junctions to
authorization issuance, consumption, and the execution outbox. Migration `0014` adds
request-identity reservation, immutable stable claims, append-only dispatch
acquisitions, claim-bound pre-effect dispositions, credential-review history,
server-selected recovery discovery, no-send retirement states, and their
source/FSM/schema-drift guards. An older binary fails closed if it encounters
an unknown migration version.

All AccordLock-managed PostgreSQL object identifiers are checked in the
repository validation suite against PostgreSQL's 63-byte identifier limit.
The check is byte-based (not character-based) and fails before a migration can
rely on PostgreSQL's silent identifier truncation.

## Rooted EKS destination registry

`EksDestinationRegistryState` activates exactly one validated EKS route only
when its canonical resource and mediation roots are already the active roots
in durable `AuthorityVector` state. Request-facing input cannot supply those
authority domains, trusted time, claim identity, physical reservation, signed
template, or execution commitments. The mediation root commits the exact
attempt ServiceAccount subject/UID/audience, attempt RBAC root, terminal-witness
registry commitment, complete credential-lifecycle policy, and three pairwise
separated broker management subject/RBAC bindings.

Destination ownership is permanent in v11. Both `(API-server identity, namespace,
Deployment UID)` and `(pinned socket, CA trust commitment, namespace,
Deployment UID)` are globally unique, so another tenant, environment, cluster
identity alias, or trust-domain alias cannot adopt the same physical target.
The original resource activation remains an audit fact while the same exact
owner may append later resource/mediation activations. V12 does not transfer
this rooted destination ownership; it retires only the exact active dispatch
claim after authenticated effect and credential-retirement evidence. Process
death, expiry, or revocation is never a release signal.

`load_current_eks_attempt_for_acquisition` atomically rechecks active authority,
revocation, deadline, both trusted-time high-waters, the exact latest
acquisition lease, physical reservation, rooted activation, and owner lineage.
It then derives the template, operation, execution-command, and
provider-request commitments from the stored signed authorization. The unsuffixed
loader is retained only for strict non-control legacy bootstrap rows.
`CurrentEksAttempt` is deliberately non-clonable and represents only a fresh
currentness sample. It is not `AuthorizedProviderAttempt` or a mechanism for
recovering lost acquisition/provider authority.

`load_frozen_eks_attempt_for_journal` uses an exact journal selector and omits
only current authority and time checks needed for safe cleanup. It returns
immutable observation-only facts only after an exact consumed
authorization/receipt/outbox, claim/reservation, rooted historical activation,
acquisition origin, and broker-journal lineage agree. The unsuffixed frozen
loader is likewise legacy-only. Phase admissibility is enforced for the
selected operation and intended recovery use; a DELETE selector additionally
requires the exact matching CREATE and DELETE lineages. The result cannot mint
a bearer or authorize a new productive mutation.
TokenReview currentness uses the acquisition-aware path; restart recovery is
secret-free and conservative-delay-only rather than a bearer-returning
observation shortcut.

## Terminal retirement

`TerminalRetirementState` first persists complete witness-registry material
only when its canonical commitment exactly matches the historical v11 rooted
activation. It then reconstructs the terminal attempt, credential, admission,
payload TokenReview request, Secret-deletion observation, and conservative
retirement expectation solely from durable state. A caller supplies no
expected binding and no verifier key.

Finalization verifies two canonical purpose-separated signatures: exact
effect and retirement of the exact attempt credential. There is no
`NO_EFFECT` path. The append-only terminal row, `ATTEMPT_IN_FLIGHT -> TERMINAL`
claim transition, active-reservation release, and trusted-time update commit
atomically. Exact retries and audits reconstruct the durable context and
re-verify both historical signatures and exact envelope bytes. Global unique
constraints prevent reuse of a terminalization ID, or reuse of an evidence ID
or envelope commitment on another claim within the same witness role. Effect
and retirement identifiers remain separate purpose-bound namespaces.

The v12 registry is historical. Verification uses each signed `observed_at`
inside the immutable verifier window and cutoff. Later key rotation or
revocation does not retroactively replace that material, and v12 has neither a
separate emergency kill nor a transparency timestamp preventing a compromised
key from backdating inside its window. Safety therefore relies on independent
effect/retirement roles, key custody, short windows/cutoffs, and the v11 root.
See `TERMINAL_RETIREMENT_DESIGN.md` for the complete handoff.

## Durable ingress replay ledger

`IngressReplayState` treats the exact configured audience bytes as an opaque
scope; it does not trim, case-fold, or Unicode-normalize them. Scope and key
text columns use PostgreSQL `COLLATE "C"`. Every permanent scope row carries
the singleton state-lineage identifier and a monotone trusted-time high-water
mark. There is intentionally no scope deletion API.

Nonce consumption locks the scope row first, rejects clock rollback, advances
the high-water mark, and inserts `(scope, key_id, nonce)` in one serializable
transaction. Concurrent stores and processes therefore have one winner. An
existing tuple is reusable only when its stored signed expiry is exactly at or
before the new trusted observation. A generic commit failure is returned as
`IngressReplayOutcomeUnknown`; callers must deny authentication and never
recover that uncertainty as success.

Garbage collection is explicit and bounded to 1,000 rows per call. It deletes
only nonce rows whose expiry is no later than the already durable scope
high-water value. It never deletes a nonce linked to a v13 durable control
submission, samples or advances time, creates a missing scope, or deletes the
scope/high-water row. `InMemoryStore` implements the same
decision and exact-boundary behavior for deterministic tests, but remains
non-durable.

## Durable control submissions

The v13 control profile turns authenticated ingress into a durable intent
before returning success. Intake verifies the exact signed canonical payload,
active principal registry, database time, and both the scope and ingress-scope
high-water marks. One serializable transaction advances those high-water
marks, permanently consumes the nonce, stores the immutable submission and
initial status event, and creates `EVALUATE` work. Exact retries return only an
inert reference to the original submission and receipt; they do not recreate
an executable ingress capability. A lost or unprovable commit response is
`OutcomeUnknown`, never authentication success.

The queue advances through exactly three roles:

1. `EVALUATE` consumes a fenced, leased work capability. Kernel evaluation,
   the server-selected single-grant decision, append-only completion, status
   event, and transition to `ISSUE` commit atomically. Kernel denial or no
   available grant terminates without issuance. This profile deliberately has
   one active grant; multiple matching grants are structural corruption, not a
   functional `MANUAL` branch.
2. `ISSUE` derives trusted issuance time from the work claim. The signed authorization,
   issuance link, completion, event, status, and transition to `CONSUME` commit
   together. A partial or pre-existing authorization tuple fails closed rather than
   being adopted.
3. `CONSUME` atomically creates or exactly recovers the receipt and execution
   outbox, binds them to the control submission, appends completion and status,
   and marks the control queue done. Legacy issuance, consumption, and dispatch
   APIs reject an authorization owned by an incomplete v13 lineage.

Exact completed-work, submission, and status recovery is historical and
read-only: it re-verifies the frozen ingress signature and complete artifact,
event, and projection lineage without consulting or advancing current time.
Recovery of an active work capability remains currentness-sensitive and
requires the exact live claim, fence, lease, authority, and both high-water
marks. PostgreSQL recovery/status reads use one repeatable-read snapshot so a
concurrent phase commit cannot be observed as a torn history.

`ControlWorkerRole` is currently a state-machine selector, not proof of a
database or workload identity. `accordlock-control` removes the raw role selector
from its public worker surface and fixes each worker type to one phase, but a
production deployment must still bind separate authenticated PostgreSQL
sessions or workload identities to evaluator, issuer, and consumer privileges.
The v13 queue itself stops at a durable execution-outbox entry. The v14
acquisition layer consumes that outbox through a server-selected API; the
caller supplies only a canonical worker identity and fresh request identity,
never a queue key, claim ID, or physical resource.

## Dispatch claim and acquisition boundary

`claim_dispatch` reloads and revalidates the exact consumed authorization tuple before
atomically creating one claim for that consumption. A different worker or
claim cannot replace it. A repeated request never reconstructs authority from
an ambiguous commit. `revalidate_dispatch_claim` repeats the current authority,
grant, revocation, signature, clock, lease, deadline, receipt, and outbox
checks. `mark_attempt_in_flight` is a one-shot durable transition and returns an
opaque, non-clonable result only after commit.

`claim_next_pending_dispatch_or_recover` orders the scope-local union of
productive and historical-recovery candidates by the durable FIFO key. Neither
class has priority over the other. A first productive selection creates one
immutable stable claim and one append-only acquisition generation. A takeover
appends a higher globally fresh lease fence; it never rewrites the claim. Only
the exact latest, live, artifact-free `CONTROL_QUEUE` generation can return
`DispatchAcquisitionAuthority`. Historical v13 claims are backfilled as inert
bootstrap generations, preserving their schema-valid lease facts even when the
old lease exceeded the new 30-second limit. Every new v14 generation remains
capped at 30 seconds.

Broker, review, attempt, and no-send history are discovered as opaque
`RecoveryRequired` work. Recovery never reconstructs acquisition/provider
authority, a bearer, or a previously issued broker I/O authority. It may derive
an exact cleanup request; beginning a fresh DELETE remains gated by the trusted
`BrokerJournalCapability`. Claim-bound queue dispositions atomically move the
claim to `DISPOSED` and release its physical reservation. A crash before
provider authority can instead close the exact frozen lineage as
`RECOVERY_NO_SEND`. Exact reconciled CREATE absence retires immediately because
no credential could have been issued; exact DELETE absence waits for the rooted
propagation and clock-uncertainty bound. An idempotent `RECOVERY_RETIRED`
transition then releases the reservation. A productive `ATTEMPT_IN_FLIGHT` is
cleanup-only and cannot be relabelled as no-send.

The physical reservation is deliberately fail-closed. A legacy productive
attempt is released only by the exact v12 signed-effect and
credential-retirement terminal transition. V14 additionally authorizations the exact
pre-effect disposition and no-send retirement profiles above. A crash, lease
expiry, admission `ALLOW`, HTTP status, DELETE acknowledgement, GET/404 without
its exact durable observation, or ambiguous effect still preserves exclusion.
The claim, every acquisition generation, and their fences remain permanent
audit history.

The trusted-time high-water mark is used by issuance snapshots, final authorization
recording, consumption, dispatch snapshots, claims, revalidation, and attempt
marking. After exact routing and record or token validation, a current temporal
sample is persisted even when the operation is rejected at an expiry or lease
boundary. A subsequent clock rollback therefore cannot resurrect the authorization or
claim. Unknown, corrupt, revoked, or misrouted input does not advance the
high-water mark and cannot use that mechanism for a simple availability attack.

This state boundary does not execute a provider request or prove an external
effect. It also does not make the database highly available or protect against
a compromised database clock, administrator, or writer role.

## Durable broker journal

`BrokerJournalState` freezes the scope, transaction ID, execution authorization ID, claim ID,
global fence, state lineage, physical Deployment identity, route commitment,
deterministic Secret name, bound Secret UID, and operation before external I/O.
Every operation that can begin broker or review I/O requires the one-shot,
store-bound `BrokerJournalCapability` issued during trusted enforcement
bootstrap. For a v14 acquisition,
`begin_broker_operation_for_acquisition` atomically persists `INTENT` and
crosses to `IN_FLIGHT`; there is no productive crash window between split
prepare/begin calls. The legacy split create/token API is restricted to strict
non-control bootstrap history; cleanup and GET-only reconciliation remain
available for exact frozen control history. The begin transition rechecks
durable lineage, dual high-water time, current authority, revocation, deadline,
and the exact latest acquisition lease. Only a successfully committed
transition returns the non-clonable `BrokerIoAuthority` for one send. A
PostgreSQL commit ambiguity
never reconstructs mutation authority.

An abandoned `IN_FLIGHT` row can become only `UNKNOWN` and, for Secret create
or delete, `RECONCILE_ONLY`. Reconciliation authority authorizations authenticated GET
only. It can never resend create/delete or issue another token. A create GET
that is absent and a delete GET that still sees the exact UID remain
`RECONCILE_ONLY`; each observation advances a CAS counter and records the last
outcome, evidence commitment, and trusted time. This authorizations eventual
consistency or asynchronous deletion to converge without reopening mutation.
A matching create or absent delete becomes `COMMITTED`; a conflicting object
becomes `TERMINAL`. Token issuance has no GET recovery: once its send is
in-flight or ambiguous it is never reissued, and cleanup must respect the
pre-I/O lifetime upper bound plus clock-uncertainty retirement time.

Exact cleanup deliberately remains available after authority revocation,
dispatch-deadline expiry, or claim-lease expiry, but only for the state-derived
route, name, original UID, lineage, and physical resource. It still rejects
clock rollback. This prevents an expired authorization from becoming a reason
to retain possibly live credentials.

The journal closes AccordLock's database/process ambiguity around mutation
authority; it does not make Kubernetes or AWS provide exactly-once behavior.
Provider authentication, response/GET verification, route commitment checks,
and consumption of the opaque authority immediately before HTTP remain broker
responsibilities. `COMMITTED` or `TERMINAL` journal state does not release the
physical-resource reservation, claim, or any other terminal exclusion. Release
requires either the exact signed effect plus credential-retirement terminal
lineage, an exact claim-bound pre-effect disposition, or the dedicated inert
`RECOVERY_NO_SEND -> RECOVERY_RETIRED` proof path described above.

The capability closes the safe-Rust object graph after trusted bootstrap; it is
not a database-global workload identity. A separately constructed store in
another process can issue its own process-local capability. Production must
therefore constrain database DML, schema mutation, and broker bootstrap through
separate authenticated roles or procedures. Those ACL/session and workload
identity controls remain deployment TCB rather than guarantees of this crate.

## Connection boundary

`PostgresStore::new` remains the local/CI profile. It uses `NoTls`, rejects
configurations without an explicit loopback host (or a local Unix socket), and
rejects a non-loopback `hostaddr` override.

`TlsPostgresStore` is a distinct remote profile. It accepts no connection
string. `TlsPostgresConfig` requires one validated DNS server name, an explicit
CA PEM bundle, database and user names, a non-empty password, and a bounded
socket connect timeout. An optional numeric target address can route the TCP
connection without replacing the DNS name used for SNI and certificate
verification. The profile constructs the PostgreSQL configuration itself with:

- `SslMode::Require`, with no plaintext or `sslmode=prefer` fallback;
- `ChannelBinding::Require`, so password authentication must complete with
  SCRAM-SHA-256-PLUS;
- `TargetSessionAttrs::ReadWrite`;
- an explicit rustls AWS-LC provider and only the supplied CA roots;
- an optional fixed client certificate chain and matching unencrypted private
  key.

The optional client certificate is an additional TLS client-authentication
layer. It does not relax the SCRAM channel-binding requirement. The selected
connector cannot derive `tls-server-end-point` channel binding from an Ed25519
server certificate, so this strict profile rejects that combination. A
deployment must verify its database certificate and PostgreSQL authentication
profile before rollout.

The PostgreSQL client library copies the password into its `Config` so this
adapter can open a fresh connection for every state operation. AccordLock does not
keep a second password `Vec`, and all AccordLock `Debug` implementations redact the
user, password, CA, and client key, but the library-owned credential remains in
process memory for the store lifetime and may be copied transiently while a
connection is established. The same process-memory limitation applies to an
optional client private key held by rustls. Secret injection, process memory
protection, short-lived credential issuance, rotation, and revocation are
deployment responsibilities. Rotating a credential currently requires
constructing and swapping in a new store.

Unit tests reproduce strict configuration, CA and client-identity parsing,
redaction, and rejection behavior. They do not perform a live TLS PostgreSQL
handshake. An ignored integration harness is provided, but has not yet been run
against an independently provisioned TLS server in this repository. A
disposable PostgreSQL server configured with TLS, SCRAM-PLUS, a matching DNS
certificate, and optional client-certificate enforcement is still required for
that evidence:

```powershell
$env:ACCORDLOCK_TEST_POSTGRES_TLS_SERVER_NAME = 'db.test.example'
$env:ACCORDLOCK_TEST_POSTGRES_TLS_TARGET_ADDRESS = '192.0.2.10' # optional
$env:ACCORDLOCK_TEST_POSTGRES_TLS_PORT = '5432'                 # optional
$env:ACCORDLOCK_TEST_POSTGRES_TLS_DATABASE = 'disposable_accordlock_test'
$env:ACCORDLOCK_TEST_POSTGRES_TLS_USER = 'accordlock_test'
$env:ACCORDLOCK_TEST_POSTGRES_TLS_PASSWORD = '<test-secret>'
$env:ACCORDLOCK_TEST_POSTGRES_TLS_CA_FILE = 'C:\path\to\test-ca.pem'
# Set both optional client files or neither.
$env:ACCORDLOCK_TEST_POSTGRES_TLS_CLIENT_CERT_FILE = 'C:\path\to\client-chain.pem'
$env:ACCORDLOCK_TEST_POSTGRES_TLS_CLIENT_KEY_FILE = 'C:\path\to\client-key.pem'
cargo test -p accordlock-state --test postgres_tls -- --ignored --test-threads=1
```

The ignored harness runs migrations and is destructive with respect to its
configured schema. Do not point it at a production or shared database.

TLS authenticates and encrypts the database transport. It does not make the
database highly available, protect credentials outside this process, or defend
against a compromised database administrator or database clock.

## Signed issuance boundary

The current `ExecutionAuthorization` schema v2 signs `max_dispatch_delay`,
`profile_hard_cap`, and the bounded dependency-expiry set. State persists the
complete signed authorization, re-verifies its deterministic COSE envelope and active
signer root, and recomputes the exact dispatch deadline from those signed
inputs. Grant registration is bound to the exact active single-grant snapshot
used by this local profile, and revocation changes its authority domain
atomically. A multi-grant production registry will require a separately frozen
snapshot or membership-proof profile rather than silently extending this local
single-grant construction.

## PostgreSQL integration test

The integration test is compiled by the ordinary test suite but ignored unless
explicitly requested because it destructively uses a disposable test database:

```powershell
$env:ACCORDLOCK_TEST_POSTGRES_URL = 'postgresql://.../disposable_test_database'
cargo test -p accordlock-state --test postgres -- --ignored --test-threads=1
```

Do not point it at a production or shared database.

The `postgres_v14_upgrade` binary is more destructive: it rebuilds the
`public` schema to exercise a real 0001-through-0013 lineage. Before connecting,
it requires a loopback or local-socket URL whose database name is exactly
`accordlock_test_v2` and the explicit confirmation
`ACCORDLOCK_TEST_POSTGRES_V14_RESET=DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2`. The
top-level local runner scopes that confirmation to this binary; external mode
requires the operator to provide it explicitly.
