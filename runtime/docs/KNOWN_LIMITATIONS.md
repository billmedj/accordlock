# Open problems and closure register

**Last reviewed:** 2026-08-30  
**Scope:** unreleased engineering alpha for local evaluation, fixed
`DEPLOY_EKS_IMAGE_V1` profile

This is a cumulative register. Existing OP identifiers are retained when an
older premise becomes obsolete so that reviews and issue links do not lose
their history.

External dependency identifiers are defined in
[EXTERNAL_GATES.md](EXTERNAL_GATES.md).

Status vocabulary:

- `CLOSED-IN-CODE` — the original local implementation gap is satisfied by
  repository source, schemas, and targeted tests. It is not a live deployment
  or independent-assurance claim.
- `OPEN-DEPLOYMENT` — the local mechanism exists, but the stated property still
  depends on live infrastructure, operational composition, or retained
  integration evidence.
- `OPEN` — implementation, assurance, or external evidence is still missing.

The following older premises are now closed in code: rooted EKS destination
registration (OP-005), native execution and wire construction (OP-007),
durable physical-resource exclusion (OP-008A), and distributed PostgreSQL
ingress replay (OP-009). Terminal retirement, v14 acquisitions, state-backed
admission, the HTTPS webhook, and TLS PostgreSQL are also implemented, but
their broader live properties remain open under OP-001, OP-006, OP-008,
OP-008B, and OP-010.

## Critical before a real external effect

### OP-001. Complete mediation and exclusive executor

**Status:** OPEN-DEPLOYMENT  
**Class:** production blocker  
**Historical premise:** the earlier kind runner invoked `kubectl` directly and
did not require an `AuthorizedProviderAttempt`. That remains true of the
exhibit, but it no longer describes the native enforcement code path.  
**Current local evidence:** `accordlock-enforcement` owns the singular
state-selected acquisition, journaled EKS broker, durable
`ATTEMPT_IN_FLIGHT` transition, by-value bearer/attempt handoff, native
executor, and cleanup path. `accordlock-eks-transport` has no shell or hidden
retry path. State-backed admission and the bounded HTTPS webhook are
implemented. The production entry point intentionally refuses to unlock.  
**Remaining premise:** no retained EKS run proves that the executor owns the
only effective Deployment-mutation credential, that every alternate mutation
path is denied, or that the webhook call originated from the API server.  
**Closure criterion:** in one disposable EKS environment, retain proof that
the three management identities have exactly their committed RBAC closures;
the executor identity alone can present the protected mutation; direct,
alternate-service-account, ordinary-workload, and admission-outage attempts
are denied; webhook origin is authenticated; the exact token audience works on
the bound API server; and exact post-state observation is reconciled.  
**External dependencies:** AWS-002, AWS-004, CUST-002, EXT-001, EXT-004.

### OP-002. Capability containment across Rust, processes, and database roles

**Status:** OPEN  
**Class:** production hardening blocker  
**Current local evidence:** request-facing values cannot construct ingress,
current-attempt, acquisition, broker-I/O, reviewed-credential, provider-attempt,
admission-context, or terminalization capabilities. The v13/v14 schedulers
select work server-side, and the enforcement object graph privately owns the
broker journal capability.  
**Remaining premise:** safe-Rust opacity does not isolate arbitrary trusted
same-process code. A separately opened PostgreSQL handle or overly privileged
database principal can still exceed the intended worker role. Control-worker
roles are state-machine selectors, not authenticated database identities.  
**Closure criterion:** split control, dispatch, webhook, terminalization, and
administration operations across authenticated least-privilege workloads and
database roles; prevent public/request processes from invoking lower-level
mutations; and retain negative authorization tests for every cross-role call
and raw-state bypass.  
**Dependencies:** AWS-002, AWS-006, EXT-001, EXT-004.

### OP-003. Isolated and role-constrained signing

**Status:** OPEN  
**Class:** TCB construction blocker  
**Current local evidence:** evaluator, authorization, activation, terminal-effect, and
terminal-retirement signatures are purpose-separated and rooted; key IDs and
public keys are checked exactly.  
**Remaining premise:** active local identities are software signers, and test
fixture seeds are public. No deployed KMS/HSM policy prevents a compromised
workload from requesting another signing purpose.  
**Closure criterion:** a KMS, HSM, TEE, or equivalent constrained service
exposes only each authorized operation; workload identity excludes the model
and request process; and rotation, disable, recovery, backdating limits, and
cross-purpose denial are exercised and logged.  
**External dependencies:** AWS-002, AWS-005, EXT-002, EXT-005.

### OP-004. Authenticated evidence connectors

**Status:** OPEN  
**Class:** evidence-premise blocker  
**Current local evidence:** `accordlock-connectors` accepts only opaque lookup
identifiers, joins bounded review/build/artifact/target snapshots, enforces
freshness and monotonicity, and emits four purpose-separated signed assertions.
The kernel verifies them against activated roots.  
**Remaining premise:** repository adapters are synthetic. No shipped connector
authenticates GitHub review state, workflow inputs/outputs, registry
attestations and quarantine state, or the live Kubernetes target. The
in-process connector checkpoint is not durable.  
**Closure criterion:** least-privilege source-specific adapters verify TLS and
service identity, strict response schemas, completeness and pagination,
monotonic provider cursors, replay/freshness, and mutation races; durable
rollback checkpoints and the authenticated connector-to-kernel handoff are
then exercised against real systems.  
**External dependencies:** GH-003, GH-004, AWS-003, CUST-003, EXT-004.

### OP-005. Rooted EKS destination and credential registry

**Status:** CLOSED-IN-CODE (2026-08-22)  
**Class:** historical authority-model gap  
**Historical premise:** destination and credential configuration was not
committed by an activated authority root. That premise is obsolete.  
**Closure evidence:** migration `0011` and `EksDestinationRegistryState`
implement root/epoch/activation-checked EKS activations and globally injective
physical ownership. The mediation root binds the route, attempt
ServiceAccount/audience, terminal-witness registry, credential-lifecycle
policy, and three distinct management subject/RBAC commitments.
`load_current_eks_attempt_for_acquisition` rechecks current authority,
activation, route, reservation, acquisition, grant, deadline, and owner
lineage before returning a non-clonable currentness sample.  
**Non-claim:** source construction does not prove AWS ownership, endpoint
identity, live RBAC closure, or that two configured names do not reach the same
unregistered provider. Those live proofs remain in OP-001 and Gate B.  
**Reopen criterion:** a request-facing path can select an unrooted route,
credential/audience, physical owner, or historical activation for productive
execution.

### OP-006. Authenticated credential, effect, and retirement observations

**Status:** OPEN-DEPLOYMENT  
**Class:** oracle-premise blocker  
**Current local evidence:** the native broker binds Secret UID, TokenRequest,
TokenReview, JWT `authorization_id`, credential ID, ServiceAccount UID, audience, lifetime,
route, and acquisition in the durable journal. The executor authenticates and
validates exact response behavior. Migration `0012` and
`accordlock-terminal-witness` require purpose-separated signed exact-effect and
credential-retirement evidence before atomic terminalization and reservation
release. There is no terminal `NO_EFFECT` shortcut.  
**Remaining premise:** local types and signatures do not prove that a deployed
observer queried the intended API server, that its workload/key was exclusive,
or that the observed post-state is complete and truthful.  
**Closure criterion:** deploy independently authenticated effect and retirement
observers; bind their identities, keys, routes, validity windows, raw provider
responses, TokenReview behavior, and queried post-state; then test forged,
stale, cross-route, incomplete, backdated, and colluding evidence and retain
exact terminal audit artifacts.  
**External dependencies:** AWS-002, AWS-004, AWS-005, EXT-002, EXT-004,
EXT-005.

### OP-007. Native execution command and wire binding

**Status:** CLOSED-IN-CODE (2026-08-22)  
**Class:** historical implementation-model correspondence gap  
**Historical premise:** the committed native adapter did not exist and only
`kubectl` could perform the local exhibit. That premise is obsolete.  
**Closure evidence:** `accordlock-eks-transport` implements one pinned-socket
HTTP/1.1-over-rustls GET/PATCH profile with explicit CA roots, DNS/SNI and ALPN
verification, exact bounded path/body construction, no proxy/redirect/retry,
and conservative post-write ambiguity. `ExclusiveEksExecutor` consumes the
opaque attempt and bearer by value, re-derives the command/wire commitments,
and authorizes exactly one write after the post-TLS currentness guard.  
**Non-claim:** the unit and composition tests do not establish live EKS
interoperability, endpoint custody, or complete mediation. Those remain OP-001
and Gate B.  
**Reopen criterion:** any productive caller can choose or alter the method,
path, query, headers, media type, body, retry policy, destination, or bearer
outside the committed route and attempt.

## Durability, recovery, and time

### OP-008. Terminal persistence and ambiguous outcomes

**Status:** OPEN-DEPLOYMENT  
**Class:** distributed-systems blocker  
**Historical premise:** terminal state, reservation release, takeover, and
recovery were wholly in-memory or absent. That premise is obsolete but the
broader external property is not closed.  
**Current local evidence:** migration `0012` atomically records signed exact
effect plus credential retirement, transitions `ATTEMPT_IN_FLIGHT -> TERMINAL`,
updates trusted time, and releases the active reservation. Migration `0014`
adds append-only leased acquisitions, recovery-only discovery, pre-effect
dispositions, exact no-send retirement, and irreversible history. A recovered
path never reconstructs a bearer or provider authority.  
**Remaining premise:** productive unknown effects still retain the reservation
for manual reconciliation; PostgreSQL and Kubernetes are not one transaction.
No retained live crash matrix proves every pre/post-commit, pre/post-write,
response-loss, lease-takeover, observer, terminalization, and HA-failover case.

**Closure criterion:** exercise every state commit and provider network boundary
with process and database failure injection; prove exact recovery/takeover,
that no unknown outcome can regain productive authority, that no reservation
is released without the exact authorized terminal or no-send proof, and that
live observer/terminal evidence remains valid across restart and failover.  
**Dependencies:** AWS-006, AWS-007, EXT-001, EXT-003, EXT-005.

### OP-008A. Durable physical-resource exclusion

**Status:** CLOSED-IN-CODE (2026-08-22)  
**Class:** historical multi-process gap  
**Historical premise:** the canonical physical reservation existed only in one
process. That premise is obsolete.  
**Closure evidence:** migration `0006` creates one global active reservation for
the rooted canonical cluster identity, namespace, and immutable Deployment UID.
Claims, monotone fences, rooted ownership, admission, terminalization, and v14
acquisition/no-send transitions are bound to it. A second authorization, tenant,
worker, process, or alias cannot obtain a concurrent active reservation inside
the registered identity model.  
**Non-claim:** live split-brain, backup rollback, HA, and unregistered aliases
remain infrastructure risks covered by OP-001, OP-008, and OP-010.  
**Reopen criterion:** two committed productive claims can own the same
registered physical key concurrently, or any release path omits the bound
terminal/no-send proof.

### OP-008B. Currentness between attempt commit and provider effect

**Status:** OPEN-DEPLOYMENT  
**Class:** external-boundary blocker  
**Historical premise:** no native executor consumed the marker by value and no
destination admission check existed. That premise is obsolete locally.  
**Current local evidence:** state revalidates the latest v14 acquisition before
the irreversible attempt transition; the executor consumes the attempt and
bearer once, enforces the state-derived deadline/credential/acquisition
horizon, and resamples immediately after TLS before the first HTTP byte. The
state-backed admission engine reloads the current attempt and atomically binds
one AdmissionReview UID to the claim, reservation, fence, authority, route,
credential, and payload provider request.  
**Remaining premise:** a revocation after the attempt commit cannot make the
database and remote effect atomic. The webhook server does not by TLS alone
authenticate its caller, and the admission path has not been deployed to prove
that every protected mutation passes through it.  
**Closure criterion:** document the attempt commit as the local linearization
point; deploy the fail-closed webhook behind an authenticated API-server-origin
boundary; prove payload attempt/fence/current-authority consumption and
bypass denial on EKS; and show that timeout or ambiguous handoff never triggers
an unsafe resend.  
**External dependencies:** AWS-002, AWS-004, EXT-001, EXT-005.

### OP-009. Durable distributed ingress replay state

**Status:** CLOSED-IN-CODE (2026-08-22)  
**Class:** historical ingress gap  
**Historical premise:** replay state was process-local. That remains true only
for `MemoryReplayGuard`, not for the production-state adapter.  
**Closure evidence:** migration `0010`, `IngressReplayState`, and
`accordlock-ingress-state` implement an audience-scoped PostgreSQL time
high-water and nonce ledger. Serializable transactions provide one concurrent
winner across processes; restart preserves replay state; rollback and
unavailable/ambiguous storage fail closed; expiry reuse and bounded garbage
collection follow the durable high-water. V13 submissions bind retained nonces
to durable intake.  
**Non-claim:** no public production ingress service, workload identity, or live
multi-region database test is claimed.  
**Reopen criterion:** a productive ingress adapter uses process-local replay,
recovers an unknown commit as authentication success, or allows a clock
rollback to resurrect a nonce.

### OP-010. Authenticated remote state service

**Status:** OPEN-DEPLOYMENT  
**Class:** infrastructure and operations blocker  
**Historical premise:** no authenticated TLS connector existed. That premise is
obsolete.  
**Current local evidence:** `TlsPostgresStore` requires structured configuration
rather than a connection string; uses explicit CA roots, DNS/SNI verification,
read-write server selection, rustls, SCRAM-SHA-256-PLUS channel binding, bounded
connection time, optional pinned target address, and optional client
certificate authentication. `accordlock-webhookd` loads secrets from bounded
files and validates the schema before readiness.  
**Remaining premise:** repository tests do not establish a live TLS handshake,
certificate/password rotation, workload-bound database identity, least-
privilege database roles, replication behavior, backup, restore, or disaster
recovery.  
**Closure criterion:** retain a live authenticated TLS/SCRAM-PLUS result against
the deployed database; bind each workload to a least-privilege role; test
cross-role denials, credential/certificate rotation, synchronous durability,
replica/failover behavior, backup restoration, rollback detection, and the
documented fail-closed behavior under partitions.  
**External dependencies:** AWS-002, AWS-006, AWS-007, EXT-005.

## Protocol, models, publication, and evaluation

### OP-011. Protocol freeze and independent encoding implementation

**Status:** OPEN  
**Class:** pre-stable-release blocker  
**Current local evidence:** provisional CDDL, canonical encodings, purpose
domains, and numeric reason registries track the Rust protocol.  
**Remaining premise:** the full v10-v14 operational profile is not frozen, and
no independent parser/encoder has checked every signed and durable byte shape.

**Closure criterion:** freeze versioning and unknown-field rules; publish
positive/negative vectors for ingress, registries, authorizations, claims,
acquisitions, admission, broker journal, and terminal evidence; and retain
byte-for-byte differential results from an independent implementation.  
**Dependencies:** EXT-002.

### OP-012. Model-to-code and model-to-SQL correspondence

**Status:** OPEN  
**Class:** formal-assurance blocker  
**Current local evidence:** bounded TLA+ models and targeted Rust/PostgreSQL
tests cover selected authorization, claim, and lifecycle transitions.  
**Remaining premise:** the models do not yet cover the complete v10-v14 schema,
native I/O, webhook timeouts, terminal witnesses, acquisitions, crash/restart,
HA, and provider behavior; a correct model can still describe the wrong code.

**Closure criterion:** freeze model files and TLC results; map each invariant to
specific Rust and SQL transitions; add v10-v14 crash/failover states; run
model-derived traces against the implementation; and obtain independent
formal-methods review.  
**Dependencies:** EXT-003.

### OP-013. Reproducible final source snapshot

**Status:** OPEN  
**Class:** publication blocker  
**Current local evidence:** the repository contains a pinned Rust toolchain,
lockfile, source manifest, migration checksums, pinned CI actions, and
fail-closed validation scripts.  
**Remaining premise:** there is no immutable reviewed public release and no
independent clean-checkout reproduction of the final sanitized tree.  
**Closure criterion:** run every required stage from the final clean source;
record exact tool versions and result counts; regenerate and verify the source
manifest; create a signed immutable revision/release; and reproduce it on a
second clean machine.  
**Dependencies:** GH-001, EXT-003.

### OP-014. Successful local Kubernetes integration

**Status:** OPEN  
**Class:** integration blocker  
**Current local evidence:** two deliberately separate local paths are
implemented. The bounded kind exhibit includes retained diagnostics, exact
patch, persisted-response validation, and strict rollout ownership checks. The
credential-free runner exhibit revalidates one exact authorized Deployment
snapshot, verifies its committed projection and preconditions, derives the
compact JSON Patch with the native executor's request builder, consumes the
durable dispatch and approval replay slots, and returns `NotSent`. The runner
exhibit performs no network I/O and never obtains a Kubernetes credential.
Neither path activates the native production composition. A retained live kind
run created the pinned cluster, observed its control-plane node as `Ready`, and
completed and revalidated the pinned baseline rollout. It then timed out while
capturing the pre-action Deployment, before the authorized target patch. A
second retained run stopped at bounded Docker access before cluster mutation.

**Remaining premise:** no retained run directory establishes a successful full
kind result. Docker Desktop 4.70.0 is crash-looping on the local host. A verified
Docker Desktop 4.88.1 installer is available, but the upgrade stopped at the
Windows UAC elevation step.  
**Closure criterion:** one immutable run directory contains the full successful
artifact set, exact source and tool versions, no failure marker, and a zero
runner exit. The report must say explicitly whether it exercised the exhibit or
the native enforcement composition. Neither result establishes EKS behavior.

**Dependencies:** LOCAL-001.

### OP-015. Security and utility evaluation

**Status:** OPEN  
**Class:** product-evidence blocker  
**Current local evidence:** synthetic differential scenarios and adversarial
regressions exercise selected local properties and remain marked
`benchmark: false`.  
**Remaining premise:** no secure-utility, false-refusal, human-escalation,
latency, strong native-policy baseline, or full-loop evaluation is published.

**Closure criterion:** freeze datasets and baselines; run static and full-loop
evaluation; report every refusal, failure, latency distribution, and escalation
without survivor filtering; and obtain independent reproduction.  
**Dependencies:** CUST-004, EXT-006.

## External validation and market evidence

### OP-016. Independent adversarial review

**Status:** OPEN  
**Class:** external dependency  
**Current local evidence:** internal and AI-assisted adversarial passes have
found and corrected defects.  
**Remaining premise:** contributors and tools involved in design or
implementation are not independent reviewers.  
**Closure criterion:** reviewers with no implementation ownership reproduce
the artifacts, attack the threat model, database capabilities, native
transport, credential lifecycle, admission origin, and terminal release; all
critical/high findings are remediated and independently retested.  
**Dependencies:** EXT-001 through EXT-005.

### OP-017. Real workflow and buyer validation

**Status:** OPEN  
**Class:** customer dependency  
**Current local evidence:** the fixed profile models a plausible GitHub Actions
to artifact registry to EKS deployment workflow.  
**Remaining premise:** no real customer workflow, design-partner acceptance,
accepted operational boundary, or measured utility evidence exists.  
**Closure criterion:** reconstruct a real workflow; identify a provenance
failure that existing controls actually miss; run shadow evaluation before
enforcement; and obtain written design-partner acceptance of reliability,
refusal, support, and break-glass boundaries.  
**Dependencies:** CUST-001 through CUST-006.

## Desktop and remote operations

### OP-018. Live messaging-provider transport

**Status:** OPEN-DEPLOYMENT  
**Class:** external integration dependency  
**Current local evidence:** signed approval challenges, bounded provider
payloads, Slack and Meta request authentication, Telegram webhook-secret
verification, Teams claims supplied by a trusted external OIDC verifier,
enrolled-actor checks, exact provider callback parsers, and a framework-neutral
inbound gateway are implemented. Its dedicated SQLite registry resolves
opaque callback tokens by digest without storing bearer values, retains signed
challenges and exact enrollments, and serializes consumption against durable
revocation. Restart, replay, expiry, wrong-actor, wrong-decision, and callback
tamper cases are covered locally. Strict fixed-authority outbound request
adapters and a native rustls/WebPKI client are also implemented. The client
rejects redirects,
proxies, non-public DNS results, ambiguous HTTP framing, oversized responses,
and unsafe authorities; one total deadline covers resolution, connect, TLS,
write, and response collection. Local queueing, durable single-host replay,
provider receipt classification, and the one-step worker are tested with both
the native wire engine and an injected deterministic transport. The worker
resolves credentials from opaque references, sends once, and transactionally
acknowledges, schedules, or dead-letters the job. Expired leases and ambiguous
outcomes are never resent automatically; authenticated reason codes and
secret-free attempt-summary digests remain available after restart. Desktop
stores provider configuration with operating-system-backed encryption and
passes enabled credentials only from its main process to a verified,
short-lived runtime over an inherited pipe. Fixed display-only alerts use
stable idempotency, exact-job claims, approval/configuration binding, bounded
retry wakeups, cancellation when the local request closes, and authenticated
terminal-row pruning. They contain no task details or remote controls.  
Desktop can also pair an Ed25519 gateway key and import one bounded,
gateway-signed verified-decision receipt through a native file picker for
local evaluation. The receipt is bound to the exact pending action, task,
channel and expiry; provider-event and receipt replay remain rejected after a
normal restart. Renderer IPC accepts neither provider callback bytes nor a
receipt payload. Each configured channel also has a fixed-copy connection test
that performs one real provider attempt without approval semantics or retry.  
**Remaining premise:** Microsoft Entra token verification is not implemented,
and the framework-neutral gateway is not exposed through a hardened public
HTTP/TLS listener. No enrolled Slack, Teams, Telegram, or WhatsApp account,
reachable callback route, retained token-refresh exercise, or provider-outage
exercise exists here. The native transport has no enterprise proxy, private-CA, or
sovereign-cloud profile. Manual reconciliation tooling for dead-letter
deliveries is not integrated into the desktop application. A crash after an
ambiguous send remains intentionally non-retryable. A local process that can
replace packaged binaries between verification and process creation remains a
check-to-use hardening boundary. Provider credentials also exist briefly as
garbage-collected strings inside the trusted Electron main process; the product
does not claim zero plaintext process memory.  
The file-import evaluation adapter does not prove provider callback
reachability or supply an always-on authenticated gateway-to-desktop transport.
**Closure criterion:** enroll disposable provider accounts; deliver the fixed
alert through every supported provider; retain redacted receipt, retry,
cancellation, rotation, restart, and outage evidence. For remote decisions,
place the local gateway behind a reachable hardened callback route, add trusted
Teams token verification, and repeat the local actor-binding, single-use,
revocation, expiry, and wrong-actor tests against live provider callbacks.  
**Dependencies:** EXT-003, CUST-003, CUST-004.

### OP-019. Live task-alignment lifecycle

**Status:** OPEN-DEPLOYMENT  
**Class:** live evaluation dependency  
**Current local evidence:** Goose now records a bounded plan checkpoint from
the actual assistant turn before a tool call is dispatched. It commits the
visible assistant text and ordered tool requests, including each request ID,
model-facing tool name, and argument digest. The selected request must appear
exactly once and match the proposal's session, run, tool-call ID, resolved tool
identity, and arguments.

The runtime constructs a typed `PRE_EXECUTION` bundle from the approved task
objective, plan checkpoint, and exact action proposal before authorization. It
revalidates and persists the complete bundle and its evaluation hash in the
same ledger transaction as the attempt. After execution it appends the observed
result digest, constructs and revalidates a `COMPLETE_TRACE` bundle, and
persists the complete evaluation hash with the execution record. Substituted
objectives, plans, proposals, results, profiles, records, timestamps, and
contexts fail validation. Audit schema v6 exposes the pre-execution evaluation
hash on `ACTION_STARTED` and the pre-execution and complete-trace hashes on
`ACTION_COMPLETED`. It also projects each revalidated record as a bounded
categorical **Task check** with **Task evidence** count and stable finding
reasons. `VERIFIED` requires at least one qualified evidence item and only
supported findings. The projection exposes no prompts, arguments, output, raw
evidence, or numeric score.

`AuthorizationDecision` schema 4 requires the exact pre-execution record hash.
`TaskControlProjection` schema 2 and `ExecutionLineage` schema 2 repeat that
same commitment, and their canonical digests cover it. Substituting the stored
record or any downstream copy therefore invalidates audit revalidation. The
complete-trace hash is completion evidence only; it is not retroactive
authority. The authorization decision, execution authorization, and execution
lineage carry only the pre-execution hash.

The provider-neutral library still supplies the strict evidence contract,
bounded material resolver, authenticated external-provider envelope,
calibration and provenance rules, restrict-only aggregation, and deterministic
source re-evaluation. Those contracts are not a claim about the quality or
truth of any live natural-language alignment judgment.

A pinned local resolver and deterministic provider now exercise that contract
with real local bytes. They can qualify only an exact configured digest for one
request, proposal, or context artifact. The provider provenance is fixed to
`DETERMINISTIC_CHECK` with `NOT_APPLICABLE` calibration; missing or unavailable
material produces review, while malformed requests, external disclosure,
binding substitution, and profile substitution fail closed. The provider
cannot qualify paraphrase, purpose, or natural-language intent.

**Remaining premise:** the connected runtime uses an empty evidence list. Its
evaluation therefore returns `REVIEW`, and audit schema v6 projects it as
`REVIEW_REQUIRED`; the interface shows **Not verified**. No production material
resolver, authenticated provider, calibrated evidence source, or authoritative
non-empty evidence ledger is connected. The pre-execution hash is
cryptographically bound through the authorization and
completed lineage, but the record itself is an abstention rather than qualified
task-alignment support. Bounded `developer/read` and `developer/tree` operations may
still be authorized automatically by the separate access and path policy,
while protected actions continue to require exact one-time approval.
`ExecutionLineage` records and revalidates exact handoff continuity; it does not
prove that an action preserved the user's meaning.

**Closure criterion:** connect a policy-scoped production material resolver and
qualified, authenticated provider; retain calibrated provider and disclosure
evidence; exercise the bound pre-execution decision path with non-empty source
evidence; expose bounded evidence details without presenting them as truth; and
publish representative false-review, latency, calibration, and adversarial-
substitution results.  
**Dependencies:** CUST-004, EXT-006.

### OP-020. Signed desktop distribution

**Status:** OPEN-DEPLOYMENT  
**Class:** release infrastructure dependency  
**Current local evidence:** source pins, binary build markers, integrity checks,
SBOM generation, and an unsigned development-package path exist.  
**Remaining premise:** no controlled Windows or macOS signing identity,
notarization evidence, production update channel, or clean-room installation
result is retained.  
**Closure criterion:** build from clean pinned revisions; sign and notarize with
controlled identities; verify upgrade, rollback, uninstall, retained audit
export, and fresh-machine installation; publish checksums and inventories.  
**Dependencies:** EXT-001, EXT-002.

### OP-021. Desktop controlled-network composition

**Status:** OPEN-DEPLOYMENT  
**Class:** live-evidence and enterprise-network dependency  
**Current local evidence:** the runtime has an atomic
HTTPS authorization-and-execution route, exact-domain and exact-method policy
commitments, single-use approval, durable observation, and a concrete native
transport. The transport uses static public roots and direct sockets, rejects
non-public or mixed DNS answers, authenticates the original DNS name, follows
no redirects, reads no ambient proxy or credential state, disables TLS early
data and resumption, sends once, and accepts only bounded, uncompressed,
unambiguously framed HTTP/1.1 responses. Its complete request/response path is
tested through an injected in-memory connector without Internet access.
Desktop stores an exact lowercase-domain allowlist through the trusted main
process, passes it to the verified runtime at launch, exposes the controlled
Goose tool only when configured, and mounts only approval-controlled GET and
HEAD requests. The renderer cannot add a destination to a running task.  
**Remaining premise:** no real provider has exercised this transport.
Enterprise proxies, private or
sovereign trust roots, split-horizon DNS, certificate rotation, network outage,
and post-send effect reconciliation are not evidenced. An ambiguous failure
after the request starts is recorded as execution unknown and is never retried
automatically.  
**Closure criterion:** retain real-provider tests for exact host, redirect, DNS rebinding, certificate,
timeout, oversized response and outage behavior; and define provider-specific
effect reconciliation before enabling mutating network actions.  
**Dependencies:** CUST-003, CUST-004, EXT-003.

### OP-022. Durable enterprise-runner state deployment

**Status:** OPEN-DEPLOYMENT  
**Class:** state-service and operations dependency  
**Current local evidence:** `accordlock-runner-engine` exposes an object-safe
state boundary and a strict SQLite implementation for one protected host.
Dispatch replay, action-approval replay, reservation, commit, release, fixed
capacity, and the trusted-time high-water mark are atomic and survive process
reconstruction. Pending rows are replay blockers, so a crash or ambiguous
commit never becomes permission to retry. Exact release is allowed only for a
known pre-effect failure; committed rows cannot be released and are pruned only
after their verified replay window closes. Pending rows are never time-pruned.
Independent connections have one reservation winner; unknown schemas and
capacity drift fail closed; and retained state contains no task text, provider
credential, or approval payload. The historical in-memory constructor remains
explicit for tests and account-free evaluation. The local deployment exhibit uses this same
state boundary: a successful preparation consumes the normal replay slots,
survives process reconstruction as a replay refusal, and returns `NotSent`
without provider transport or credentials.  
**Remaining premise:** SQLite establishes neither multi-host linearizability
nor disaster recovery. No protected production volume, backup/restore run,
disk-full exercise, OS identity boundary, filesystem rollback defense, or
independent review is retained. Connector observation sequence high-water
state remains separate and must also become durable before multiple productive
runner processes collect evidence.  
**Closure criterion:** deploy the database on a protected local volume for the
single-host profile and retain restart, crash, disk-full, corruption, backup,
restore, ownership and rollback tests. Before any multi-host profile, replace
SQLite with a reviewed linearizable state service implementing the same
contract and prove one winner under failover and partition.  
**Dependencies:** EXT-001, EXT-002, CUST-003.

## Update rule

Change a status only with dated evidence that directly satisfies its criterion.
A local implementation may close a historical code gap but never an
infrastructure, customer, or independent-review claim. A successful kind run
does not establish EKS behavior. A valid admission does not establish that
Kubernetes persisted the object. A provider timeout does not establish that no
effect occurred.
