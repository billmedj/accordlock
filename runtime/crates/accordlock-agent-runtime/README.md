# AccordLock agent runtime

This crate is the trusted local authority used by the AccordLock Goose
distribution. Its Desktop binary exposes only authenticated health and
runtime-owned atomic filesystem/terminal execution on a literal loopback
listener. Goose cannot submit caller-reported authorization or observation.

## Task/session bootstrap

Goose cannot register or widen its own authority. Before Goose's first tool
call, the trusted Desktop main process must:

1. obtain the user's approval over a concrete Task Policy;
2. build the closed typed `TaskPolicy` outside the renderer and Goose;
3. construct `ApprovedSession::new_with_task_objective(...)` with the Goose
   `session_id`/`run_id`, canonical workspace, current nonzero policy epoch,
   exact approved task objective, Task Policy, approval window, and explicit
   `(extension_id, tool_name)` capabilities;
4. send that record over the inherited control channel described below;
5. only after that durable insertion, start or release the policy-controlled Goose
   session.

`approve_session` writes an immutable binding directly to SQLite. Duplicate
session or task identifiers are rejected; they are never updated through an
upsert. An unknown session receives `DENY/UNKNOWN_SESSION`.

Schema v5 is a pre-release reset boundary. SQLite files created by earlier
private alpha builds are never migrated or modified in place: versions 1 through
4 fail with `PreReleaseStateResetRequired`. Export anything needed for audit,
then start with a new local database.

The standalone `serve` binary starts with no approved sessions. It therefore
satisfies Desktop startup/health and denies every tool call until Desktop sends
an approval through the private channel. No registration HTTP endpoint is
exposed, because Goose receives the planner HTTP bearer and must never be able
to turn that bearer into policy authority.

## Private Desktop control channel

Desktop starts the runtime with `--control-stdio`, gives it dedicated inherited
stdin/stdout pipes, and never passes those pipe handles to Goose or the
renderer. The pipe itself is the capability; there is no bearer or address to
discover. Closing Desktop's write end terminates the runtime and therefore its
HTTP planner surface.

When `--ready-line` is present, stdout begins with exactly one existing ASCII
line:

```text
ACCORDLOCK_RUNTIME_READY={"schema_version":2,"url":"http://127.0.0.1:<port>"}\n
```

Immediately after that newline, both pipe directions consist only of binary
frames:

```text
4 bytes  ASCII magic "ALC1"
4 bytes  unsigned JSON byte length, big-endian
N bytes  UTF-8 JSON payload (0 <= N <= 262144)
```

Version-2 requests are strict (`deny_unknown_fields` recursively). Approval is:

```json
{
  "schema_version": 2,
  "request_id": "01234567-89ab-4def-8123-456789abcdef",
  "method": "APPROVE_SESSION",
  "approved_session": {
    "schema_version": 3,
    "task_id": "01234567-89ab-4def-8123-456789abcdef",
    "session_id": "goose-session-id",
    "run_id": "goose-run-id",
    "workspace_root": "<absolute canonical existing directory>",
    "policy_epoch": 1,
    "task_policy": {
      "schema_version": 2,
      "task_objective_hash": "sha256:<64 lowercase hex characters>",
      "preauthorized_capabilities": [
        {"extension_id": "developer", "tool_name": "read"},
        {"extension_id": "developer", "tool_name": "tree"}
      ],
      "protected_paths": [
        ".accordlock", ".env", ".git", ".goose", ".ssh", "credentials"
      ]
    },
    "task_policy_hash": "sha256:<domain-separated contract commitment>",
    "task_objective": "Inspect the approved workspace without changing it.",
    "capabilities": [
      {"extension_id": "developer", "tool_name": "read"},
      {"extension_id": "developer", "tool_name": "tree"},
      {"extension_id": "developer", "tool_name": "write"}
    ],
    "approved_at": 1787472000,
    "expires_at": 1787475600
  }
}
```

`request_id` must be a non-nil lowercase hyphenated UUID. The approval must
pass the canonical `ApprovedSession` profile: canonical workspace, sorted and
unique explicit capabilities, nonzero policy epoch and policy commitment,
an exact nonempty objective whose UTF-8 digest matches
`task_policy.task_objective_hash`, and a bounded validity window.

## Live plan and task-alignment bridge

Before each tool dispatch, Goose captures one `AgentPlanCheckpoint` from the
actual assistant turn. The checkpoint contains the visible assistant text and
ordered tool requests. Each request contributes its ID, model-facing tool name,
and canonical argument digest. Hidden reasoning, transport metadata, tool
results, and binary content are excluded. The selected request must occur
exactly once and match the proposal's session, run, tool-call ID, resolved tool
identity, and argument digest.

`ToolCallProposal` schema 3 carries that checkpoint. The runtime validates the
checkpoint and builds a `PreExecutionLiveIntentBundle` from the approved task
objective, plan, and exact action. It revalidates the resulting
`IntentConformanceRecord` over the source objects, then persists the bundle and
its digest in the same SQLite transaction as the authorization attempt. When a
result is observed, the runtime revalidates the pre-execution bundle, appends
the exact result digest, builds a `CompleteLiveIntentBundle`, revalidates it,
and persists it with the execution record.

The connected profile intentionally supplies no provider evidence. Its
evidence list is empty and its evaluator outcome is therefore `REVIEW`; it
cannot claim natural-language support. No production material resolver, authenticated
provider, calibrated evidence source, or non-empty authoritative evidence
ledger is connected. `AuthorizationDecision` schema 4 requires the exact
pre-execution evaluation hash. Its canonical digest covers that field, and the
single-use execution authorization binds the decision digest.
`TaskControlProjection` schema 2 and `ExecutionLineage` schema 2 repeat the same
pre-execution hash. Bounded `developer/read` and `developer/tree` operations may
still be automatic when their separate access and path checks pass; binding an
abstaining evaluation does not turn it into task-alignment support.

Only bounded `developer/read` and `developer/tree` may be automatic. Before
either runs, the runtime parses the strict filesystem request, confirms local
read-only scope, and excludes native secret patterns plus task-specific
`protected_paths`. It then creates a bound `TaskRequirement`,
`TransformationStep`, `ConformanceEvaluation`, and `PolicyDecisionRecord`.
The authorization commits their hashes, and the ledger retains the complete
evaluation for audit revalidation. A missing, mismatched, or altered record
fails closed.

Every completed action also creates an immutable, provider-neutral
`ExecutionLineage` schema 2. It binds the approved task identity, objective,
and policy to the exact tool proposal, complete execution request,
pre-execution intent-evaluation hash, authorization decision, single-use
execution authorization, completed execution record, and trusted
start/completion times. All commitments are derived from complete validated
objects; no proposal is relabeled as a plan and no authorization is relabeled
as an action. Historical trace schemas remain read-only for audit
compatibility. Prompts, tool arguments, and output are not copied into the
lineage. The trusted runtime database separately retains complete tool
proposals for exact validation, idempotence, and recovery. That database can
therefore contain sensitive arguments and must be protected as trusted local
state; only its audit projection is redacted.

Audit page schema 6 exposes only the bounded projection needed by the desktop:
`execution_lineage_hash`, `task_scope_status`, `review_status`,
`decision_reason_code`, `task_control_hash`, `task_control_provenance`, and the
intent-evaluation hashes. `ACTION_STARTED` carries
`intent_evaluation_hash`; `ACTION_COMPLETED` carries
`intent_pre_evaluation_hash` and `intent_complete_evaluation_hash`.
The pre-execution hash is part of authority and lineage. The complete-trace
hash is post-execution audit evidence and cannot retroactively authorize an
action.

Each available evaluation is also revalidated and projected as an
`intent_assessment` containing its profile, categorical status, qualified
evidence count, and stable finding reasons. `VERIFIED` requires at least one
qualified evidence item and only supported findings. Zero evidence is
`REVIEW_REQUIRED`, which the desktop presents as **Not verified** under
**Task check** and **Task evidence**.

Provenance distinguishes current `LINEAGE_BOUND` evidence from `EMBEDDED` or
`RECONSTRUCTED` historical evidence. The page does not expose prompts, model
output, raw evidence, or an opaque numeric score.

For historical storage schemas 1 and 2, `execution_lineage_hash` is never an
old trace or bundle commitment under a new label. The runtime first verifies
that historical commitment, revalidates the complete request, decision,
authorization, record, proposal, and approved-session scope, then derives the
current `ExecutionLineage` and exposes its domain-separated digest. The legacy
storage commitment remains an internal compatibility check.

The plan checkpoint, typed intent bundles, and completed execution lineage
record and revalidate exact object handoffs. They do not claim that free text
and an action mean the same thing. Qualified task-alignment evidence is
designed to be restrict-only: it may require review or deny, but cannot create
authority. That qualified evidence path is not yet connected. File writes,
terminal commands, network requests, credential paths, destructive actions,
and invalid or ambiguous read requests still require exact approval or are
denied by the independent structural policy.

Every accepted request receives one framed response with this exact shape:

```json
{
  "schema_version": 2,
  "request_id": "01234567-89ab-4def-8123-456789abcdef",
  "status": "ACK",
  "code": "SESSION_APPROVED",
  "approval_digest": "sha256:<64 lowercase hex characters>"
}
```

An exact durable retry returns `ACK/SESSION_ALREADY_APPROVED` with the same
digest. Reusing either `session_id` or `task_id` for a different record
returns `ERROR/APPROVAL_CONFLICT`; authority is immutable and never widened by
an upsert. Other recoverable codes are `MALFORMED_REQUEST`,
`INVALID_REQUEST_ID`, `UNSUPPORTED_SCHEMA`, `UNSUPPORTED_METHOD`,
`INVALID_APPROVAL`, and `LEDGER_UNAVAILABLE`. Error responses set
`approval_digest` to `null`; frame-level errors also set `request_id` to `null`.

Bad magic, an oversized declared length, or truncation produces respectively
`FRAME_HEADER_INVALID`, `FRAME_TOO_LARGE`, or `FRAME_TRUNCATED`, then terminates
the channel. The runtime never attempts to resynchronize an attacker-controlled
stream.

Desktop can later disable that exact authority without exposing a planner HTTP
route:

```json
{
  "schema_version": 2,
  "request_id": "11234567-89ab-4def-8123-456789abcdef",
  "method": "REVOKE_SESSION",
  "session_revocation": {
    "schema_version": 2,
    "task_id": "01234567-89ab-4def-8123-456789abcdef",
    "session_id": "goose-session-id",
    "run_id": "goose-run-id"
  }
}
```

The successful response repeats the complete identity and binds it to the
canonical revocation digest:

```json
{
  "schema_version": 2,
  "request_id": "11234567-89ab-4def-8123-456789abcdef",
  "status": "ACK",
  "code": "SESSION_REVOKED",
  "revocation_digest": "sha256:<64 lowercase hex characters>",
  "task_id": "01234567-89ab-4def-8123-456789abcdef",
  "session_id": "goose-session-id",
  "run_id": "goose-run-id"
}
```

The first revocation is immutable and durable. An exact retry returns
`ACK/SESSION_ALREADY_REVOKED` with the same digest and identity. Unknown,
partial, or cross-bound identities return `UNKNOWN_SESSION` or
`REVOCATION_BINDING_MISMATCH`; a conflicting durable record returns
`REVOCATION_CONFLICT`. Revocation records are retained rather than deleting
approvals, so registering the original approval again cannot resurrect it.
The first write must be timestamped at or after every event already committed
for the session; an earlier trusted timestamp returns `INVALID_REVOCATION_TIME`.
This check runs after the exact-retry fast path, so retries remain idempotent.
Every later authorization attempt is durably denied with `SESSION_REVOKED`.
The transition is prospective: an authorization already consumed and executing before
the serialized revocation transaction is not retroactively cancelled.

## Private audit projection

Desktop can read a compact task history through `GET_SESSION_AUDIT` on the
same inherited ALC1 channel. The planner HTTP surface does not expose this
method. A request binds one exact `session_id` and a bounded page:

```json
{
  "schema_version": 2,
  "request_id": "41234567-89ab-4def-8123-456789abcdef",
  "method": "GET_SESSION_AUDIT",
  "audit_query": {
    "schema_version": 2,
    "session_id": "goose-session-id",
    "offset": 0,
    "limit": 50,
    "snapshot_revision": null
  }
}
```

The response projects session approval and revocation, action decisions,
starts, outcomes, denials, and file restores from SQLite. It includes a page
digest, stable event identities, and a durable `snapshot_revision`. The first
request omits that revision (or sends `null`). Every request with a non-zero
offset must repeat the exact revision returned by the first page. If any
audit-relevant row for that session changes, the runtime returns
`AUDIT_SNAPSHOT_CHANGED`; the client restarts at offset zero instead of merging
two different histories. Activity in another session does not invalidate the
page sequence.

It never includes the runtime bearer, provider credentials, raw action
arguments, file contents, or terminal output. Pages contain at most 100 events
and at most 252 KiB of encoded page JSON, leaving framing space below the 256
KiB control-channel limit. Unknown sessions, malformed bounds, histories above
100,000 events, oversized single events, and corrupt evidence fail closed with
typed errors. The underlying records and protocol hashes remain authoritative.
The projection is a read-only display and export surface.

`page_digest` is the lowercase `sha256:` digest of these exact bytes:

```text
ASCII("accordlock:v5:session-audit-page\0") ||
UTF8(canonical_json([5, task_id, session_id, run_id, offset, next_offset,
                     total_events, snapshot_revision, snapshot_at, events]))
```

`canonical_json` recursively sorts object keys, preserves array order, and uses
compact JSON. The digest detects accidental or parser-level divergence; it is
not a signature and does not authenticate an export outside the private
runtime channel.

## Exact single-use action approval

Goose-provided scores or evidence never grant mutation authority. Without a
matching private approval, the filesystem executor returns this bounded runtime
challenge; unrelated optional fields are omitted:

```json
{
  "schema_version": 2,
  "proposal_digest": "sha256:<exact complete proposal>",
  "status": "APPROVAL_REQUIRED",
  "reason_code": "ACTION_APPROVAL_REQUIRED",
  "approval_request": {
    "schema_version": 2,
    "task_id": "01234567-89ab-4def-8123-456789abcdef",
    "session_id": "goose-session-id",
    "run_id": "goose-run-id",
    "tool_call_id": "goose-tool-call-id",
    "proposal_digest": "sha256:<exact complete proposal>",
    "task_policy_hash": "sha256:<approved contract>",
    "prestate_hash": "sha256:<executor-observed target state>",
    "action": {
      "extension_id": "developer",
      "tool_name": "write",
      "relative_path": "notes.txt",
      "action_type": "CREATE_FILE",
      "requested_bytes": 8
    }
  },
  "approval_request_hash": "sha256:<domain-separated approval context>"
}
```

Desktop resolves only those exact bindings over ALC1. It constructs the
`ActionApproval` with `ActionApproval::for_context(...)`, which copies the full
`task_requirement`, `transformation_step`, `policy_decision`, and
`policy_decision_hash` from the runtime challenge. Desktop chooses only a fresh
`approval_id`, `APPROVED` or `DENIED`, the approval evidence hash, and a bounded
validity window. The complete object is sent as `action_approval` with method
`REGISTER_ACTION_APPROVAL`; unknown or omitted fields fail closed.

The exact ACK is:

```json
{
  "schema_version": 2,
  "request_id": "21234567-89ab-4def-8123-456789abcdef",
  "status": "ACK",
  "code": "ACTION_APPROVAL_REGISTERED",
  "approval_digest": "sha256:<canonical approval>",
  "approval_id": "31234567-89ab-4def-8123-456789abcdef",
  "proposal_digest": "sha256:<exact complete proposal>",
  "approval_request_hash": "sha256:<runtime approval context>"
}
```

An exact retry returns `ACTION_APPROVAL_ALREADY_REGISTERED`; changed bindings
fail closed. `APPROVED` yields protocol outcome `ALLOW_AFTER_APPROVAL` and
is consumed in the same SQLite transaction as the authorization. The executor then
rehashes the same prestate on the opened target handle immediately before
mutation. A change returns `STATE_STALE`; the consumed approval cannot be reused.
The optional non-Desktop core authorization route has no trusted
action/prestate envelope, so a mutating proposal gets
`EXECUTION_CONTEXT_REQUIRED`, never a resolvable approval challenge.

## Standalone launch contract

Desktop launches:

```text
accordlock-agent-runtime serve --host 127.0.0.1 --port 0 --ready-line --control-stdio
```

with `ACCORDLOCK_RUNTIME_TOKEN` and an absolute
`ACCORDLOCK_RUNTIME_DATA_DIR`. After opening the durable ledger and binding the
socket, the process emits exactly one readiness line and serves authenticated
`GET /api/v2/health`, atomic filesystem execution, and atomic terminal
execution. The binary uses `RuntimeConfig::for_accordlock_desktop`; generic
authorization and caller-reported observation are not mounted. Controlled HTTPS
is absent by default. The trusted Desktop launcher may add repeatable
`--https-domain <exact-lowercase-domain>` arguments; only then does the runtime
mount atomic GET/HEAD execution through its direct WebPKI transport. The
transport has no proxy, cookie, redirect, retry, ambient credential, or local
address path.
Library integrations that still need the historical core protocol must opt
into the `caller-reported-governance` Cargo feature and use `RuntimeConfig::new`.
Its observations are caller-reported and must not be presented as Desktop
execution receipts.

To reopen a stopped ledger, Desktop launches a separate process:

```text
accordlock-agent-runtime audit --control-stdio
```

It receives an absolute existing `ACCORDLOCK_RUNTIME_DATA_DIR` but no runtime
token. It does not create or migrate a database, bind an HTTP socket, accept
approvals or revocations, or execute tools. It opens the current ledger schema
with SQLite read-only and `query_only` protections and accepts only the strict,
bounded `GET_SESSION_AUDIT` control request. Missing, linked, outdated, corrupt,
or mutation-shaped input fails closed without granting execution authority.

## Display-only approval notifications

Desktop may launch the same verified binary in a separate, short-lived mode:

```text
accordlock-agent-runtime notify --request-stdio
```

This process receives one bounded `ALN1` frame through inherited standard
input and writes only a secret-free delivery report. The request contains an
exact pending-approval digest, its fixed receipt time and local expiry, a
host-protected outbox key, and at most one enabled configuration for each
supported provider. The receipt-to-expiry window cannot exceed five minutes. Provider
credentials travel only through the inherited pipe. They are never placed in
arguments, environment variables, the encrypted outbox, provider payloads, or
diagnostics. They necessarily exist transiently in the trusted sender and
runtime process memory; zeroization is best effort where the host language
allows it.

The runtime builds temporally stable fixed copy: `AccordLock alert` and `Open
Approval Center to see the latest status.` It includes no task objective, workspace, path, command,
action preview, approval link, callback token, or remote decision button. The
single encrypted SQLite outbox deduplicates by exact approval digest and
channel across process launches. Each launch claims and reports only the exact
job identifiers returned by that request; it never drains an unrelated job.
Credential references also bind the approval, channel, expiry, destination,
and non-secret endpoint configuration while allowing provider-token rotation.
A queued job is rejected after the local approval expires, including when
expiry occurs during a multi-channel batch. The report exposes only a validated
next retry time for those exact jobs. Desktop may schedule a bounded wake-up
only while the same local approval remains pending. Old terminal rows are
removed in bounded authenticated batches; the outbox itself also has a fixed
record capacity. Notification failure never approves an action and never
changes the pending local decision.

This mode sends outbound messages only. It does not accept provider callbacks
or remote approvals, denials, task stops, or revocations.

## Native terminal broker

`POST /api/v2/execution/terminal/authorize-and-execute` accepts a strict
`ToolCallProposal` for `developer/shell`. Its arguments are not a command
string:

```json
{
  "argv": ["cargo", "test", "-p", "example"],
  "cwd": ".",
  "env": {"CI": "true", "NO_COLOR": "1"},
  "timeout_seconds": 60,
  "max_output_bytes": 65536
}
```

`argv[0]` is a trusted alias, never a model-selected path. Desktop binds each
alias to one canonical executable when it launches the runtime, for example:

```text
--terminal-program cargo=sha256:<64 lowercase hex>=C:\Tools\cargo.exe
```

Shells, script hosts, generic interpreters, shebang scripts, relative
executable paths, PTYs, command strings, response-file indirection, absolute or
traversing argument paths, explicit URL arguments, unknown fields, traversal
working directories, arbitrary environment names or values, unbounded
arguments, output, and timeouts are rejected. The process receives null stdin,
an empty inherited environment, and only the small explicit low-entropy
allowlist. Runtime, AWS, GitHub, Kubernetes, proxy, and other ambient
credentials are not copied into the child.

Every accepted process proposal still needs a signed, single-use action approval.
The runtime commits the executable bytes, native file identity, explicit
environment names, and canonical working directory in the approval prestate.
It keeps the provisioned file identity open for the runtime lifetime and opens
another pinned handle for each execution. On Windows that handle denies write
and delete sharing from provisioning through process completion. On Linux the
broker asks the kernel to execute `/proc/self/fd/<pinned-fd>` rather than
re-resolving the configured path. The identity and bytes are rechecked before
and immediately after spawn and again after process-tree cleanup. Any mismatch
after authorization is `EXECUTION_UNKNOWN`, never a normal process failure.

The terminal result includes the pinned executable digest, a domain-separated
digest of the exact invocation, and SHA-256 digests of the complete stdout and
stderr streams even when the displayed prefix is truncated. Returned text
replaces terminal escapes, control characters, and bidirectional formatting
characters; the raw-stream digests preserve deterministic evidence without
letting untrusted output control the desktop display. The broker atomically
consumes authorization and records either that result or an indeterminate tool
error in the durable ledger. In the optional core profile, sending the same
proposal to the generic authorization route does not authorize direct
execution; it returns `EXECUTION_CONTEXT_REQUIRED`.

Before spawn, every isolated process is placed in a Windows Job Object or a new
Unix process group. A parent exit is not completion: the broker terminates and
waits for the complete job/group before returning, so ordinary descendants
cannot remain as background work. Timeout, wait, output-capture, or tree-cleanup
uncertainty is never reported as a retryable process failure; it returns
`EXECUTION_UNKNOWN` with a consumed authorization and durable record. Tests cover
both a naturally exiting parent and a timed-out parent that each launch a real
descendant.

This containment is not an OS sandbox. It does not add a lower-privilege user,
filesystem namespace, network namespace/firewall, syscall filter, CPU or
memory quota, or other kernel-enforced isolation. A configured native program
can still use authority available to the runtime user, interpret its own
workspace configuration, or attempt to leave a Unix process group. The generic
broker cannot infer every program-specific argument meaning. macOS and other
non-Linux Unix targets revalidate the open identity around a path-based spawn;
unlike Windows and Linux, they do not yet use an identity-stable spawn primitive.
Those platform sandbox, resource, and non-Linux identity-stable-spawn controls
remain production gates. The broker must not be described as sandboxed or
production-grade until those controls are supplied and independently tested.

## Native HTTPS broker

When the route is explicitly enabled, `POST
/api/v2/execution/network/authorize-and-execute` accepts only
`accordlock_network/https_request` proposals with explicit method, HTTPS URL,
sorted allowlisted headers, bounded UTF-8 body/response, timeout, and
`"redirect_policy":"DENY"`. HTTP, credentials in URLs or headers, IP literals,
localhost names, noncanonical domains/ports, GET/HEAD bodies, redirects, and
unknown fields are rejected.

The Desktop profile leaves the route absent by default. Its trusted launcher
may supply one or more exact lowercase `--https-domain` values; only then does
the runtime install `WebPkiHttpsEgress` and mount the route. Library integrations
can install the same transport through `Runtime::with_https_egress`. The
supplied transport uses Mozilla public roots,
direct public-IP connections, exact DNS-name TLS authentication, HTTP/1.1 with
connection close, one total deadline, strict response framing, and bounded
headers and body. It reads no proxy environment, owns no credentials, disables
client authentication, early data and session resumption, and never redirects,
retries, decompresses, pools, or reuses a connection. Every DNS answer must be
public; one mixed public/private answer fails closed before connect.

Without an explicitly installed transport, the core route returns
`NETWORK_EGRESS_NOT_CONFIGURED` before creating or consuming an authorization;
it never fabricates success. With one, the exact domain, method and byte limits
are committed into approval prestate and rechecked before send. The single-use
authorization and network execution record follow the same durable path as
local filesystem and command execution.

This closes the native transport and local Desktop composition gaps, not the
live-evidence gate. Enterprise proxies,
private certificate authorities and sovereign roots are not supported. The
OS resolver, public CA ecosystem and remote server remain trust dependencies,
and a failure after request transmission remains an ambiguous effect that is
recorded as execution unknown rather than retried.
