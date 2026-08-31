# AccordLock Distribution Contract

This document defines the security boundary for the AccordLock desktop distribution. It is an implementation contract for local engineering and review, not a production readiness claim.

## Components

- **AccordLock Desktop** provides the Task, Approval, Settings, and History interfaces.
- **Protected Goose backend** runs the agent loop and routes protected tool calls through a mandatory Policy Enforcement Point.
- **AccordLock runtime** owns Task Policy state, Action Approval state,
  single-use authorization, and execution records. Production execution
  credentials are outside the current alpha.

The model provider can propose an action. It cannot approve, authorize, or execute a protected action by itself.

## Standard lifecycle

`TaskRequest -> TaskAuthorization -> ToolExecutionRequest -> PolicyDecision -> ApprovalDecision -> ExecutionAuthorization -> ExecutionRecord -> TaskReport`

### Task request

The desktop binds a plain-English objective to an exact workspace, session, run, capability set, protected paths, and expiry.

### Task authorization

The user approves the Task summary. The trusted desktop process sends an `APPROVE_SESSION` control request containing a v2 `ApprovedSession` and `TaskPolicy`. The runtime validates and stores the binding.

### Tool execution request

Immediately before a protected tool call, Goose creates a provider-independent `ToolExecutionRequest`. The request includes the exact session, run, tool call, canonical workspace, extension, tool name, arguments, and argument hash.

### Policy decision

The runtime returns `ALLOW`, `APPROVAL_REQUIRED`, or `DENY`. An allow decision includes a short-lived, single-use `ExecutionAuthorization` bound to the exact request.

### Approval decision

When an action is within the Task's approved capability set but is not preauthorized for automatic execution, the runtime returns an `ApprovalRequest`. Actions outside the Task authorization are denied and require a new Task. AccordLock shows the operation, target, change preview, reason, and expiry in plain English. Security details contain protocol identifiers and hashes. The trusted desktop process registers `APPROVED` or `DENIED` with `REGISTER_ACTION_APPROVAL`.

### Remote decision input

Messaging providers do not call the desktop application. A separate gateway
authenticates the provider callback and uses the approval-channel core to
produce a verified, single-use decision. The desktop accepts only a gateway-
signed receipt bound to the exact pending Approval Center item, task, channel,
expiry, challenge and provider event. The renderer can open native enrollment
and test-receipt pickers, but it cannot submit a provider payload, key or
receipt. A verified receipt remains a decision input; the existing trusted
resolver still creates and registers the action-specific proof.

The included local path imports signed fixtures for deterministic evaluation.
It is not an HTTP callback service. A production deployment still needs TLS
termination, provider account and webhook configuration, Microsoft token
verification, and a private authenticated gateway-to-desktop transport.

### Execution record

After execution, Goose records a `ToolExecutionObservation` through `/api/v2/execution/tool-observations/record`. A transport failure produces an unknown execution state and must not be presented as safe to retry.

### Audit and recovery

The runtime projects redacted ledger records through the private control
channel. Pagination is bound to one durable revision, bounded below the control
frame limit, and protected by a domain-separated page digest. The renderer can
export verified pages but cannot create or amend ledger records.

Session audit schema 6 adds a bounded categorical projection for each available
revalidated task-alignment evaluation. The desktop presents it as **Task check**
and **Task evidence**. `VERIFIED` requires at least one qualified evidence item
and only supported findings; zero evidence is `REVIEW_REQUIRED` and is shown
as **Not verified**. The projection contains no prompt, tool arguments, raw
evidence, output, or numeric score, and it cannot expand task authority.

The desktop persists an encrypted task locator before installing runtime
authority. Reopening history requires the same canonical workspace selected by
the trusted main process. Supported deletion recovery is bound to the original
execution record and requires a fresh restore challenge.

## v2 routes

- `GET /api/v2/health`
- `POST /api/v2/authorization/tool-calls/authorize-and-consume`
- `POST /api/v2/execution/tool-observations/record`
- `POST /api/v2/execution/filesystem/authorize-and-execute`
- `POST /api/v2/execution/terminal/authorize-and-execute`
- `POST /api/v2/execution/network/authorize-and-execute` (mounted only when the
  trusted main process starts the runtime with an exact domain allowlist; GET
  and HEAD only, with exact approval)

## Fail-closed requirements

- AccordLock distribution builds cannot select the upstream pass-through path.
- Unknown protocol fields are rejected.
- Workspace paths are canonicalized and bound before authorization.
- Authorization is short-lived, request-specific, and single-use.
- Protected tools never fall back to direct execution after a runtime error.
- An unavailable record endpoint yields `EXECUTION_UNKNOWN`.
- Pre-release local data with an incompatible database version is never silently deleted or migrated.
- Desktop renderer processes do not receive the runtime bearer token or backend binding secret.
- A renderer cannot claim another workspace's durable task history by knowing
  its session identifier.
- A continuation audit page cannot be combined with a different ledger
  revision.

## Build markers

A generated Windows development package stages three verified binaries:

- `goose.exe` with `accordlock-build.json`
- `accordlock-agent-runtime.exe` with `accordlock-runtime-build.json`
- `accordlock-preflight-runner.exe` with `accordlock-preflight-runner-build.json`

All marker files use `schema_version: 2`, include the source commit, dirty-source flag, binary name, and SHA-256 digest. The runtime marker also commits `protocol_version: 2`. Release packaging requires clean source trees. Explicit dirty builds are limited to unsigned local development. The macOS pipeline stages the equivalent architecture-matched sidecars, rebinds their digests before packaging, and emits separate DMG and ZIP artifacts for arm64 or x64.

## Publication boundary

AccordLock owns one minimal read-only publication guard workflow. Inherited workflows are manually triggered fail-closed stubs until they receive an AccordLock-specific threat review. The repository contains no public signed installer, production support promise, or automatic update channel.

## Attribution

AccordLock is derived from Goose. License and third-party attribution are packaged from repository-local `NOTICE` and `THIRD_PARTY_NOTICES.md` files.
