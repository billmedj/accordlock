# AccordLock Architecture

**Release stage:** Engineering Alpha · **Document scope:** the public monorepo assembled on 2026-08-31 · **Production status:** not production-ready

## System in one sentence

AccordLock is a desktop agent and independent execution runtime that turns a model-proposed tool call into a bounded transaction: the requested effect must match an approved task, current authority, current state, admitted evidence, and available resources before a credential-holding component can perform it.

The governing rule is simple:

> A model may propose an action. It cannot create authority for that action.

This rule applies to helpful output, hallucinated output, and output influenced by hostile instructions. AccordLock does not depend on the model recognizing every attack. It makes protected execution depend on state that the model does not control.

## Product topology

```text
┌─────────────────────────────────────────────────────────────────────┐
│ AccordLock Desktop                                                  │
│ projects · tasks · model connection · approvals · activity         │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ fixed task contract
                                v
┌─────────────────────────────────────────────────────────────────────┐
│ Protected agent backend                                             │
│ model conversation · plan checkpoint · normalized tool proposal     │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ untrusted proposal
                                v
┌─────────────────────────────────────────────────────────────────────┐
│ AccordLock runtime                                                  │
│ task policy · conformance evidence · authority · state · approvals  │
│ single-use authorization · transaction ledger · recovery            │
└──────────────┬──────────────────────────────┬───────────────────────┘
               │                              │
               │ exact execution authority    │ redacted projection
               v                              v
┌──────────────────────────────┐   ┌──────────────────────────────────┐
│ Brokered executors           │   │ Operator surfaces                │
│ filesystem · process · HTTPS │   │ approval center · audit · export │
│ preflight · Kubernetes path  │   │ recovery · remote decision input │
└──────────────┬───────────────┘   └──────────────────────────────────┘
               │ owned credentials
               v
        operating system / GitHub / AWS / ECR / Kubernetes
```

The Electron renderer and the model-facing agent loop are outside the authorization boundary. A trusted main process starts the local runtime, keeps its bearer material out of the renderer, selects the workspace, and mediates access to operating-system credential storage. Credential-holding executors accept only typed, pre-authorized operations.

## Three independent questions

AccordLock keeps three decisions separate because substituting one for another produces unsafe systems.

### 1. Is the action authorized?

The task policy answers whether the exact tool, operation, workspace, target, and limits are within the authority approved for the task. This decision is structural. A model response, confidence score, or successful process cannot grant additional access.

### 2. Does qualified evidence support the action?

The conformance engine evaluates the approved request, the recorded agent plan, the exact proposed action, current context, and admitted evidence. Evidence is restrict-only: it can preserve an existing policy decision or increase restriction. It cannot add a tool, target, credential, network destination, or resource allowance.

The connected free-text desktop path currently has no qualified production evidence provider. It therefore records an explicit abstention and shows **Not verified**. This projection is separate from structural task policy; bounded reads may still run automatically inside approved access. The runtime can verify exact configured artifact digests; byte identity is not a claim about meaning.

### 3. What effect is known to have occurred?

An execution observation records an outcome separately from authorization. A timeout, lost response, or interrupted process can produce `UNKNOWN`. Unknown effects are reconciled; they are not treated as safe to retry.

## Protected transaction

Every consequential action follows the same logical sequence.

| Stage | Owned by | Security-relevant output |
| --- | --- | --- |
| Task creation | trusted desktop | objective, canonical workspace, capabilities, protected paths, expiry |
| Task approval | user and runtime | immutable task authorization and policy epoch |
| Plan capture | protected agent backend | bounded checkpoint of visible assistant text and ordered tool requests |
| Action proposal | protected agent backend | normalized tool identity, canonical arguments, argument digest, target context |
| Pre-execution evaluation | runtime | revalidated categorical evidence record bound to request, plan, and action |
| Policy decision | runtime | allow, exact approval required, or deny |
| Human decision | trusted approval surface | short-lived decision for one pending action |
| Execution authorization | runtime | request-specific, short-lived, single-use authority |
| Brokered execution | credential-holding executor | one exact effect attempt |
| Observation | executor and runtime | applied, not applied, failed, or unknown result evidence |
| Complete trace | runtime | immutable request-plan-action-result lineage for audit and reconciliation |

Each later record commits to the exact earlier records it consumes. Changing the task, plan, arguments, target state, evidence, policy epoch, authorization, or result changes the commitment and invalidates the chain.

## Decision semantics

Runtime access decisions are intentionally small:

- `ALLOW` means the exact action is inside the fixed task policy and may receive a single-use execution authorization.
- `APPROVAL_REQUIRED` means the action is eligible for an exact human decision but is not pre-authorized for automatic execution.
- `DENY` means the action is outside the task or failed an integrity or enforcement check. A broader task must be reviewed separately.

Evidence findings use a different vocabulary:

- supported evidence preserves the structural decision;
- uncertainty or missing qualified evidence is classified as requiring review by the evidence engine;
- a qualified contradiction blocks dispatch.

The current desktop displays that classification as **Not verified**; it is not yet a universal dispatch condition for every local tool. Execution outcomes form a third vocabulary. In particular, `UNKNOWN` is an effect-knowledge state, not an access decision.

## Exact authorization

An execution authorization repeats the security-relevant identity of the request. Depending on the operation, this includes:

- task, session, run, and tool-call identifiers;
- principal and policy or configuration epochs;
- canonical workspace and protected target;
- tool identity and canonical argument digest;
- target-state or precondition commitment;
- pre-execution evaluation commitment;
- validity interval and audience; and
- a unique authorization identifier.

The runtime consumes that identifier atomically. A valid signature is insufficient after expiry, state drift, authority drift, target substitution, argument substitution, or prior use.

## Local execution surfaces

### Filesystem

Read operations can be automatic when they remain inside the approved canonical workspace and task policy. Edits, writes, deletion, and restore use exact authorization. Supported deletion uses recovery storage and binds a later restore challenge to the original execution record.

Path checks are performed on canonical paths. Protected locations remain unavailable even if the model requests them through alternate spelling or traversal.

### Process execution

Process execution is disabled until the user allows specific programs. The runtime authorizes direct executable-plus-argument vectors rather than shell text, verifies executable identity where supported, and requires a one-time decision for each invocation. Descendants are tracked through Windows Job Objects or Unix process groups.

This boundary limits what AccordLock will launch. It is not an operating-system sandbox. The current alpha does not claim complete containment against a malicious allowed executable.

### Network

Network access is off by default. A trusted user may configure exact lowercase domains. The local broker supports bounded HTTPS `GET` and `HEAD`, public WebPKI, public IP destinations, no redirects, and exact approval per request. The model cannot extend the allowlist.

Mutating HTTP methods, private certificate authorities, enterprise proxy profiles, and arbitrary sockets are outside the current controlled-network profile.

### Deployment preflight

A separate runner performs read-only GitHub, ECR, and Kubernetes checks for a saved environment. The environment fixes repository, workflow, AWS account, registry, and Deployment identity. The runner owns bounded credentials and returns a signed receipt. It does not merge, build, push, or deploy.

### Kubernetes execution profile

The runtime contains a narrow profile for changing one container image in one existing Deployment. Its design binds the cluster route, namespace, Deployment name and UID, container identity, prior image, new immutable digest, `resourceVersion`, object projection, authorization, and admission request.

The repository includes the policy, state, broker, transport, executor, admission, and reconciliation components for this path. A successful live EKS mutation with complete mediation has not been demonstrated. The account-free exhibit constructs and revalidates the exact patch, consumes replay state, and returns `NotSent` without credentials or network I/O.

## Durable state and concurrency

The high-consequence runtime uses durable state to define linearization points for issuance, consumption, dispatch claims, physical-resource reservations, admission decisions, and terminal retirement. PostgreSQL migrations cover these lifecycles; the local desktop also uses a bounded durable ledger.

Two details matter:

1. **Stable claims, renewable acquisitions.** Recovery appends a higher acquisition generation instead of rewriting the original transaction claim.
2. **Canonical resource reservations.** Concurrent actions that resolve to the same protected physical resource cannot both hold an active reservation within the configured identity model.

The database and an external provider do not form one distributed transaction. AccordLock therefore records irreversible phases and retains reservations when the outcome cannot be established.

## Failure handling

The runtime distinguishes these cases:

- definitely not sent;
- authorized and acquired, but no provider request started;
- request transmission started and outcome is unknown;
- provider accepted an intermediate step, but persistence is unknown;
- exact effect observed;
- exact failure observed; and
- manual resolution required.

No timeout, HTTP status, process exit, or admission response alone proves that an external effect did not occur. Productive unknown outcomes are not blindly retried.

## Audit, privacy, and recovery

The trusted runtime stores complete records needed to validate and recover controlled actions. The desktop receives a redacted projection through a private control channel.

Audit pagination is bound to one durable ledger revision and protected by a domain-separated page digest. The renderer can display and export verified pages but cannot create or amend records. The public projection includes categorical task-check status and cryptographic commitments while excluding prompts, raw tool arguments, provider credentials, and raw evidence.

Audit integrity proves continuity of recorded objects under the stated trust assumptions. It does not prove that a user wrote a complete task, that an evidence source was truthful, or that an unobserved external effect did not occur.

## Remote approval architecture

Slack, Microsoft Teams, Telegram, and WhatsApp adapters share one approval-channel core. Provider callbacks terminate at a separately operated gateway. That gateway authenticates the provider event and emits a signed receipt bound to one pending action, task, channel, enrollment, challenge, event, and expiry. Replay state survives restart.

The desktop does not accept raw provider callbacks. Its local evaluation path imports signed fixtures. Live provider accounts, callback routing, Microsoft identity verification, and a private authenticated gateway-to-desktop transport remain deployment work.

## Assurance architecture

The repository uses complementary evidence:

- **Lean 4:** 81 theorems over abstract authorization, lifecycle, evidence, effect-knowledge, resource, and dispatch definitions.
- **TLA+:** eight bounded state-machine models for operational interleavings, replay, reservations, admission, control queues, and recovery.
- **AccordBench:** 73 reviewable cases covering request-to-action conformance, transaction lifecycle, shared resources, and safe autonomy.
- **Implementation tests:** Rust, TypeScript, Python, schema, migration, and adversarial tests across the runtime and desktop.

These artifacts establish selected properties at different abstraction levels. They do not establish an end-to-end refinement from the formal models to the complete implementation, validate third-party cryptography, or certify a deployed system.

## Deployment boundary

The current source supports local engineering, adversarial evaluation, and architecture review. Production use additionally requires signed distribution, isolated key custody, authenticated live evidence, complete credential mediation, hardened operating-system isolation, live provider acceptance tests, database operations, incident procedures, and independent security review.

See [Product Status](PRODUCT_STATUS.md), [Threat Model](THREAT_MODEL.md), and [Limitations](LIMITATIONS.md) for the exact release boundary.
