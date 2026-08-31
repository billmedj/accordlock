# Engineering Case Study: A Transaction Boundary for Autonomous Agents

**Project:** AccordLock · **Stage:** Engineering Alpha · **Scope:** public desktop, runtime, assurance artifacts, and cloud-execution profile

## Executive summary

Agent systems are usually strongest at planning and weakest at the moment a plan becomes an external effect. A model can be authorized to use a tool while still proposing the wrong action, acting on stale state, following hostile content, exceeding a shared limit, or retrying an effect whose outcome is unknown.

AccordLock explores a systems answer: treat each consequential tool call as a transaction. The model produces an untrusted proposal. A separate runtime binds that proposal to approved human intent, current authority, current target state, admitted evidence, resource availability, and a one-time execution authorization. A broker owns credentials and constructs the effect. The result closes a durable lineage or remains explicitly unknown.

The repository carries that idea across a real desktop agent, a Rust enforcement runtime, controlled filesystem/process/network paths, remote-approval protocols, cloud preflight, a narrow Kubernetes profile, durable SQL state, formal models, and an adversarial evaluation corpus.

The result is a functional engineering alpha with an unusually explicit claim boundary. It is ready for inspection and local evaluation. It is not ready to authorize production infrastructure.

## The engineering problem

Traditional access control answers whether a principal may perform a class of action on a resource. Agent execution adds several questions that ordinary permission checks may not answer:

- Did this exact action preserve the reviewed task and its constraints?
- Is the action still valid under the current policy and configuration?
- Did the target change after the plan was reviewed?
- Is the artifact the one produced by the approved build?
- Is another transaction already consuming the same physical resource?
- Did a previous attempt fail, succeed, or lose its response?
- Can the model reach the effect through a path that bypasses the decision?

These are transaction and provenance problems as much as model-behavior problems. Solving them solely in a system prompt leaves the final authority inside the component most exposed to untrusted content.

## Product thesis

The central design decision is to demote the model from actor to planner.

The model may select a tool and construct candidate arguments. The runtime independently decides whether that proposal can become executable. Trusted configuration, task authority, evidence policy, time, replay state, resource state, and credentials remain outside the model protocol.

This creates a practical form of bounded autonomy:

- routine actions can proceed automatically when the task contract and any applicable evidence policy permit them;
- consequential actions pause on the exact effect rather than the entire session;
- actions outside the task are denied rather than upgraded in place; and
- failures preserve enough state for safe reconciliation.

The product value is the ability to delegate more work without granting broad, reusable authority to a probabilistic planner.

## Design constraints

The system was developed under several hard constraints.

### Exactness

Approving “edit the repository” or “deploy the service” is too coarse for high-consequence execution. Authorization needs the normalized tool, arguments, target, preconditions, policy context, and lifetime of one request.

### Currentness

A correct decision can become unsafe after a policy, key, configuration, artifact, or target-state change. The system rechecks current authority at multiple irreversible points rather than relying on one early approval.

### No authority from evidence

An evaluator, model, or attestation can support or restrict a decision. It cannot manufacture access absent from the task policy. This prevents a favorable score from becoming a capability escalation.

### Conservative uncertainty

Missing evidence produces review. Contradiction blocks dispatch. An ambiguous external effect remains unknown. These states cannot be silently converted to allow or safe retry.

### Reviewable implementation

Security claims need inspectable schemas, state transitions, reason codes, tests, and formal artifacts. Hidden heuristics and scalar confidence scores are insufficient for the authorization boundary.

### Usable control

Safety that pauses on every harmless read will be disabled. The product separates automatic work inside a fixed task from exact approvals at meaningful boundaries, then presents technical detail progressively.

## Architecture decisions

### 1. Fixed task contract

A task binds a plain-English objective to a canonical workspace, session, run, capability set, protected paths, and expiry. The model cannot extend that contract during the task. Broader access requires a separately reviewed task.

This choice makes the approval surface comprehensible while giving the runtime stable inputs for every later decision.

### 2. Actual plan capture

The agent backend records a bounded checkpoint from the assistant turn before dispatch. It commits visible assistant text and ordered tool requests, including request identifiers, tool names, and argument digests. Hidden reasoning and transport metadata are excluded.

The selected tool request must appear exactly once and match the normalized proposal. This prevents a detached summary from standing in for the plan that produced the action.

### 3. Typed conformance records

The runtime creates a pre-execution request-plan-action record and, after execution, a complete request-plan-action-result record. Evidence responses are authenticated, context-bound, fresh, and re-evaluated from their source records before authorization.

Evidence aggregation is monotone toward restriction. Support preserves the baseline policy decision, uncertainty requires review, and a qualified contradiction denies. The same model may contribute evidence, but self-review receives no privileged status.

The connected free-text path has no qualified production evidence. It records abstention rather than displaying a misleading success state. That categorical projection is currently separate from structural access, so bounded reads inside the approved task may still run automatically.

### 4. Exact, single-use execution authority

The runtime issues a short-lived authorization that repeats the request's security-relevant commitments. Consumption is atomic and leaves replay state. An action with changed arguments, target state, authority epoch, evaluation record, or deadline cannot reuse the authorization.

This design converts approval from a reusable permission into a one-time transaction input.

### 5. Credential-holding broker

The model and renderer do not receive production execution credentials. A dedicated component owns the credential and accepts a constrained, typed operation. For local tools, the runtime executes the exact file, process, or HTTPS request. For cloud paths, dedicated connectors and executors reduce candidate inputs to fixed identifiers and routes.

The architecture still needs a deployed proof of complete mediation. The code treats that as a release gate rather than assuming that protocol design alone creates isolation.

### 6. Durable state before irreversible work

PostgreSQL state defines commits for issuance, consumption, dispatch claims, resource reservation, worker acquisition, admission, observation, and retirement. Recovery appends new acquisition generations while preserving the original claim.

This matters when workers crash or responses disappear. The system can distinguish work that was never sent from work whose outcome is unresolved. It refuses blind mutation retries.

### 7. Canonical physical-resource reservation

Logical aliases can refer to one real object. AccordLock derives a physical-resource identity from rooted configuration and the authorized object's immutable identity, then allows one active reservation for that resource.

The mechanism addresses races between independently valid tasks. Its guarantee depends on truthful destination registration and complete alias coverage.

### 8. Destination-side enforcement

The Kubernetes profile includes a state-backed validating admission path. Its intended role is to reject protected mutations without an active exact transaction, even if a caller has the relevant Kubernetes verb.

This closes a gap between upstream approval and the final admitted object. It also introduces demanding deployment assumptions: API-server caller origin, webhook availability, RBAC closure, administrator bypass, credential exclusivity, and post-state observation. Those assumptions remain explicit production blockers.

### 9. Separate authorization from effect knowledge

Authorization answers whether an attempt may start. Observation answers what happened. A complete trace links them without allowing a post-execution result to retroactively justify the attempt.

This separation is essential for network failure, process interruption, webhook response loss, and provider-side ambiguity.

## Product implementation

### Desktop experience

The desktop is derived from Goose and adds a native project and task flow, fixed-access review, exact approval sheets, an Approval Center, activity history, export, supported file recovery, connection settings, and deployment preflight.

The security model is kept out of the normal interaction until a decision is needed. Primary states use plain language. Protocol identities, commitments, evidence provenance, and reason identifiers remain available in expandable details and exports.

### Controlled local tools

- Filesystem reads can run automatically inside the approved workspace.
- Changes and destructive operations receive one-time authorization.
- Process execution uses allowed executable identities and direct argument vectors; no shell interpreter is accepted by the controlled profile.
- HTTPS is off by default and limited to trusted exact domains, `GET`/`HEAD`, public WebPKI, public IPs, no redirects, bounded responses, and exact approval.

The process broker is deliberately described as controlled execution rather than a sandbox.

### Audit and recovery

The runtime owns a durable ledger. The renderer receives redacted, digest-checked pages bound to one revision. Completed records expose exact lineage commitments and categorical task-check evidence without exposing prompts, raw arguments, credentials, or raw evidence.

Supported deletions move data to recovery storage. Restore requires a fresh challenge bound to the original execution record.

### Remote decisions

Slack, Microsoft Teams, Telegram, and WhatsApp share signed challenge and receipt contracts. A separate gateway authenticates provider callbacks. The desktop accepts only a signed receipt for one pending action and still resolves it through the trusted exact-approval path.

The local implementation includes adapters, secure storage, queue behavior, replay protection, enrollment, and deterministic fixtures. A live gateway is not bundled.

### Deployment preflight

The preflight runner owns bounded credentials and performs read-only checks across a fixed GitHub repository and workflow, AWS account and ECR repository, and Kubernetes Deployment. It produces a signed, independently verifiable receipt and states that no deployment occurred.

This provides useful product behavior before the mutation path is ready for production authority.

## Assurance strategy

No single validation method covers the system. AccordLock uses several layers.

### Lean 4

Eighty-one theorems cover abstract properties for exact authorization bindings, no authority amplification, single-use grants, transaction ordering, restrict-only evidence, abstention, unknown outcomes, resource composition, and final dispatch conditions.

### TLA+

Eight models explore bounded interleavings for authorization lifecycle, dispatch claims, resource reservation, admission, broker journaling, terminal retirement, control queues, and durable acquisitions.

### AccordBench

The deterministic 73-case corpus covers request-to-action conformance, replay and crash behavior, shared resources, and safe autonomy. Metamorphic relations check that harmless rewrites preserve outcomes and meaningful changes alter them.

### Implementation tests

Rust, TypeScript, Python, SQL, schema, and integration tests exercise malformed inputs, stale state, replay, substitution, concurrency, timeouts, unknown effects, process descendants, audit integrity, remote receipts, and provider boundaries.

The assurance package is intentionally explicit about gaps. A theorem about an abstract transition does not certify its database adapter. A fixture-oracle score validates the benchmark runner, not product performance. A successful local test does not establish live provider identity.

## Difficult problems uncovered

### Semantic evidence without unsafe confidence

Recording request-plan-action-result continuity is tractable. Establishing that an action preserves human meaning is a separate problem. The design therefore uses categorical evidence, provenance, calibration requirements, and abstention. It refuses to turn an empty evidence set into a score.

### Unknown outcomes

Exactly-once external effects are usually unavailable across process, database, and provider boundaries. The project models effect knowledge directly and reserves the resource until authenticated reconciliation can close it.

### Usability under least privilege

Per-call security can become unworkable. The product response is a fixed task contract, automatic bounded reads, exact approvals for consequential effects, concise decision copy, remote notification, and a searchable audit timeline. Representative user testing remains necessary.

### Proof-to-code correspondence

Formal models are valuable only when their claim boundary and implementation correspondence remain visible. The repository is moving toward a machine-readable map from public claims to definitions, theorems, models, code, and tests.

## Evidence produced so far

- provider-free runtime execution chain with explicit `production_ready: false`;
- the complete Rust workspace test command passed after monorepo assembly on 2026-08-31; tests that explicitly require a disposable PostgreSQL service remained skipped;
- desktop test, type, lint, formatting, and publication checks were green on the imported desktop snapshot before assembly and remain a clean-checkout public release gate;
- local PostgreSQL transaction and TLS profiles;
- 81 Lean theorem declarations built with a pinned toolchain and no placeholders or declared axioms;
- bounded TLA+ runs recorded for the canonical local configurations;
- 73 validated AccordBench fixtures;
- account-free Kubernetes patch construction and replay rejection with `NotSent`; and
- a partial kind run that reached a Ready control plane but did not complete the protected mutation exhibit.

These results support the Engineering Alpha label. They do not support a production claim.

## Engineering lessons

1. Model alignment and execution integrity are different layers. Both matter, and each needs its own evidence.
2. Permission should name the exact effect whenever the consequence is material.
3. Evidence should never expand authority.
4. Unknown external effects deserve a first-class state.
5. Recovery logic belongs in the initial transaction design.
6. Physical identity matters when logical aliases compete for one resource.
7. A polished approval surface is part of the security boundary.
8. Formal methods are strongest when paired with adversarial executable tests and honest non-claims.

## Next engineering milestones

The shortest path to a credible public release is:

1. complete the clean monorepo, root validation, claim map, and provider-free adversarial demo;
2. reproduce every local gate from a fresh checkout;
3. retain one successful disposable kind composition;
4. harden an isolated runner and eliminate bypass paths;
5. validate GitHub, AWS, ECR, EKS, and messaging integrations with scoped test accounts;
6. publish measured system results on AccordBench and representative workflows;
7. ship signed, clean-machine-tested desktop artifacts; and
8. complete an independent security review before production use.

## Why the work matters

Frontier-agent capability is advancing faster than organizations can safely delegate consequential work. The limiting factor is increasingly the execution substrate around the model: authority, evidence, isolation, recovery, evaluation, and operator control.

AccordLock is a concrete exploration of that substrate. Its strongest contribution is not a claim that agents stop making mistakes. It is an architecture in which a mistaken proposal does not automatically become an authorized effect, and every accepted effect carries a reviewable transaction history.

See [Architecture](ARCHITECTURE.md), [Threat Model](THREAT_MODEL.md), [Product Status](PRODUCT_STATUS.md), and [Research Provenance](RESEARCH_PROVENANCE.md).
