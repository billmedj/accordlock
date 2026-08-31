# Threat Model

**Release stage:** Engineering Alpha · **Applies to:** the public desktop, local runtime, preflight runner, and narrow Kubernetes execution profile · **Production status:** not production-ready

## Security objective

For a protected action, AccordLock aims to ensure that execution occurs only when all of the following remain true at the point of use:

- a trusted user or administrator approved the task authority;
- the exact tool request is inside that authority;
- required evidence is authentic, current, and admitted by policy;
- the active principal, policy, configuration, target state, and deadline still match;
- the authorization has not been consumed;
- required shared resources remain available; and
- a credential-holding executor constructs only the bound effect.

After an attempt, the system records what it can establish. Ambiguous outcomes remain explicit and cannot be converted into success or a safe retry by convenience.

This objective limits the effects of a compromised or mistaken planner. It does not make model output trustworthy.

## Claim level

This threat model describes implemented controls, deployment assumptions, and open risks. Most controls have local unit, integration, or adversarial tests. Some transaction properties are represented in Lean 4 definitions or bounded TLA+ models.

There is no end-to-end formal verification, production certification, independent security assessment, retained successful EKS deployment, or proof of complete mediation. A control marked as implemented locally is still subject to its operating-system, key-management, deployment, and external-service assumptions.

## Protected assets

- task authority and policy configuration;
- approval and execution authorization records;
- signing and verification keys;
- model-provider and deployment credentials;
- canonical workspace and protected file state;
- command and executable identity;
- network destination policy;
- GitHub, AWS, ECR, and Kubernetes environment identity;
- transaction, replay, reservation, and recovery state;
- evidence records and trust registries;
- execution observations and audit continuity; and
- operator decisions, including remote decision receipts.

## Security principals and trust zones

| Zone | Role | Trust assumption |
| --- | --- | --- |
| Human operator | defines the task and reviews exact actions | may make mistakes; explicit decisions are authoritative within configured scope |
| Enterprise administrator | configures policy, destinations, identities, keys, and deployment | trusted for the configured environment; compromise can invalidate the guarantee |
| Desktop renderer | presents product UI | untrusted for authority, credentials, and ledger mutation |
| Model and conversation content | proposes plans and tool calls | untrusted, including under prompt injection or hallucination |
| Protected agent backend | captures plan and normalizes proposals | trusted to route protected calls through the runtime; not allowed to self-authorize |
| Trusted desktop main process | selects workspace, starts sidecars, owns private control channels | part of the local trusted computing base |
| AccordLock runtime | evaluates policy, consumes authorizations, records state | trusted implementation boundary |
| Credential-holding executor | constructs and sends one bounded effect | must be isolated from the model and alternate callers |
| Evidence source | supplies typed facts | trusted only for activated scope, key, freshness, provenance, and policy |
| Durable state service | provides replay, lifecycle, reservation, and audit state | must preserve integrity, monotonicity, and availability assumptions |
| Operating system and credential vault | isolates processes, files, and secrets | trusted in the local alpha; host compromise is out of scope |
| Cloud and Kubernetes control planes | accept effects and expose observations | external systems whose identity and responses must be authenticated |

## Adversaries considered

### Hostile content presented to the model

A repository, document, webpage, tool result, or message can contain instructions that attempt to override the task, request secrets, expand network access, or trigger a destructive tool.

AccordLock treats the resulting tool proposal as untrusted. The content cannot alter the task contract, domain allowlist, authority epochs, evidence registry, trusted clock, authorization state, or credential-holding executor through the model protocol.

### Incorrect or hallucinated agent behavior

The agent can invent a file, command, URL, deployment identity, or claim of success. Exact schemas, canonicalization, current-state checks, evidence requirements, and observed-result records constrain protected effects. A fabricated statement is not execution authority or provider evidence.

The system cannot guarantee that every allowed edit is useful or semantically correct. That depends on task quality and qualified evidence, both of which have explicit limitations in the current alpha.

### Malicious or compromised renderer

Renderer code may attempt to forge approval, change the selected workspace, access keys, submit a remote-provider callback, or alter audit history. Authority and credentials remain in the main process or runtime. Approval surfaces and native file pickers cross a trusted main-process boundary. The renderer receives redacted audit projections.

The current design still trusts Electron, its main process, and the host operating system. A complete renderer-escape assessment has not been performed.

### Replay and substitution attacker

An attacker may reuse an approval, authorization, provider event, admission identifier, or stale request; replace arguments or target state; or route an action to a different resource. The design uses canonical commitments, short validity windows, unique identifiers, authority epochs, target-state commitments, and durable replay stores.

### Network attacker

An attacker may redirect traffic, substitute a certificate, replay a callback, or exploit ambiguous transport outcomes. The controlled HTTPS profile uses public WebPKI, public-IP resolution, exact domains, no redirects, bounded responses, and no automatic mutation retry. Cloud paths require rooted destination identities and authenticated observations.

Live enterprise proxies, private certificate authorities, messaging callbacks, and EKS transport have not completed production acceptance testing.

### Compromised evidence source

An activated evidence source may lie while producing structurally valid signed data. AccordLock verifies identity, scope, freshness, commitments, and policy admission; it does not establish the truth of a source that remains trusted by configuration. Independent or diverse evidence policies are a deployment responsibility.

### Concurrent or failed workers

Two workers may race for one resource, a worker may crash after an irreversible step, or a response may be lost. Durable claims, generation-fenced acquisitions, canonical physical-resource reservations, irreversible phases, and explicit unknown outcomes address the safety side of these failures.

Availability and automatic resolution are not guaranteed.

## Threats and controls

| Threat | Current control | Current evidence | Remaining risk |
| --- | --- | --- | --- |
| Prompt injection causes a protected call | model proposal has no authority; task policy, required approval, applicable evidence, and current state are evaluated independently | local desktop/runtime tests and adversarial cases | an action already authorized by an overly broad task can still be harmful |
| Hallucinated target or success | canonical target checks; typed provider responses; separate execution observation | local runtime tests and no-send Kubernetes exhibit | real-provider observation path is not fully deployed |
| Tool request changes after review | plan, tool identity, arguments, target context, and evaluation commitment are repeated in exact authorization | Lean abstract properties and implementation tests | no complete proof that every adapter preserves canonical encoding |
| Approval replay | short-lived decision bound to one pending action; durable single-use consumption | local tests | live remote gateway and multi-device behavior are unproved |
| Authorization replay | unique authorization identifier, atomic consumption, replay tombstone | Lean abstract properties, Rust tests, PostgreSQL tests | live failover and rollback resistance need deployment validation |
| Stale policy or target state | policy/configuration epochs and target-state commitments are rechecked | Lean abstract properties and implementation tests | external state can change after the last check; destination enforcement must close the window |
| Direct credential use by the model | credentials stay in OS vault, preflight runner, broker, or executor | local process and protocol tests | complete process isolation and production credential exclusivity are not proved |
| Shell injection | process broker uses direct executable and argument vectors; shell interpreters are not accepted in the controlled profile | local tests | an allowed executable may itself interpret dangerous input; no full OS sandbox |
| Filesystem escape | canonical workspace checks, protected paths, exact file operation | local tests | symlink, filesystem, antivirus, and host-specific behavior require broader platform review |
| Network scope expansion | network off by default; exact trusted allowlist; GET/HEAD only; redirects disabled | local tests | no live enterprise-network acceptance, proxy profile, or arbitrary protocol isolation |
| Forged external evidence | signed, purpose-separated, challenge-bound response with freshness and trust-root checks | local cryptographic and substitution tests | provider truth, key custody, calibration, and live transport remain assumptions |
| Concurrent effects on one resource | durable canonical reservation and fenced acquisitions | PostgreSQL tests and bounded models | external aliases not represented in the rooted registry can defeat identity assumptions |
| Lost response triggers duplicate effect | no automatic mutation retry; unknown outcome retained for reconciliation | Lean/TLA+ properties and local failure tests | manual resolution may hold a resource indefinitely |
| Kubernetes admission bypass | intended fail-closed admission plus exclusive executor identity | local admission implementation and tests | cluster administrator, alternate credentials, caller-origin proof, and live complete mediation remain blockers |
| Audit tampering in renderer | runtime-owned ledger; revision-bound, digest-checked redacted pages | desktop/runtime tests | host or runtime compromise remains in scope of trusted computing base |
| Malicious remote decision | authenticated provider event, signed exact receipt, durable event replay protection | local contracts and fixture tests | no bundled live gateway; Microsoft identity verification and callback deployment pending |
| Signing-key misuse | purpose-separated keys and scoped verification profiles | local implementation | isolated KMS/HSM custody and anti-backdating policy are absent |
| Supply-chain compromise | locked dependencies, pinned toolchains and actions, publication guard, source manifest, SBOM scripts | repository checks | signed reproducible release and independent provenance verification pending |

## Prompt-injection claim boundary

AccordLock does not claim prompt-injection immunity. It does not guarantee that a model will ignore hostile text, preserve its plan, or produce a correct answer.

The defensible claim is narrower: hostile text processed by the model does not, by itself, create task authority, change trusted configuration, mint approval, issue execution authority, or supply a credential. A protected effect still has to pass the independent runtime and exact execution path.

This is containment at the execution boundary. Its strength depends on complete mediation. Any unbrokered tool, alternate credential, overbroad task, compromised administrator, or bypass route falls outside that guarantee.

## Hallucination claim boundary

AccordLock separates statements from effects. A model can claim that a command ran or a deployment succeeded; the ledger records only trusted execution and observation events. A model can invent an identifier; rooted configuration and current-state checks must resolve it before protected execution.

The alpha does not yet provide qualified natural-language evidence for general task correctness. The UI must therefore distinguish **Within approved access**, **Reviewed**, **Not verified**, and **Blocked** rather than implying that an allowed action is correct.

## Residual production blockers

- complete mediation of every protected effect and removal of alternate credential paths;
- hardened separation between model, renderer, runtime, executor, and secrets;
- production key custody and purpose-restricted signing;
- authenticated live evidence connectors and independently reviewed trust policy;
- qualified evidence for general task conformance, with measured abstention and error rates;
- successful retained kind and EKS compositions from the release revision;
- proof of Kubernetes API-server caller origin and practical bypass resistance;
- live PostgreSQL role separation, replication, backup, restore, and disaster recovery;
- live messaging gateway, callback authentication, private receipt transport, and provider acceptance;
- signed installer, update, rollback, and uninstall validation on clean systems;
- fault injection across crash, timeout, partition, clock, state drift, and failover boundaries; and
- independent security review.

## Explicit non-goals for this release

- defending a fully compromised host, cluster control plane, or trusted administrator;
- guaranteeing availability when safety-critical state is unavailable;
- proving the truth of a configured evidence source that has been compromised;
- making PostgreSQL and an external provider one atomic transaction;
- authorizing arbitrary Kubernetes mutations;
- replacing IAM, RBAC, admission control, software-supply-chain attestations, or policy engines;
- guaranteeing the completeness of a human task description;
- certifying legal or regulatory compliance; and
- claiming end-to-end formal verification.

## Security review rule

Any change to canonical encoding, task authority, evidence admission, signing, replay state, transaction phase, credential custody, provider transport, observation, recovery, or audit projection changes this threat model. Such a change should include adversarial tests and an explicit update to the affected assumption or residual risk.

See [Architecture](ARCHITECTURE.md), [Product Status](PRODUCT_STATUS.md), and [Limitations](LIMITATIONS.md).
