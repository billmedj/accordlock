# Product Status

**Current stage:** Engineering Alpha / Technical Preview | **Validation
snapshot:** 2026-08-31 | **Document revised:** 2026-09-02 | **Production-ready:**
no

## What exists today

AccordLock is a functional source product, not a design mockup. The monorepo contains:

- a desktop agent derived from Goose, with projects, tasks, provider configuration, approvals, activity, recovery, and deployment-preflight surfaces;
- an independent Rust runtime for task policy, exact approvals, single-use execution authorization, controlled execution, audit, and recovery;
- controlled filesystem, direct-process, and bounded HTTPS paths;
- a read-only GitHub-ECR-Kubernetes preflight runner;
- the components for a narrow, transactionally authorized Kubernetes image-update path;
- remote-approval protocol foundations for Slack, Microsoft Teams, Telegram, and WhatsApp;
- typed request-plan-action-result conformance records and a provider-independent evidence engine;
- PostgreSQL lifecycle, replay, reservation, admission, and recovery state;
- Lean 4 proofs over an abstract authorization model;
- eight bounded TLA+ state-machine models; and
- AccordBench, a 73-case deterministic evaluation corpus.

The product can be built and evaluated locally. It must not yet be used as a production security boundary.

## Maturity vocabulary

The status labels below have strict meanings.

| Label | Meaning |
| --- | --- |
| Implemented locally | source and automated tests exist in the repository |
| Composed locally | the relevant components have run together on a developer workstation |
| Live-proven | a retained run exercised the boundary against the named external system |
| Independently reviewed | an external reviewer assessed the implementation and deployment evidence |
| Production-ready | documented release, operational, security, and acceptance criteria are complete |

An implementation can be substantial without being live-proven. A passing fixture cannot stand in for an authenticated provider run.

## Capability matrix

| Capability | Current status | Important boundary |
| --- | --- | --- |
| Desktop projects and tasks | Implemented locally | release UX still needs broader user testing |
| Fixed objective, workspace, capabilities, protected paths, and expiry | Implemented locally | depends on trusted main-process workspace selection |
| Model-provider connection | Implemented through the desktop provider layer | provider compatibility varies; provider output remains untrusted |
| Local model support | Present through the inherited local-inference paths | no local model is bundled as a security dependency or quality guarantee |
| Automatic bounded file reads | Implemented locally | only inside approved canonical workspace and policy |
| Exact file edits, writes, deletion, and restore | Implemented locally | destructive operations require one-time authorization; platform hardening continues |
| Direct process execution | Implemented locally | disabled by default; explicit programs and one-time approval; not an OS sandbox |
| Controlled HTTPS | Implemented locally | exact trusted domains, GET/HEAD only, public WebPKI, no redirects; live enterprise-network acceptance pending |
| Task policy and exact approval | Implemented locally | approval does not prove semantic correctness |
| Short-lived, single-use execution authorization | Implemented locally | production process isolation and failover validation pending |
| Durable audit and export | Implemented locally | redacted projection is revision-bound and digest-checked; host compromise remains out of scope |
| Deletion recovery | Implemented for supported file operations | recovery applies only when the runtime recorded the original protected operation |
| Request-plan-action-result lineage | Implemented locally | proves object continuity under the runtime's inputs, not preservation of human meaning |
| Evidence engine | Implemented locally | general live free-text path has no qualified production evidence provider and therefore abstains |
| Exact artifact verification | Implemented locally | proves configured byte identity, not semantic validity |
| Slack approval protocol | Implemented locally | no bundled live callback gateway or provider-account acceptance result |
| Microsoft Teams approval protocol | Implemented locally | live Microsoft identity verification and gateway deployment pending |
| Telegram approval protocol | Implemented locally | live provider-account and callback acceptance pending |
| WhatsApp approval protocol | Implemented locally | live provider-account and callback acceptance pending |
| Approval Center | Implemented locally | remote decisions still pass through the same exact trusted resolver |
| Saved deployment environments | Implemented locally | release packaging and real-account validation pending |
| Read-only GitHub adapter | Implemented locally | authenticated real-account acceptance evidence pending |
| Read-only ECR adapter | Implemented locally | authenticated real-account acceptance evidence pending |
| Read-only Kubernetes adapter | Implemented locally | authenticated real-cluster acceptance evidence pending |
| Signed deployment-preflight receipt | Implemented locally | preflight never performs a deployment |
| GitHub Actions evidence producer | Implemented locally | protected workflow and real-repository acceptance still need retained evidence |
| Credential-free worker protocol | Implemented locally | production remote runner service and hardened transport are not deployed |
| Narrow Kubernetes image-update profile | Components implemented locally | no retained successful end-to-end EKS mutation or complete mediation proof |
| Account-free Kubernetes no-send exhibit | Implemented locally | constructs and validates the patch, obtains no credential, performs no network I/O |
| Disposable kind profile | Scripts and tests present; a pre-assembly developer run reported a Ready control plane | no retained post-assembly run or complete evidence package |
| PostgreSQL transaction state | Source and tests present; an earlier component run was reported | post-assembly reproduction, production roles, HA, backup, restore, and disaster recovery pending |
| Lean assurance core | 81 abstract theorems, pinned toolchain | no implementation refinement proof or end-to-end verification |
| TLA+ models | eight bounded models | bounded exploration is not a proof of unmodeled code or deployment behavior |
| AccordBench | 73 reviewable cases | fixture coverage is not a representative field-performance estimate |
| Windows development package | local package-integrity path exists | current public installer is not signed or released |
| macOS packaging path | source path exists | no public signed and notarized release artifact |
| Independent security review | Not performed | required before production positioning |

## What can be evaluated without an account

A reviewer can inspect and run substantial portions of the system without a model API key, cloud account, or paid service:

- the provider-free runtime demo;
- policy, authorization, replay, audit, and recovery tests;
- the request-plan-action-result schemas and evidence engine;
- AccordBench and its fixture validator;
- Lean builds and theorem audit;
- bounded TLA+ models after obtaining the pinned tool;
- PostgreSQL integration profiles on a disposable local database;
- the account-free Kubernetes no-send exhibit; and
- desktop source checks and development builds.

The disposable kind composition also needs a working Docker engine. It remains account-free.

## What requires external systems

The next evidence tier requires controlled test accounts or infrastructure:

- a GitHub repository with protected workflow and review settings;
- an AWS account with scoped ECR and EKS test resources;
- a disposable Kubernetes or EKS target with the intended admission and RBAC configuration;
- Slack, Microsoft Teams, Telegram, and WhatsApp test applications or accounts;
- a reachable approval gateway with authenticated callback and private desktop transport;
- production-style key custody and workload identity;
- a clean Windows system for install, update, uninstall, and recovery tests;
- a macOS signing and notarization environment; and
- independent security reviewers.

## Assurance evidence

### Machine-checked abstract properties

The Lean project checks 81 theorems covering exact authority and state bindings, no authority amplification, one-time execution, transaction ordering, restrict-only evidence, unknown-effect handling, resource composition, and an abstract final dispatch condition.

These are theorems about the definitions in the Lean project. The repository does not claim that the full Rust, TypeScript, database, operating-system, or cloud implementation has been proved to refine those definitions.

### Bounded state exploration

Eight TLA+ models cover issuance, consumption, dispatch, physical-resource reservation, admission, broker journaling, control queues, recovery, and terminal retirement. Their checked configurations explore bounded state spaces. Larger bounds and live failure injection remain separate obligations.

### Deterministic evaluation corpus

AccordBench contains:

- 43 request-to-action conformance cases;
- 10 transaction-lifecycle cases;
- 10 shared-resource cases; and
- 10 safe-autonomy cases.

The included oracle output verifies the scoring pipeline. It is not an AccordLock performance result.

## Current safe use

Appropriate uses of this release are:

- source review;
- local engineering and adversarial testing;
- formal-model inspection;
- controlled demonstrations with non-sensitive disposable data;
- integration prototyping; and
- design-partner evaluation without production authority.

Inappropriate uses include authorizing production infrastructure, storing irreplaceable audit data, relying on the unsigned development package, or treating the task-check projection as a guarantee of intent preservation.

## Technical-preview exit criteria

Before a public source alpha is tagged, the monorepo should pass reproducible root-level checks for code, documentation, formal traceability, publication hygiene, and provider-free demonstrations from a clean checkout. The source tag should state its exact limitations and contain no production installer claim.

## Production-readiness gates

Production positioning requires all of the following classes of evidence:

1. complete mediation and isolated credential custody;
2. authenticated live evidence and destination activation;
3. successful retained Kubernetes and EKS end-to-end runs;
4. crash, timeout, partition, replay, stale-state, and failover testing;
5. production database roles, TLS, backup, restore, and recovery exercises;
6. signed and verified Windows and macOS distribution;
7. live messaging-provider and gateway acceptance;
8. measured latency, safe completion, false refusal, and review burden on representative workflows;
9. documented incident, continuity, and emergency-access procedures; and
10. independent security review with remediation.

See [Architecture](ARCHITECTURE.md), [Threat Model](THREAT_MODEL.md), and [Limitations](LIMITATIONS.md).
