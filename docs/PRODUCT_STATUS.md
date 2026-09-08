# Product status

Engineering alpha for local evaluation, not a production security boundary.
Validation snapshot: 2026-08-31. Status details last updated: 2026-09-02.

## Available locally

The desktop and Rust runtime can be built from source. The features below
have local implementations and tests; this does not establish compatibility
with live providers. See the [local validation record](LOCAL_VALIDATION.md).

| Area | Available | Limits |
| --- | --- | --- |
| Desktop | Projects, tasks, providers, approvals, activity, recovery, saved deployment environments | Broader UX testing and release-package validation remain |
| Task policy | Fixed objective, workspace, capabilities, protected paths, expiry | Workspace selection must remain in the trusted main process |
| Models | Desktop provider connections and inherited local-inference paths | Compatibility varies; no model is bundled; model output remains untrusted |
| File operations | Bounded reads, action-bound edits, writes, deletion and restore | Reads stay inside the approved canonical workspace and policy; destructive operations need single-use authorization |
| File recovery | Restore supported operations recorded by the runtime | Cannot recover unrecorded operations or undo arbitrary external actions |
| Process broker | Approved programs with single-use authorization | Disabled by default; not an OS sandbox |
| HTTPS broker | Exact configured public domains, `GET`/`HEAD`, public WebPKI, no redirects | Enterprise-network acceptance remains |
| Execution grants | Short-lived, single-use authority consumed before dispatch | Production process isolation and failover validation remain |
| Audit and export | Durable records; redacted exports bound to a revision and checked by digest | Does not protect against host compromise |
| Task-check records | Request-plan-action-result lineage and artifact digest verification | Establishes record continuity and byte identity, not human intent or semantic correctness |

The evidence engine abstains on general free-text checks because it has no
qualified production evidence provider. Approval does not prove that a model
understood the task. Filesystem behavior still needs platform hardening.

Native [Effect Transaction Protocol (ETP)](https://github.com/billmedj/etp)
mediation is planned, not implemented.

## Cloud and remote approvals

The preflight runner uses read-only GitHub, ECR and Kubernetes adapters and
produces signed receipts. Preflight never deploys. These adapters still need
retained acceptance results from authenticated accounts and clusters.

The repository also contains:

- A GitHub Actions evidence producer, pending protected-workflow and
  real-repository acceptance.
- A credential-free worker protocol. A production remote runner and hardened
  transport are not deployed.
- Components for changing one container image in one Kubernetes Deployment.
  There is no retained successful end-to-end EKS mutation or complete-mediation
  proof. The account-free exhibit validates a patch and returns `NotSent`
  without credentials or network I/O.
- Disposable kind scripts and tests. A developer reported a Ready control plane
  before repository assembly; no complete post-assembly run has been retained.
- PostgreSQL transaction, replay, reservation, admission and recovery state.
  An earlier component run was reported; post-assembly reproduction and
  production database operations remain.

Slack, Microsoft Teams, Telegram and WhatsApp have local approval-protocol
foundations. They are not live integrations: no public callback gateway or
private gateway-to-desktop transport is bundled. Provider-account acceptance,
including Microsoft identity verification, remains. Remote decisions pass
through the same action-bound resolver as the desktop Approval Center.

## Tests and formal models

- [Lean](../runtime/formal/README.md): 81 theorems over abstract authorization,
  state bindings, authority limits, single-use execution, ordering, evidence,
  unknown outcomes, resource composition and dispatch.
- [TLA+ models](ARCHITECTURE.md#assurance-architecture): eight bounded
  models covering issuance, consumption, dispatch, reservations, admission,
  broker journals, queues, recovery and terminal retirement.
- [AccordBench](../runtime/benchmarks/accordbench/README.md): 73 deterministic
  cases: 43 request-to-action, 10 transaction-lifecycle, 10 shared-resource and
  10 safe-autonomy cases. The included oracle output checks the scoring pipeline,
  not AccordLock performance.

The formal models do not prove that the Rust, TypeScript, database, OS or cloud
implementation follows those models. Bounded exploration and fixtures do not
establish production reliability or field performance.

## What you can evaluate

Without a model API key or cloud account, you can run the
[provider-free demo](../demos/README.md), runtime tests, schema and evidence-engine
checks, AccordBench, Lean audits, bounded TLA+ checks and desktop development
builds. Use the pinned tools. PostgreSQL tests need a disposable database;
the kind composition needs Docker. The Kubernetes no-send exhibit needs neither
cloud credentials nor provider access.

Use disposable, non-sensitive data for integration prototypes and design-partner
evaluation. Do not grant production authority or rely on the alpha for
irreplaceable audit records.

Live validation needs controlled GitHub, AWS and messaging test accounts, a
Kubernetes or EKS target with scoped RBAC and admission rules, and an
authenticated approval gateway. Key custody and workload identity must also be
tested in that environment.

## Release work remaining

There is no public signed Windows installer or signed and notarized macOS
artifact. Local Windows package-integrity checks and macOS packaging source
exist. Clean-machine installation, update, uninstall and recovery tests remain.
An independent security review has not been performed.

A source alpha should pass clean-checkout code, documentation, formal
traceability, publication-hygiene and provider-free demo checks. It does not
establish production readiness, which also requires:

1. Complete mediation, isolated credential custody, authenticated evidence and
   destination activation.
2. Retained Kubernetes/EKS end-to-end runs and live messaging/gateway acceptance.
3. Crash, timeout, partition, replay, stale-state and failover tests.
4. Production database roles, TLS, high availability, backup, restore and
   disaster-recovery exercises.
5. Signed, verified Windows and macOS distribution.
6. Representative workflow measurements for latency, safe completion, false
   refusals and review burden.
7. Incident, continuity and emergency-access procedures, plus independent
   security review and remediation.

See [Architecture](ARCHITECTURE.md), [Threat Model](THREAT_MODEL.md) and
[Limitations](LIMITATIONS.md) for the enforcement boundaries and remaining tests.
