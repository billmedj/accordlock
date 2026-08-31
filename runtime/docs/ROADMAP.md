# AccordLock roadmap

**Last reviewed:** 2026-08-30

This roadmap is organized by evidence gates. The cloud profile
remains intentionally narrow: authorize one exact image update to one existing
Kubernetes Deployment. The local desktop profile separately mediates bounded
agent file and command actions; it does not widen the cloud authorization.

## Current evidence boundary

The repository currently implements:

- durable PostgreSQL replay and lifecycle state through migration `0014`;
- rooted EKS destination ownership and durable physical-resource reservation;
- exact terminal retirement and conservative no-send recovery;
- server-selected, append-only dispatch acquisitions;
- a native EKS credential broker, pinned TLS transport, and one-shot executor;
- state-backed admission plus a bounded HTTPS webhook composition root;
- an authenticated TLS PostgreSQL profile;
- a bounded local agent runtime with durable activity records, recovery
  evidence, and revision-consistent audit export;
- an exact-domain HTTPS execution broker with a direct public-WebPKI,
  public-IP-only, redirects-disabled and response-bounded native transport.
  Desktop can provision exact lowercase domains through its trusted main
  process and mounts only atomic, approval-controlled GET and HEAD requests;
- actual assistant-turn plan capture plus typed pre-execution and complete-trace
  bundles that are rebuilt, revalidated, and persisted around each action;
- typed pre-execution and complete-trace profiles, a strict portable
  task-alignment record whose authorization path re-runs the evaluator, a
  bounded material resolver with explicit disclosure policy, Ed25519/COSE
  egress-authority grants, and authenticated external-provider responses.
  Provider evidence cannot create authority. External grants are exact-scope
  and time-bound, but not one-shot, and do not establish live network-route
  enforcement;
- a pinned local resolver and deterministic provider that qualify only an
  explicitly configured exact artifact digest. This reference path exercises
  disclosure, provenance, abstention, and binding checks without claiming
  natural-language correctness;
- `AuthorizationDecision` schema 4, `TaskControlProjection` schema 2, and
  `ExecutionLineage` schema 2 bind the exact pre-execution evaluation hash;
  audit schema v6 exposes both evaluation hashes and a bounded categorical
  **Task check** and **Task evidence** projection. `VERIFIED` requires at least
  one qualified evidence item and only supported findings; the connected
  free-text profile has no qualified evidence and is shown as **Not verified**;
- 81 Lean theorems, built without placeholders or declared axioms;
- AccordBench 0.3.0 with 73 cases, including 43 task-alignment cases and
  eight explicit metamorphic relations, guarded by 24 tests;
- signed remote-approval contracts with strict outbound request adapters,
  externally verified Teams claim binding, a fixed-authority rustls/WebPKI
  transport, encrypted local queueing, a fail-closed one-step worker,
  authenticated dead-letter reasons, and durable replay protection. Desktop
  secure storage, gateway-key enrollment, fixed connection tests, and signed
  remote-decision receipt import are wired locally. Provider accounts, a
  reachable callback service, private gateway-to-Desktop delivery, and Entra
  verification are not bundled or evidenced live;
- a strict single-host SQLite enterprise-runner state with atomic pending and
  committed reservations, independent dispatch and action-approval replay,
  fixed capacity, restart survival, and a monotonic trusted-time high-water
  mark. Ambiguous crash state remains replay-blocking; and
- an account-free runner exhibit that revalidates the exact authorized
  Deployment snapshot, derives the compact JSON Patch with the same builder as
  the native executor, consumes the durable replay slots, and returns
  `NotSent`. It has no provider credential, transport, network I/O, or
  production-readiness override.

These facts do not satisfy a live gate. There is no retained successful full
kind composition or EKS run, no production evidence resolver or qualified
provider for natural-language task alignment connected to the captured plan
and bound evaluation path, no
production key/database identity deployment, and no independent assessment.
The enforcement production entry point therefore remains deliberately
fail-closed pending live RBAC, webhook-origin, and token-audience evidence.

## Gate A — public technical preview

Exit criteria:

- the repository builds and tests from a clean checkout;
- the deterministic demo runs without cloud credentials;
- the account-free Kubernetes exhibit completes on a disposable kind cluster
  with a retained immutable run directory;
- all shipped files pass secret, license, formatting, and repository checks;
- installation, architecture, threat boundaries, and limitations are public;
- every local-only capability and external premise is labelled accurately;
- no known critical defect invalidates the stated local claim boundary.

Expected release label: `v0.1.0-alpha.1`.

## Gate B — pilot-ready beta

Exit criteria:

- authenticated GitHub review and build evidence is consumed;
- the existing bounded plan checkpoint and authorization hash binding consume
  material from a production policy-scoped resolver, verified egress-authority
  grant, authenticated provider response, and qualified conformance evidence;
- external-disclosure grants are atomically claimed when single use is required,
  and the egress broker proves enforcement of the committed route and provider;
- every portable evaluation record is deterministically re-evaluated over its
  exact source inputs before its commitment is accepted;
- an immutable ECR image digest is verified;
- the exclusive execution path updates a disposable EKS target;
- the three management identities' effective RBAC closures, the exact API
  audience, and API-server-only webhook caller boundary are retained as signed
  activation evidence;
- direct, alternate-identity, ordinary-workload, and webhook-outage mutation
  attempts fail closed;
- replay, stale-state, bypass, outage, and break-glass scenarios are exercised;
- PostgreSQL TLS identity, least-privilege roles, restart, and exact recovery
  are exercised against the deployed state service;
- system latency and denial reasons are measured;
- conformance abstentions, review rates, substitutions, and false refusals are
  measured on a representative frozen corpus;
- installation and rollback are reproducible in a fresh sandbox.

Expected release label: `v0.1.0-beta.1`.

## Gate C — production candidate

Exit criteria:

- at least one bounded pilot has run on a non-critical customer workflow;
- production key custody, identity, database, backup, recovery, and monitoring
  controls are exercised;
- crash tests cover each database commit, provider-write, admission-response,
  observation, terminalization, takeover, and failover boundary;
- an independent security review has no unresolved critical or high finding;
- operational ownership, support, incident response, and break-glass procedures
  are accepted;
- measured reliability and refusal behavior meet the deployment's agreed
  thresholds.

Expected release label: `v1.0.0-rc.1` only after these conditions are met.

## Non-goals before beta

- multi-cloud support;
- a broad policy language;
- a hosted dashboard;
- arbitrary Kubernetes mutations;
- claiming live messaging-provider delivery before account enrollment and a
  trusted callback transport exist;
- turning an unverified model-generated plan into authorization;
- marketing claims that exceed retained evidence.

Detailed engineering closure criteria live in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

Release labels describe evidence, not aspiration. A locally implemented
mechanism may close a historical code gap without advancing Gate B. A kind run
does not establish EKS behavior, an AdmissionReview `ALLOW` does not prove
object persistence, and a timeout never proves that no external effect
occurred.
