# AccordLock architecture

**Last updated:** 2026-08-22  
**Status:** technical-preview architecture  
**Initial profile:** `DEPLOY_EKS_IMAGE_V1`

This document describes the product implemented in this repository and the
larger deployment in which that code is intended to operate. The distinction is
material:

- **implemented locally** means that source, migrations, composition roots, and
  adversarial tests exist in this repository;
- **locally composed** means that the components can be joined without claiming
  that a real provider accepted an effect; and
- **live-proven** means that the same boundary has been exercised against a
  retained kind or EKS environment with authenticated infrastructure evidence.

As of 2026-08-22, the safety-critical local profile extends through PostgreSQL
migration `0014`: durable ingress replay, rooted EKS destinations, durable
physical-resource reservation, terminal retirement, and server-selected
dispatch acquisitions are implemented. Native EKS broker/transport/executor
and state-backed admission/webhook/TLS-PostgreSQL adapters also exist. The
repository still does **not** claim a successful kind composition, EKS
interoperability, complete live mediation, production operations, customer
validation, or independent assurance.

## 1. Product definition

The product is a provenance-aware execution boundary for high-consequence AI
and automation actions.

Its first profile is deliberately narrow:

> authorize one exact container-image change to one existing Kubernetes
> Deployment, then allow that change only while the authenticated evidence,
> grant, policy, authority configuration, target state, and deadline remain
> valid.

The model may propose the change. It does not hold an enforcement key, choose
the trusted evidence, select the active policy, construct a grant, set the
clock, create an execution credential, or decide whether the effect occurred.

The intended commercial form is hybrid:

- a customer-hosted enforcement plane beside the protected cluster;
- an optional SaaS control plane for configuration, evidence status,
  conformance, audit projections, and operator workflows;
- a local SDK and API for agent and CI integrations;
- destination-specific enforcement profiles, beginning with EKS.

The customer-hosted plane remains authoritative for an effect. Loss of the SaaS
control plane must fail closed for new protected effects unless a narrowly
defined, pre-activated continuity policy says otherwise.

## 2. Why this is not another generic agent gateway

Existing gateways and policy decision points can evaluate actor, tool, action,
resource, session, budget, and policy attributes. Several already issue signed
decisions or single-use execution tokens.

The product hypothesis is narrower. A conventional control may allow a
deployment because the actor and target are authorized while lacking an
authenticated, current link between:

1. the reviewed source commit;
2. the build that consumed that commit and its declared inputs;
3. the signed, non-quarantined image digest produced by that build;
4. the exact pre-state of the destination Deployment;
5. the authority configuration under which the authorization was created; and
6. the exact mutation finally presented to the destination.

The product is valuable only if customer workflows contain consequential cases
where that missing lineage changes the decision. This remains a market
hypothesis until reproduced with external design partners.

## 3. Fixed launch profile

`DEPLOY_EKS_IMAGE_V1` changes one container image in one existing Deployment.
The protected projection includes at least:

- cluster identity;
- namespace;
- Deployment name and immutable UID;
- container name and index;
- prior image digest;
- new image repository and digest;
- prior `resourceVersion`;
- a complete protected-object projection hash;
- reserved transaction, authorization, and operation annotations; and
- the final admitted object projection.

The profile does not create Deployments, change replicas, service accounts,
environment variables, sidecars, volumes, security context, networking, or
arbitrary annotations. Any such delta is denied.

## 4. End-to-end authority path

```text
authenticated intent
        |
        v
trusted evidence connectors
        |
        v
deterministic provenance kernel
        |
        v
constrained authorization issuer and signer
        |
        v
durable one-time consumption
        |
        v
durable claim + physical reservation + v14 acquisition
        |
        v
exclusive executor + exact request construction
        |
        v
fail-closed Kubernetes admission authorization
        |
        v
persisted effect observation + reconciliation
```

Every arrow is a trust boundary. Passing the previous stage is not sufficient
to skip a later one.

## 5. Component responsibilities

| Component | Responsibility | Must not accept from an untrusted request |
|---|---|---|
| Ingress | Authenticate caller, audience, nonce, time window, and exact intent | Tenant, actor, trusted clock, registry activation |
| Evidence connectors | Retrieve source-specific facts and sign bounded assertions | Grades, policy verdicts, arbitrary source scopes |
| Kernel | Verify activated registries, evidence, provenance constraints, policy, and target binding | Active policy, authority vector, trusted evidence labels |
| Authorization issuer | Load the registered grant and signer configuration, derive time and audience, sign and durably record | Grant body, signer key, AUTHORIZATION_ID, deadline policy, current time |
| State | Enforce issuance, consumption, replay, authority epoch, rollback-resistant time, durable claims, and reservations | Caller-selected current authority or lifecycle state |
| Dispatch | Re-derive execution bindings and advance the bounded attempt state machine | A fabricated consumption receipt or resource identity |
| Executor | Consume one opaque attempt, own the effect credential, construct and send one exact request | HTTP method, path, body, credential, effect classification |
| Admission | Recheck final object delta and state-backed attempt at the destination | A request annotation treated as authorization |
| Reconciler | Establish persisted effect or manual-resolution status from authenticated observations | A caller-supplied success boolean |
| Audit projection | Expose non-executable status and evidence references | Raw authorizations, credentials, reusable claims |

## 6. Durable state and linearization points

The local candidate uses PostgreSQL as the safety-critical state authority. The
relevant linearization points are:

1. **authorization issuance commit:** the signed authorization and its registered grant are
   recorded after a final current-state check;
2. **authorization consumption commit:** AUTHORIZATION_ID, receipt, deadline, grant use, and outbox
   are written atomically;
3. **dispatch claim and reservation commit:** one consumed authorization obtains one
   immutable stable claim and one canonical physical resource is bound to at
   most one active claim;
4. **dispatch acquisition commit:** server-side selection appends one bounded
   lease generation; takeover appends a higher generation instead of rewriting
   the stable claim;
5. **attempt-in-flight commit:** the latest acquisition and current state are
   rechecked immediately before handing one opaque authority to the executor;
6. **admission authorization commit:** the exact AdmissionReview UID and bound
   mutation are consumed before an allow response is returned; and
7. **terminal or no-send retirement commit:** only the exact rooted evidence
   profile atomically changes the lifecycle and releases the reservation.

These commits do not make PostgreSQL and Kubernetes one distributed
transaction. An allow response can be lost, Kubernetes can reject a later
stage, or the process can crash. Such outcomes require idempotent exact
recovery or manual reconciliation. They must never be guessed as success or
safe non-delivery.

The implemented migration sequence establishes the following local boundaries:

| Migration | Locally implemented boundary |
|---|---|
| `0010` | Audience-scoped PostgreSQL replay high-water and nonce ledger, including bounded garbage collection |
| `0011` | Rooted EKS destination activation and globally injective physical-owner registry |
| `0012` | Rooted terminal-witness material, exact effect and credential-retirement evidence, terminal history, and atomic reservation release |
| `0013` | Durable authenticated submission intake and fenced evaluate/issue/consume control queue |
| `0014` | Request-identity reservation, immutable claims, append-only dispatch acquisitions, recovery discovery, pre-effect dispositions, and no-send retirement |

These are database and code properties. They do not prove that a deployed
database is highly available, that its credentials enforce the intended role
split, or that Kubernetes and AWS observed the same facts.

## 7. Physical-resource identity

The reservation key is derived from the stored signed authorization, not supplied by
the executor request. It currently includes:

- canonical cluster identity;
- namespace; and
- immutable Deployment UID.

Tenant, environment, Deployment alias, container name, and resource version do
not split this key. This prevents two aliases for one authorization-bound resource
from obtaining two reservations inside the stated identity model.

Migration `0011` implements the activated EKS registry that binds this logical
key to a canonical route and globally prevents reuse of the same registered API
server/socket trust identity and Deployment UID by another owner. Production
still requires authenticated activation evidence proving that the registered
AWS/EKS route is truthful. Unregistered aliases or two configured routes that
reach the same provider outside that evidence remain an external risk.

## 8. Admission behavior

The state-backed validating admission decision is implemented locally and the
`accordlock-webhookd` composition root exposes it over bounded HTTPS. In the
launch profile it is the intended final product enforcement point. It must:

- accept only Kubernetes `admission.k8s.io/v1` Deployment `UPDATE` reviews;
- serve a certificate that the API server validates through the webhook
  `caBundle`;
- accept calls only through a deployment-proved API-server-origin boundary;
- require the exact dedicated executor service-account identity;
- derive the physical resource from trusted cluster configuration and the old
  object's UID;
- validate the complete post-mutation projection after mutating webhooks;
- reload the durable attempt, physical reservation, authority, grant, deadline,
  and high-water time;
- compare the provider request, old object, new object, executor identity, and
  observer commitments;
- atomically consume one exact AdmissionReview UID;
- recover only the same UID and exact tuple while the authorization remains
  current; and
- deny on storage uncertainty, replay, expiry, authority change, route
  mismatch, or unavailable state.

`dryRun: true` is non-consuming. It may test the pure schema and object-delta
rules, but it must not reserve or consume an admission authorization.

The webhook configuration must use fail-closed behavior for the protected
profile. An admission allow is not proof that the object was persisted. The
effect remains unresolved until an authenticated post-state observation is
reconciled.

Server-side TLS authenticates the webhook to Kubernetes; it does not, by
itself, authenticate the caller to the webhook. `AdmissionReview.userInfo`
must therefore be trusted only after the live network/client-authentication
boundary has proved API-server origin. This caller-origin property is not yet
proved in kind or EKS.

## 9. Credential and bypass model

The long-term product should prefer an executor identity whose Kubernetes
permission is harmless without the admission webhook. The webhook must deny
every protected mutation lacking an active state-backed attempt.

Operational deployment must establish:

- no agent or model process receives the executor credential;
- no alternative service account or cluster-admin path is treated as part of
  the protected guarantee;
- the admission configuration cannot be disabled by the executor;
- the executor cannot modify its own admission policy, trust registry, or
  credentials; and
- break-glass actions are separately authenticated, audited, and excluded from
  the automatic-action guarantee.

A cluster administrator can bypass a Kubernetes admission webhook. Cluster
administration therefore remains in the trusted computing base unless a
stronger external enforcement mechanism is added.

## 10. Failure behavior

The product uses the following conservative classes:

- **definitely not sent:** no provider request left the trusted transport;
- **acquired but no productive authority survived:** rediscover only the exact
  v14 recovery work; prove the authorized pre-effect disposition or provider
  object absence; cross the rooted no-send retirement bound; then release the
  reservation without reconstructing a bearer or attempt;
- **attempt committed, send not started:** do not infer no effect from process
  state; recover only through the exact durable claim and journal protocol;
- **outcome unknown:** do not resend, retain the physical reservation, and
  reconcile;
- **admission committed, response lost:** recover only the same UID and tuple
  while current; otherwise deny and retain the historical record;
- **admission allowed, persistence unknown:** query authenticated destination
  state and classify only as exact effect or manual resolution for a productive
  attempt; and
- **effect observed:** store immutable exact-effect evidence, then release the
  reservation only when separate exact credential-retirement evidence also
  passes the rooted terminal-witness profile.

No timeout, HTTP status, credential expiry, or admission record alone proves
that an earlier effect did not occur. There is no productive terminal
`NO_EFFECT` path.

## 11. Product surfaces

### 11.1 Customer-hosted enforcement plane

- ingress verifier;
- evidence connector runtime;
- deterministic kernel;
- constrained signer adapter;
- PostgreSQL-backed lifecycle state;
- dispatcher and reconciler;
- exclusive EKS executor;
- validating admission webhook; and
- non-executable audit/event exporter.

### 11.2 SaaS control plane

- tenant and environment configuration;
- connector and attester registry management;
- policy and grant workflows;
- authority epoch activation;
- conformance results;
- read-only action timelines;
- manual-resolution queue; and
- deployment-health and bypass-inventory views.

The SaaS UI is an operator surface. It is not itself proof that an effect was
authorized or occurred.

### 11.3 Integration surfaces

- strict action-intent API;
- SDK for CI and agent frameworks;
- status and evidence-reference API;
- event export to SIEM and incident systems;
- policy integration with Cedar, OPA, AuthZEN, or existing gateways; and
- Kubernetes admission and workload identity configuration.

The product should complement existing policy systems. It should not require a
customer to replace them merely to obtain value-lineage enforcement.

## 12. Current implementation map

This table reports repository capability, not deployment certification.

| Repository component | Implemented local capability | Boundary not yet proved |
|---|---|---|
| `accordlock-ingress` + `accordlock-ingress-state` | Signed bounded ingress, rooted principal registry, and PostgreSQL-backed atomic replay/high-water adapter | No public production ingress service or workload identity |
| `accordlock-connectors` | Four-source typed connector runtime with exact cross-source joins, freshness checks, and signed assertions | Source adapters are synthetic; no authenticated GitHub, registry, or Kubernetes clients |
| `accordlock-protocol` | Strict types, canonical encodings, purpose-separated COSE profiles | Pre-1.0 wire profile, not an independently implemented public standard |
| `accordlock-kernel` | Deterministic evaluation over authenticated, activated evidence | The real-source truth and connector-to-kernel handoff remain deployment premises |
| `accordlock-issuance` | State-loaded grant, purpose-separated signing, and final record check | No KMS/HSM adapter or production key custody |
| `accordlock-state` | PostgreSQL migrations `0001`-`0014`, including replay, rooted EKS activation, global reservation, admission ledger, terminal retirement, control queue, and dispatch acquisitions | No live TLS database result, database-role split, HA, backup, restore, or disaster-recovery proof |
| `accordlock-control` | Role-fixed bounded evaluate/issue/consume workers over the durable v13 queue | Worker roles are not yet separate authenticated database identities |
| `accordlock-dispatch` | State-selected acquisition import, opaque attempt authority, recovery-only work, and conservative no-send retirement | Kubernetes remains a separate transaction; productive unknown effects require reconciliation |
| `accordlock-eks-profile` | One canonical route shared across registry, broker, transport, executor, and admission | Authentic AWS ownership, endpoint mapping, and live RBAC are external proofs |
| `accordlock-eks-broker` | Native one-shot Secret, TokenRequest, TokenReview, and exact cleanup lifecycle backed by the durable journal | Live Kubernetes behavior, management-identity RBAC closure, and token audience are unproved |
| `accordlock-k8s` | Exact compact JSON Patch derivation and strict object/rollout projections | No provider interaction by this pure crate |
| `accordlock-eks-transport` | Pinned-socket HTTP/1.1 over rustls, exact GET/PATCH construction, no automatic retry, and conservative send classification | No retained live EKS handshake or interoperability run |
| `accordlock-executor` | By-value one-shot attempt and bearer consumption, final currentness horizon, exact native request, and typed effect evidence | Process-global credential exclusivity and destination enforcement are deployment invariants |
| `accordlock-admission` | Strict state-backed AdmissionReview decision and PostgreSQL atomic UID/claim/request replay ledger | Does not authenticate the HTTP caller or prove persistence after ALLOW |
| `accordlock-webhook` | Bounded fail-closed HTTPS server, readiness gate, state-backed admission composition, and TLS-PostgreSQL startup validation | Not deployed; API-server caller origin, HA, certificate custody, and bypass resistance are unproved |
| `accordlock-enforcement` | Singular acquisition-to-broker-to-attempt-to-native-executor composition with secret-free recovery | Productive entry point intentionally remains fail-closed pending three live activation proofs |
| `accordlock-runner-protocol` + `accordlock-runner-bridge` + `accordlock-runner-engine` | Credential-free dispatch, exact authorization reconstruction, single-host durable replay state, and an account-free exhibit that derives the native compact JSON Patch and returns `NotSent` | The exhibit has no credential, provider transport, network I/O, admission result, or post-state evidence; it does not deploy |
| `accordlock-activation` | Purpose-separated verification format for RBAC, webhook-origin, and audience proof bundles | Synthetic verifier only; no live collector, durable replay service, or enforcement unlock |
| `accordlock-terminal-witness` | Purpose-separated exact-effect and exact-credential-retirement evidence profiles | Observer truth, key custody, and live collection remain external premises |
| `accordlock-service` | Strict transport-independent submission/status facade | Not wired to the v13/v14 production state composition and has no public server |
| `accordlock-cli` | Deterministic synthetic scenarios and prepared account-free Kubernetes exhibit | No retained successful kind run; the exhibit is not the native production path |

The production enforcement entry point currently reports exactly three live
activation blockers: effective RBAC closure for the three management
identities, authenticated webhook caller origin, and the exact Kubernetes API
audience on the bound EKS route. Those blockers are intentionally not
convertible into a local boolean or a readiness override.

## 13. Production acceptance gates

The launch profile is not production-ready until all of the following are
demonstrated:

1. a public request cannot inject identity, current authority, grant material,
   policy, time, evidence grade, deadline, signer, or credential;
2. evidence comes from authenticated GitHub, build, artifact, and target
   adapters with bounded source-specific behavior;
3. signer keys are purpose-separated and isolated in an HSM, KMS, or equivalent
   constrained signing service;
4. two processes and two tenants cannot obtain concurrent authority for one
   physical Deployment;
5. all protected mutations are denied when the admission service, state store,
   or current authority is unavailable;
6. direct use of the executor identity without a current attempt is denied at
   admission;
7. crash tests cover every commit and network boundary, including response-loss
   recovery and unresolved outcomes;
8. terminal reconciliation is durable and cannot release a resource while an
   earlier credential or effect may remain live;
9. the native Kubernetes transport authenticates the intended API server and
   sends the committed request without hidden retries;
10. the complete chain runs on a disposable kind cluster and a separate EKS
    sandbox with retained immutable evidence;
11. baseline comparisons show cases where ordinary action policy and native
    admission controls allow an action because they lack the required lineage;
12. latency, refusal, escalation, recovery, and operational-load measurements
    meet a customer-defined threshold; and
13. independent reviewers who did not write the papers or code attack the
    implementation and verify the remediations.

## 14. Product-validation boundary

Engineering completion does not establish product demand. Before AccordLock
can claim operational utility, the fixed profile must be evaluated against a
real deployment workflow with a willing design partner. That evaluation must
show a reproducible integrity gap that existing controls do not already close,
measure installation and operating burden, and define acceptable reliability,
refusal, recovery, and break-glass behavior.

Commercial targets, pricing, pipeline strategy, and partner identities are not
part of the public architecture or security evidence.

## 15. Version and naming policy

The current public research artifacts are not silently replaced by this
product architecture. Any paper revision retains its own version and scope.

The software product, packages, command-line tools, container images, and
documentation use the name **AccordLock**. Historical research artifacts that
predate this repository retain their original titles and are not silently
rewritten.

The protocol is still pre-1.0. Until a stable release exists, wire formats,
database schemas, and command-line interfaces may change between minor
versions. Every incompatible change must include migration notes and updated
conformance vectors.
