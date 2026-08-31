# AccordLock threat model

**Status:** unreleased engineering alpha  
**Profile:** `DEPLOY_EKS_IMAGE_V1`  
**Last reviewed:** 2026-08-22

This document states what AccordLock is intended to protect, which actors and
systems are trusted, and which properties are not yet established. It is a
design threat model, not an independent assessment or security certification.

## Security objective

For the initial profile, AccordLock should allow one exact image update to one
existing Kubernetes Deployment only while all of the following remain valid:

- the caller and bounded intent are authenticated;
- the required review, build, artifact, and target evidence is authentic,
  fresh, and mutually consistent;
- the active policy, grant, signer, destination, and authority epoch match;
- the live target is still the authorization-bound target and pre-state;
- the authorization has not expired, been consumed, or been replayed; and
- the provider request does not exceed the authorized mutation.

When AccordLock cannot establish a required fact, it must refuse the action or
retain it for explicit reconciliation. It must not guess that an unknown remote
outcome is safe to retry.

## Evidence level of this threat model

The repository contains three different evidence levels that must not be
collapsed:

- **implemented locally:** PostgreSQL replay and lifecycle state through
  migration `0014`; rooted EKS activation; durable global reservation;
  server-selected acquisitions; exact terminal retirement; the native EKS
  broker, TLS transport and executor; state-backed admission; the bounded HTTPS
  webhook; and authenticated TLS PostgreSQL configuration;
- **composed but fail-closed:** the enforcement object graph joins acquisition,
  broker, attempt, executor and cleanup code, while its production entry point
  deliberately refuses to unlock without live activation evidence; and
- **not live-proven:** no retained kind composition or EKS run proves endpoint
  behavior, management RBAC closure, token audience, API-server-to-webhook
  caller origin, bypass denial, or end-to-end effect/retirement observation.

Local implementation status is evidence about code and schemas, not evidence
that an external system supplied a truthful fact.

## Protected assets

- integrity of the reviewed deployment intent;
- provenance links among source, build, image digest, and target state;
- active policy, grant, authority, destination, and attester registries;
- authorization-issuer and evidence-attester signing keys;
- short-lived Kubernetes execution credentials;
- transactional consumption, replay, dispatch, reservation, and retirement
  state;
- effect observations and audit records; and
- the exclusive path from an authorized attempt to the protected mutation.

## Adversaries considered

- a compromised or malicious AI agent that can submit arbitrary requests;
- a caller that tries to inject trusted policy, time, identity, evidence grade,
  grant, destination, signer, or authority fields;
- a tenant attempting replay, cross-tenant confusion, or cross-target reuse;
- an attacker able to reorder, delay, duplicate, or substitute network data;
- a compromised evidence source or connector returning scoped falsehoods;
- an attacker with partial application access attempting to misuse a generic
  signer or lower-level state capability;
- a credential thief attempting direct Kubernetes access or action after
  revocation; and
- a dependency, build, or release-path attacker attempting to alter the shipped
  implementation.

## Trust boundaries

| Boundary | Local implementation | Live trust position |
|---|---|---|
| AI model or automation caller | Strict bounded proposal and signed-ingress schema | Untrusted; must never receive evidence, state, signer, broker, or executor authority |
| Ingress adapter | Rooted signature verification plus PostgreSQL nonce/high-water adapter | Public transport and workload identity are not deployed |
| Evidence connectors | Typed four-source join and purpose-separated signed assertions | Real source adapters and durable source checkpoints are absent |
| Kernel | Deterministic decision over activated evidence | Trusted decision component; upstream truth remains source-scoped |
| PostgreSQL state | Migrations `0001`-`0014`, local/CI store, and authenticated TLS store | Safety-critical authority; database roles, HA, backup and recovery are unproved |
| Signer adapters | Purpose separation and rooted verification | Production key isolation, anti-backdating and workload policy are unproved |
| Dispatcher and executor | Durable acquisitions, opaque attempt, native one-shot executor | Exclusive process/credential custody and complete live mediation are unproved |
| Kubernetes admission | State-backed atomic decision plus bounded HTTPS webhook | Server TLS authenticates the webhook, not its caller; API-server origin and bypass denial are unproved |
| Observation and terminal retirement | Exact effect/retirement witness formats and atomic terminal release | Observer truth, key custody and live collection are unproved |
| Cluster administrator | No defense in the local profile | Inside the trusted computing base and able to bypass admission controls |

The detailed field-level split is in [TRUST_BOUNDARY.md](TRUST_BOUNDARY.md).

## Threats and controls

| Threat | Control | Status on 2026-08-22 |
|---|---|---|
| Caller injects trusted facts | Strict request schemas and server-loaded identity, policy, grant, clock, registry, and authority state | Implemented locally; public service composition not proved |
| Forged or substituted evidence | Typed signed assertions, activated attester scopes, canonical encodings, and exact provenance joins | Verifier/runtime implemented; real connectors absent |
| Ingress replay or clock rollback | PostgreSQL audience high-water and atomic nonce ledger | Implemented locally in migration `0010`; live service/HA unproved |
| Authorization replay or double use | Short lifetime, unique AUTHORIZATION_ID, transactional consumption, global reservation, and one-shot admission UID | Implemented locally; live failover unproved |
| State changes after evaluation | Authority and target rechecks at issuance, consumption, acquisition, attempt, pre-write guard, and admission | Implemented locally; no atomicity with Kubernetes |
| Cross-target or confused-deputy use | Rooted destination, injective owner registry, exact route/UID/pre-state/mutation/credential binding | Implemented locally in the registered identity model; AWS truth unproved |
| Signing-key misuse | Purpose-separated identities and a production requirement for constrained KMS/HSM-style signing | Separation implemented; isolation absent |
| Direct provider bypass | Exclusive executor credential plus destination-side admission enforcement | Components implemented; live complete mediation not proved |
| Concurrent attempts on one resource | Durable canonical reservation, stable claim, acquisition generation and monotone fences | Implemented locally; split-brain/rollback tests remain |
| Ambiguous network outcome | Durable irreversible phases, no mutation retry, recovery-only discovery, exact no-send retirement, retained reservation | Implemented for bounded local paths; live crash matrix incomplete |
| Unsafe terminal release | Purpose-separated exact-effect and credential-retirement witnesses followed by atomic terminalization | Implemented locally; observer trust and live evidence unproved |
| Forged AdmissionReview caller | Private API-server-origin path or supported client authentication in addition to webhook server TLS | Not live-proven; production blocker |
| Secret disclosure in diagnostics | Bounded secret inputs, zeroization where implemented, and redacted `Debug`/logging surfaces | Implemented locally within stated Rust limits |
| Build or dependency compromise | Locked inputs, pinned toolchain/CI actions, source manifest, audit, and reproducible checks | Local controls exist; immutable public reproduction absent |
| Denial of service | Fail closed, bounded parsing, queues, semaphores, and timeouts | Safety behavior implemented locally; availability not guaranteed |

## Current residual risks

The engineering alpha does not yet establish all intended controls in one real
deployment. In particular:

- evidence is synthetic rather than collected from authenticated GitHub,
  registry, AWS, and Kubernetes systems;
- production signing-key custody and workload identities are not configured;
- the three broker-management identities' effective RBAC closures and the
  exact Kubernetes API audience have not been proved on EKS;
- webhook server TLS does not authenticate an inbound caller, and no retained
  deployment proves API-server-only origin or complete bypass denial;
- no successful retained kind composition or EKS execution exists;
- productive ambiguous effects may require manual resolution and retain their
  physical reservation indefinitely;
- terminal witness truth, key custody, and collection have not been
  independently validated;
- authenticated PostgreSQL transport exists in code, but live TLS,
  least-privilege roles, replication, backup, restore, and disaster recovery
  have not been exercised; and
- a cluster administrator remains capable of bypassing Kubernetes admission.

The authoritative engineering closure criteria are maintained in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Explicit non-goals for the preview

- defending a cluster after its trusted administrators or control plane are
  fully compromised;
- guaranteeing availability when safety-critical state or evidence is
  unavailable;
- authorizing arbitrary tools or Kubernetes mutations;
- proving the truth of a compromised upstream source that is still configured
  as authoritative;
- making PostgreSQL and a remote provider one atomic distributed transaction;
- replacing Kubernetes RBAC, admission, Sigstore, SLSA, OPA, or existing policy
  engines; and
- claiming compliance, certification, or end-to-end formal verification.

## Review and reporting

Changes to a trust boundary, canonical encoding, signing operation, state
transition, credential path, or provider effect must update this document and
include adversarial tests. Report security findings through
[SECURITY.md](../SECURITY.md), not a public issue.
