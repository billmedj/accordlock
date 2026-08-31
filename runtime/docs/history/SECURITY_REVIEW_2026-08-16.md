# AccordLock local security review — historical snapshot

> This review predates the AccordLock public-release cleanup. Product and
> identifier names were normalized later; findings must be checked against the
> current source tree and current known-limitations register.

**Date:** 2026-08-16  
**Status:** historical adversarial local engineering audit; superseded by the
current source tree and [known limitations](../KNOWN_LIMITATIONS.md)  
**Scope:** then-current AccordLock workspace and the fixed
`DEPLOY_EKS_IMAGE_V1` profile  
**Not established:** production security, complete mediation, practical
utility, benchmark performance, customer acceptance, kind or Amazon EKS
success, independent review, or a security certification

## Conclusion

The workspace contains a substantive local reference implementation, not a
finished product. It now joins signed ingress, deterministic provenance
evaluation, state-backed authorization issuance, signed authorization storage, transactional
single-use consumption, one durable dispatch claim per consumed authorization, an irreversible
`ATTEMPT_IN_FLIGHT` boundary, deterministic Kubernetes patch construction, and
strict post-state checks.

The central production property is not yet established. The local Kubernetes
runner submits the patch through a direct `kubectl` credential and does not use
the state-backed dispatch claim or `AuthorizedProviderAttempt` before the
external effect. The workspace also lacks real evidence connectors, isolated
keys, an authenticated control-plane service, a credential broker, a native
executor, authenticated provider observations, terminal dispatch persistence,
high-availability recovery, and an independently reviewed deployment boundary.

The correct description is therefore a pre-G1 engineering candidate for one
narrow enforcement profile. It is suitable for continued adversarial
development. It is not yet suitable for authorizing a production resource.

The final internal AI-assisted pass did not identify an additional defect that
invalidates the narrowly conditional local-operation claim under its stated TCB
premises. The physical multi-process reservation gap and the interval between
`ATTEMPT_IN_FLIGHT` and the provider send remain P1 production blockers. This
internal disposition is neither proof of absence nor independent assurance.

## Audited claim boundary

Under all of the following premises:

- the process supplying policy, authority, registry, clock, nonce, and state is
  trusted;
- the evaluator and authorization signing keys are not exposed or misused;
- registered evidence attesters are authoritative and truthful within their
  declared scopes;
- PostgreSQL state and its credentials are controlled by the enforcement
  boundary;
- destination registration, credential claims, and provider observations are
  authenticated before entering the dispatch machine;
- all external effects pass through the intended executor path;

the local implementation can perform these bounded operations:

1. verify a strict, domain-separated, application-signed ingress envelope;
2. derive tenant and actor from a rooted ingress registry and reject replay;
3. verify four typed evidence kinds against a rooted attester registry;
4. compute a deterministic policy and provenance decision without consulting a
   model;
5. bind the accepted ingress expiry into the evaluation issuance window;
6. verify a rooted evaluator and issue a v2 authorization with a distinct rooted
   authorization signer;
7. load the grant, audience, authority, time, and dispatch policy from trusted
   state rather than request data;
8. store the exact signed authorization and consume its AUTHORIZATION_ID once;
9. create one durable dispatch claim for a consumed authorization, revalidate it, and
   irreversibly mark one provider attempt in flight;
10. derive one preconditioned Kubernetes JSON Patch and validate selected
    persisted and eventual projections, including the
    Deployment-to-ReplicaSet-to-Pod ownership chain.

This statement is conditional. The repository does not establish the premises
by itself.

## Current implementation map

| Surface | Local property implemented | Required TCB premise | Production blocker |
|---|---|---|---|
| Protocol | Strict typed records, canonical CBOR payloads, domain-separated COSE Sign1, authorization v2, signed dispatch policy | Correct implementation and protected signing keys | No frozen interoperability profile or independent parser |
| Ingress | Rooted key registry, signed request, exact proposal binding, audience and expiry checks, replay guard | Registry activation and server time are trusted | Replay state is process-local; no production transport or workload identity |
| Kernel | Opaque ingress join, rooted attester registry, deterministic decision, evidence and policy commitments | Policy, authority vector, registry lifecycle, and attester truth are trusted | No production evidence collection or authenticated control-plane loader |
| Issuance | State-loaded grant and audience, rooted evaluator and signer, signed authorization recorded before return | Software signer and state adapter remain inside the TCB | No KMS, HSM, TEE, or role-constrained signing service |
| State | Authority CAS, grant accounting, signed issuance record, one-time consumption, receipt, outbox, authorization/AUTHORIZATION_ID-scoped durable claim, fence, lease, time high-water mark, attempt marker | Database credentials and state administration are trusted and exclusive | Local profile uses loopback `NoTls`; no authenticated state service, physical-resource claim, replication, or disaster recovery |
| Dispatch | State-backed import, current-state rechecks, process-local physical reservations and ambiguity handling, one-shot local provider-attempt marker | Destination configuration, token claims, provider responses, and observer evidence are authentic | No broker, provider-side fence, durable physical reservation, terminal lifecycle, HA takeover, or automated reconciliation |
| Kubernetes | Exact patch derivation and strict projection checks | Captured objects and API identity are authentic | No native controlled executor; actual wire request is not observed or committed |
| CLI and runner | Deterministic synthetic harness and prepared kind workflow | Public fixture keys and caller `kubectl` credential are accepted only as test inputs | Direct `kubectl` path is not complete mediation; no successful kind or EKS result is claimed |
| Models | Bounded lifecycle specifications for authorization and dispatch-claim behavior | Abstraction matches the intended Rust and SQL behavior | Correspondence review, crashes, external effects, and distributed failover remain open |

## High-priority findings

### PA-01. External-effect mediation is absent

`infra/local/k8s/run-live.ps1` submits the prepared JSON Patch directly with
`kubectl`. The live path does not call `claim_dispatch`, does not commit
`ATTEMPT_IN_FLIGHT`, and does not require an `AuthorizedProviderAttempt` before
the patch crosses the provider boundary.

The runner is useful as an integration exhibit, but it cannot support an
unsignability or complete-mediation claim. A caller holding the same Kubernetes
credential can bypass AccordLock entirely.

Closure requires an executor that owns the only mutation credential, consumes
the non-clonable provider-attempt authority, rejects every direct route, and
records the provider response plus an independently queried post-state.

### PA-02. Library capabilities are not a same-process security boundary

Opaque types prevent several accidental constructions. They do not isolate
authority from arbitrary code linked into the same process. State
administration methods are public. A dispatch claim token is clonable and is
exposed by reference. The state `mark_attempt_in_flight` method is public.
Dispatch destination registration, authority activation, emergency-stop
control, lease recovery, and evidence-resolution methods are also public.

No direct raw constructor for `AuthenticatedIngressRequest`, `KernelContext`,
`IssuanceSnapshot`, `DispatchSnapshot`, `ClaimedDispatch`, `AttemptInFlight`, or
`AuthorizedProviderAttempt` was found. This is useful API hardening. It is not
process isolation.

Closure requires a broker or service boundary that owns the state adapter,
claim token, dispatch machine, signer handles, and destination credentials.
Untrusted request code must not receive these objects or invoke their control
methods.

### PA-03. Provider evidence is an oracle premise

`BoundObjectObservation`, `CredentialClaims`, `AuthenticatedObserver`,
`ExactEffectEvidence`, `NonIssuanceEvidence`, and
`CredentialInvalidationEvidence` can be constructed by a caller. The dispatch
machine checks identifiers, bindings, timing, and nonzero commitments. It does
not verify a Kubernetes response, TokenRequest credential, token signature,
observer credential, or post-state attestation.

An `EXECUTED` phase is therefore valid only under the premise that a trusted
adapter supplied truthful authenticated observations. The Rust type name does
not establish that premise.

Closure requires authenticated provider adapters, canonical observation
profiles, verifier roots, replay and freshness rules, and negative tests for
substitution, omission, collusion, and stale observations.

### PA-04. Destination and credential registration are not rooted

The dispatch machine accepts a locally registered `PhysicalResourceId` and
`CredentialProfile`. Their contents are not committed by an activated
destination registry that is checked against the active `resource` or
`mediation` authority domain.

Zero or multiple matching destinations fail closed, but one incorrect trusted
registration can select the wrong API identity or credential profile. The
current code documents the API server identity as a premise; it does not prove
the premise.

Closure requires a canonical activated destination registry whose exact root,
epoch, and activation identifier are included in current state checks.

### PA-05. Command and wire commitments are prospective

`accordlock-k8s` commits to an identifier named
`accordlock-k8s-native-client/v1`. No such native executor is implemented. The
local runner uses `kubectl`, whose effective transport is not observed and
compared with the stored commitment.

The current values commit to the intended method, path, content type, and body.
They are not evidence of the actual command or network request.

Closure requires a native executor with a frozen request profile, exact
credential and destination binding, and an observed request or server-side
receipt that can be compared with the authorization-bound commitment.

### PA-06. Signing-key isolation is not implemented

The cryptographic library exposes a generic software `SigningIdentity` and a
generic `sign_cose` function. Key separation and signer-root checks are enforced
inside issuance, but the repository cannot prevent code that already possesses
the active private key from signing another payload directly.

The local fixtures intentionally use public deterministic seeds. They
demonstrate cryptographic plumbing, not custody or unconstructibility against a
compromised signer process.

Closure requires isolated keys, role-constrained signing operations, workload
authentication, rotation and disable procedures, audit logs, and tests showing
that the model and request process have no signer route.

### PA-07. Physical-resource exclusion is not durable

The PostgreSQL claim is unique for one consumed authorization and AUTHORIZATION_ID. The reservation
for a Kubernetes physical resource is held only in the in-memory dispatch
machine. Two processes can therefore claim two different valid authorizations aimed
at the same Deployment. Kubernetes resource-version preconditions may cause one
patch to fail, but they do not establish exclusive credential issuance or one
provider attempt for that physical target.

Closure requires a canonical physical-resource key, one durable active
reservation and monotonically increasing fence for that key, and transactionally
linked claim, credential, attempt, retirement, and reconciliation state.

### PA-08. Currentness stops at the local attempt marker

The last current-state check and the `ATTEMPT_IN_FLIGHT` commit precede the
network send. An `AuthorizedProviderAttempt` has no destination-enforced fence
or independently checked expiry. Authority can change after that commit while
the marker is held. No local API can make the database commit, remote send, and
resource effect one atomic event.

Closure requires a trusted one-shot executor that consumes the marker by value
and sends immediately, plus destination-side admission or another provider
fence tied to the attempt generation and current authority. Until then,
currentness is claimed only at the recorded state check, not at remote effect
time.

## Defects corrected during this audit cycle

The following statements are bounded local implementation results. They are not
independent assurance:

- authenticated ingress is now joined to the kernel through an opaque result,
  and its signed expiry bounds authorization issuance;
- attester registry, evaluator verifier, and authorization signer material are bound
  to explicit authority roots;
- authorization issuance loads the grant and executor audience from state and performs
  a second current-state check before returning signed bytes;
- authorization v2 signs the dispatch deadline policy and immutable dependency
  expiries;
- state stores and verifies the exact signed authorization rather than a naked authorization
  payload;
- PostgreSQL and in-memory adapters expose one durable dispatch claim and an
  irreversible attempt marker;
- exact routed time observations advance the applicable high-water state during
  signed ingress, grant registration, issuance, consumption, and dispatch,
  including temporal rejections, so a later clock rollback cannot revive an
  expired local authorization; unknown or mismatched routes do not advance that
  state;
- issuance rejects an exact `consume_before` boundary before recording the
  authorization;
- the state-backed dispatch bridge rechecks current state before bound-object
  creation, token issuance, credential acceptance, and provider-attempt
  authorization;
- Kubernetes eventual validation now checks the exact
  Deployment-to-ReplicaSet-to-Pod ownership chain.

Targeted tests for these components passed during the implementation cycle. A
complete local runner also passed on 2026-08-16; exact tools, aggregate counts,
limitations, and excluded results are recorded in
`docs/REPRODUCTION_REPORT_2026-08-16.md`.

## Publication and product blockers

Before any production or customer-enforcement claim, all of the following
remain necessary:

1. encapsulate the signer, state, claim token, dispatch machine, and executor in
   authenticated service boundaries;
2. remove every direct destination credential route from the model and caller;
3. implement real GitHub, build, artifact-registry, and Kubernetes evidence
   connectors;
4. root destination, credential, observer, and executor configuration in active
   authority;
5. implement a durable physical-resource reservation, the native one-shot
   executor, destination-side fencing, actual request observation, effect
   receipt, terminal persistence, crash recovery, and high-availability rules;
6. run and retain a successful account-free kind integration without treating
   it as EKS evidence;
7. exercise a dedicated AWS sandbox before making an EKS claim;
8. freeze and independently parse the protocol profile;
9. complete security, utility, refusal, escalation, and latency evaluations
   against strong baselines;
10. obtain independent systems-security, cryptographic, formal-methods, and
    infrastructure review;
11. validate one real customer workflow and its bypass inventory.

Current technical uncertainties and closure criteria are tracked in
[`docs/KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md). Release gates are in
[`docs/ROADMAP.md`](../ROADMAP.md).

## AI-assistance boundary

The implementation, tests, models, and this audit were produced with extensive
AI assistance under the author's direction. AI-assisted adversarial review is
internal work. It is not represented as independent validation. Every result
remains subject to reproduction from an immutable source revision and review by
people who did not author the papers or code.
