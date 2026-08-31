# Trust boundary

**Status:** provisional local engineering boundary; the public wire profile is not frozen  
**Applies to:** the current `DEPLOY_EKS_IMAGE_V1` candidate only  
**Does not establish:** production security, complete mediation, independent
review, or customer acceptance

## Governing rule

The model and every caller-controlled process are outside the trusted computing
base. Parsing, schema validation, a hash, a signature, a field name such as
`approved`, or the Rust type name `TrustedEvidenceSet` does not make a claim
true. A security premise is usable only when an authenticated component is
registered to assert that premise within an explicit tenant, environment, kind,
and resource scope, and the assertion passes freshness and current-authority
checks.

The public proposal lane carries requested intent only. It must never carry an
authoritative policy, grade, label, attester entry, clock, authority vector,
revocation decision, grant, approval, build result, artifact verdict, or target
state.

## Source classes

| Source or record | Initial status | Condition before security use | Forbidden interpretation |
|---|---|---|---|
| Model, agent host, CLI, API caller | Untrusted | None; it may propose an operation only | Model output is never an approval, grade, label, or safety verdict |
| `AgentProposal` and `DeploymentTemplate` | Untrusted intent | Validate shape; bind authenticated tenant and actor; compare every decision-critical field with active policy and authoritative evidence | `actor`, `tenant`, target, digest, annotations, or request ID are not trusted because the caller supplied them |
| Authenticated ingress identity | Trusted only for its registered identity binding | Verify transport/workload identity, tenant mapping, audience, replay protection, and current registration | A string copied from `AgentProposal.actor` or `.tenant` is not authenticated identity |
| Connector output / `SignedEvidence` | Untrusted until verified | Deterministic COSE, accepted protected headers, registered current key, issuer and key match, allowed scope, exact canonical payload, time window, and exact authority vector | A valid signature proves who signed bytes; it does not prove the signer was authoritative or the claim was true |
| `TrustedEvidenceSet` wrapper | Untrusted container at ingress | Verify every enclosed assertion independently and bind the set to the request through a connector-owned correlation path | The type name does not confer trust, and `request_id` equality is not authentication |
| Registered attester record | Trusted internal state | Load from the active tenant registry whose root and epoch are current | The proposal or connector cannot register itself, choose its grade, or widen its scope |
| `PolicyConfig` | Trusted internal state only after activation | Load the exact compiled policy selected by the current signed activation and verify its canonical hash against the active policy root | Caller-supplied policy or static attributes cannot replace active policy state |
| `AuthorityVector` | Trusted internal state | Read from the transactional authority store; require exact root, epoch, and activation-ID equality at each specified check | An epoch or root copied from evidence or an authorization cannot establish currentness by itself |
| Clock and nonce | Trusted internal service | Use the selected database/time and cryptographic randomness profiles | Caller time, UUID, or model time is not authoritative |
| `CapabilityGrant` | Trusted internal state only | Load or verify it through the active grant registry, check status, scope, validity, use budget, and active grant-registry root | A grant passed by a caller is not authority merely because its fields match the proposal |
| `EvaluationAttestation` | Trusted only for its bounded statement | Verify evaluator identity, COSE signature, external AAD, canonical payload equality, outcome, template hash, evidence root, policy root, and authority vector | It is not proof that sources outside the registered scopes were complete or honest |
| `ExecutionAuthorization` | Trusted only after verification and current-state checks | Verify constrained authorization signer, COSE profile, audience, exact operation/template, time, current authority, grant, and one-time state in the executor transaction | A valid authorization is not permission for a different payload, resource, tenant, audience, time, or route |
| Consumption or dispatch receipt | Evidence after durable creation | Bind to the consumed authorization and transactional state; sign or checkpoint under the selected receipt profile | Authorization is not evidence that the external effect succeeded |
| Enforcement node, transaction store, signer/KMS path, verifier, executor | Trusted computing base for the stated property | Authenticate components, isolate credentials, constrain APIs, review code and configuration, and exercise failure recovery | The current local harness is not yet this production trusted path |
| Destination API | External consequence system | Reach it only through the exclusive executor and reconcile provider response with queried post-state | An HTTP success response alone is not proof of the intended world-state effect |

## Current data lanes

```text
UNTRUSTED PROPOSAL LANE
model or caller
  -> AgentProposal (intent only)
  -> signed application ingress envelope
  -> rooted key-registry identity and replay check [local implementation]
  -> AuthenticatedIngressRequest [opaque]
  -> production transport and durable replay service [absent]
  -> deterministic comparisons

EVIDENCE LANE
registered connector or attester
  -> SignedEvidence
  -> COSE + key + registry + scope + freshness + authority verification
  -> verified assertions and computed grades

INTERNAL AUTHORITY LANE
activated policy + attester registry + revocation + authority roots/epochs
  + trusted time + nonce + grant lookup
  -> KernelContext and authorization-issuance inputs

OUTPUT LANE
kernel decision
  -> signed EvaluationAttestation
  -> state-backed constrained authorization issuance
  -> signed ExecutionAuthorization
  -> current-state re-verification + atomic consumption
  -> durable authorization/AUTHORIZATION_ID-scoped dispatch claim + ATTEMPT_IN_FLIGHT
  ---- current implemented authority boundary ----
  -> exclusive credential broker and native executor [absent]
  -> authenticated provider observation and durable effect receipt [absent]
```

No arrow from the untrusted proposal lane may populate either the evidence lane
or the internal authority lane. Shared text values are equality-check inputs,
not trust transfers.

## Signed assertion behavior

The four current evidence payloads remain claims made by scoped attesters:

- review evidence may assert repository, commit, approval, and review-state ID;
- build evidence may assert workflow, run, result, input completeness, and
  output digest;
- artifact evidence may assert image digest, producing run, signature verdict,
  and quarantine state;
- target evidence may assert target identity and an observed prior state.

The outer COSE signature authenticates the assertion bytes. The active attester
registry determines whether that issuer may make that kind of assertion for the
named scope and supplies the grade. The kernel must not trust a self-selected
grade, a bare `source_uri`, or booleans received directly from the model.

## Known local blockers

These are documentation of current gaps, not claims that the gaps are repaired:

1. `accordlock-ingress` verifies a domain-separated application signature and
   can bind replay protection to the PostgreSQL-backed
   `accordlock-ingress-state` adapter. The in-memory guard remains test-only.
   No deployed production mTLS, workload identity, identity-provider binding,
   or operator-approved registry lifecycle exists.
2. The grant, audience, evaluator, authorization signer, and deadline policy are now
   loaded or derived inside the state-backed issuance path. However, the
   administrative APIs that activate authority, register or revoke grants, and
   configure keys have no production service authentication. Authorization keys remain
   ordinary software keys in process memory rather than HSM/KMS-confined keys.
3. Review, build, artifact, and target assertions are signature-, registry-,
   scope-, authority-, and freshness-checked. The production connectors that
   retrieve and attest those facts do not exist. A valid signature still does
   not establish truth outside the registered attester premise.
4. Target projection equality, the Kubernetes post-state projection, rooted EKS
   destination registration, native TLS transport, credential broker, and
   one-shot executor are implemented locally. Their API-server identity,
   effective RBAC, token audience, observer independence, and caller-origin
   evidence still depends on trusted activation material and has not been
   established in a live EKS deployment.
5. PostgreSQL provides signed-authorization storage, single-use consumption, current
   revalidation, globally exclusive physical-resource reservation, monotone
   fencing, durable acquisition/no-send recovery, terminal retirement, receipts,
   and outbox state. Backup rollback, HA, split-brain, failover, and deployment
   of least-privilege database roles have not been established.
6. The local `kind` runner does not use the durable dispatch bridge. It invokes
   `kubectl patch` directly with an existing credential after local consumption.
   It therefore tests authorization and Kubernetes mutation plumbing separately
   and does not establish complete mediation. No successful live `kind` or EKS
   run has been recorded.
7. The exclusive credential broker, native executor, pinned TLS transport,
   admission engine, terminal witness, and recovery state machines exist as
   local components. They have not been composed and deployed with exclusive
   credentials, an authenticated API-server-only webhook boundary, complete
   mutation mediation, or an independently verified observation path. The
   direct `kubectl` exhibit is not evidence for those properties.
8. Code holding a store, dispatch token, machine, or signing key is inside the
   current TCB. Rust opacity prevents several accidental constructions but is
   not an isolation boundary against hostile code in the same process. A
   production service must keep all raw state, control-plane, signer, and
   lifecycle APIs away from request-facing components.
9. Schema conformance has not yet been checked by an independent CDDL
   implementation, and no public interoperability encoding profile is frozen.

Until these blockers are closed and tested, any public-facing endpoint must be
treated as a local demonstration harness, not an authorization service.

## Schema relationship

`schemas/accordlock-local-candidate.cddl` mirrors the positional canonical arrays
currently emitted for hashes and signatures. It deliberately does not grant
trust to any parsed record and does not freeze a JSON transport. The reason-code
registry is `schemas/reason-codes.json`. Both are provisional and may change
before the public wire profile is frozen.
