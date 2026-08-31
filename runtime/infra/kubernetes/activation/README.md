# AccordLock EKS activation gate — captured evidence, offline decision

This directory contains a standard-library-only, fail-closed gate for a
**previously captured** EKS activation evidence bundle. It contains no cluster
collector, deployment automation, credentials, network calls, or apply path.
Running it cannot change Kubernetes or AWS state.

`CANDIDATE_EVIDENCE_CLAIMS_VALIDATED` means only that the submitted claims are
complete, fresh, internally consistent, committed to one activation context,
and match the exact reviewed profile. It does **not** mean that a SHA-256
commitment proves the committed
bytes are true, that a claimed source identity is authentic, or that an
external control remains in force. Raw command inputs and responses must be
retained outside this tree, authenticated by the operating environment, and
independently reviewable. **No production activation is authorized** without
provenance, signature or equivalent attestation of those raw artifacts by a
reviewed collector in the trusted computing base, followed by an explicit
operator review. This script must never be consumed as cryptographic proof.

## Files and authority

- `bundle.schema.json` is the JSON Draft 2020-12 interchange shape. It is useful
  to producers but deliberately cannot express all cross-record invariants.
- `validate.py` is the normative payload gate. It uses only the Python
  standard library and performs no I/O except reading one local JSON file.
- `example.refused.json` is a poison-pill sentinel, not a template that can
  pass. It contains placeholders, zero commitments, and no evidence.
- `test_validate.py` constructs a complete in-memory fixture and attacks every
  important binding. No live command or credential is embedded in it.

Run the local checks from this directory:

```powershell
python .\test_validate.py
python .\validate.py .\example.refused.json --now 2026-08-16T00:00:00Z
```

The tests must pass. The checked-in example must print `REFUSED` and exit with
status 1. A production gate evaluation should omit `--now`; that option exists
only for deterministic tests and retrospective review.

## Evidence envelope

Every evidence item, including every negative probe and every
SubjectAccessReview matrix cell, has the same mandatory envelope:

| Field | Meaning |
| --- | --- |
| `id`, `kind` | Unique canonical record identifier and closed evidence type |
| `observed_at` | UTC second at which the fact was observed |
| `source_identity` | Exact identity attributed by the capture system |
| `activation_context_commitment` | Prevents evidence from another release or cluster being spliced in |
| `command_commitment` | SHA-256 commitment to the exact captured input/action |
| `response_commitment` | SHA-256 commitment to the exact captured result |
| `freshness` | Per-kind maximum age and exact `valid_until` |
| `claims` | Kind-specific closed claim object, never a naked boolean |

Bare `true`/`false` values are refused at any depth. Outcomes are explicit
enums such as `authenticated`, `allow`, `deny`, `connection_blocked`, or
`consumed_once`. All commitments use lowercase `sha256:<64 hex>` and the
all-zero sentinel is forbidden. Duplicate JSON object keys are rejected at
parse time, including inside nested evidence claims; the last lexical value
can never silently replace an earlier one.
The complete bundle is bounded to 2 MiB and decoded as strict UTF-8 before
payload traversal, limiting parser allocation and nesting abuse from an
untrusted capture artifact.

Canonical context and route commitments are computed over UTF-8 JSON with
sorted object keys, no insignificant whitespace, and domain separation:

```text
SHA256(ASCII(domain) || 0x00 || canonical_json_bytes)
```

The domains are `accordlock.eks.activation-context.v1` and
`accordlock.eks.route-profile.v1`. Changing one byte in a route profile requires a
new route commitment and therefore a new activation-context commitment on
every evidence item.

## Exact evidence closure

The gate requires all of the following; omission is refusal:

1. A captured Kubernetes server version of at least 1.32 and
   `ServiceAccountTokenAUTHORIZATION_ID` recorded as GA and enabled.
2. One route profile binding the exact EKS cluster ARN, trust domain, API-server
   identity, API DNS name, HTTPS URL and port, canonical resolved socket set,
   API CA, real Kubernetes audience, namespace, ServiceAccount name and UID,
   and target Deployment. The gate recomputes its route commitment.
3. A bound TokenRequest followed by TokenReview. The same canonical JWT AUTHORIZATION_ID,
   `AUTHORIZATION_ID=<uuid>` credential ID, ServiceAccount UID, audience, route, and bearer
   commitment must survive both records. Username and modern ServiceAccount
   groups are exact, and the review must occur inside the bearer lifetime.
4. An authenticated Kubernetes GET against the exact API DNS name, audience,
   bearer, namespace, Deployment path, and route.
5. Three separate broker-management authorities: `secret_lifecycle`,
   `service_account_token`, and `token_review`. Their subjects, effective-RBAC
   commitments, and actual credential-byte commitments are pairwise distinct.
   Executor and webhook subjects are also distinct (as is the activation
   operator), the executor bearer is independently committed, and absence of a
   Kubernetes API credential for the webhook is explicit.
6. One complete normalized effective-RBAC graph for each of those three broker
   authorities. Each graph binds the subject and actual credential to its
   configured RBAC commitment and enumerates Roles, ClusterRoles, RoleBindings,
   ClusterRoleBindings, EKS access entries, and `aws-auth`. The gate requires a
   single exact authorization object/binding, an exact positive allowlist, no
   EKS/IAM alternate path, and refuses wildcard rules, aggregation,
   impersonation, `escalate`, `bind`, RBAC mutation, `pods/exec`, or any extra
   permission. The graph commitment is computed over the normalized graph; it
   is not inferred from probes.
7. The complete, exact dynamic SubjectAccessReview matrix. Secret lifecycle alone may
   create/get/delete the exact bound Secret; token issuance alone may create a
   TokenRequest for the exact ServiceAccount name; token review alone may create
   cluster-scoped `authentication.k8s.io/tokenreviews`; and the executor alone
   may GET/PATCH the exact Deployment. Every management authority has denials
   for both other management operations and Deployment PATCH. Executor and
   webhook cross-operation denials are also mandatory. Missing, duplicate,
   extra, incorrectly scoped, or subject-swapped cells are refused. A legacy
   single `broker` identity or credential cannot pass.
8. A positive webhook invocation attributed to the EKS control plane and a
   negative raw AdmissionReview probe from **every** declared ordinary workload
   zone. Probe UIDs and sources are distinct, no application response may be
   observed, and the boundary mode is identical across positive and negative
   evidence.
9. The exact `admissionregistration.k8s.io/v1` behavior represented as evidence:
   `failurePolicy: Fail`, `matchPolicy: Equivalent`, `NoneOnDryRun`, two-second
   timeout, `UPDATE` only, `apps/v1` namespaced Deployments only, and exact
   namespace/object opt-in selectors.
10. A currently valid webhook certificate chain and DNS validation tied to the
   exact Service DNS and the VWC `caBundle` commitment.
11. A contemporaneous end-to-end mutator inventory tying RBAC, EKS access, IAM,
    and admission-exemption snapshots to exactly one ordinary authorized
    mutator identity and one active bearer. Alternate Deployment-mutator
    credentials are empty and break glass is disabled for activation. This is
    an activation condition, not a claim that EKS can never have administrators;
    any administrative path that can bypass the provenance check makes this
    condition false.
12. One durable AdmissionReview UID consumption with `consumption_count: 1`,
    bound to the exact credential ID and bearer.
13. A provider request whose expected, sent, and webhook-observed commitments
    are identical, whose UID and route match the consumed authorization, and
    whose send time remains inside the bearer validity window.

The gate also checks the chronology GET → provider send → API-server callback →
durable UID consumption. Freshness limits are deliberately short: credential,
request, callback, and consumption evidence is capped at five minutes; route,
RBAC, network, certificate, VWC, and inventory evidence at fifteen minutes;
server-version evidence at one hour. A producer may choose a shorter lifetime,
never a longer one.

## Caller boundary: two honest options

The VWC `caBundle` authenticates the **webhook server to the API server**. It
does not authenticate the API server to the webhook. AdmissionReview fields,
including `userInfo` and UID, remain attacker-controlled data when an ordinary
workload can call the webhook endpoint directly.

Only one of these environment-specific boundary profiles may be claimed:

### API-server mTLS

Use `apiserver_mtls` only where the managed control plane actually supports a
configurable webhook client certificate and the webhook verifies its chain and
identity. The bundle must commit both the observed client certificate and the
platform configuration that makes it authoritative. Do not select this mode
merely because server-side TLS or a `caBundle` exists; generic customer-managed
API-server client authentication must not be assumed on EKS.

### EKS customer-routed or dedicated network enforcement

Use `eks_customer_routed_network` when the webhook is reachable only through a
customer-controlled/dedicated path that admits the observed EKS control-plane
path and blocks ordinary workload sources. The bundle commits the enforcement
configuration, route snapshot, and positive control-plane path. A raw forged
AdmissionReview must then fail from every workload trust zone, not merely from
one convenient test pod. The allowed EKS path is topology-, CNI-, security
group-, and version-specific; a generic diagram or nominal NetworkPolicy is not
evidence.

Both modes require a positive real control-plane callback and negative probes.
The validator checks their closure and freshness; it cannot establish packet
origin, certificate ownership, or control-plane configuration by itself.

## Deliberate non-features

This package deliberately does not:

- discover workload zones or decide that a zone list is complete;
- capture or print bearer tokens, certificate private keys, or command output;
- generate a passing bundle from asserted booleans;
- perform AWS, DNS, socket, TLS, Kubernetes, or PostgreSQL calls;
- install, patch, register, or remove a webhook;
- infer source authenticity from a self-reported `source_identity`;
- make its candidate-validation output a substitute for collector attestation,
  operator approval, or independent red-team review.

A production evidence collector must therefore be a separately reviewed,
least-privilege component with authenticated artifact storage. Its output may
be fed to this gate only after the checked-in sentinel has been replaced by a
new capture ID, real context, non-sentinel commitments, exact raw-artifact
bindings, and complete evidence from the destination environment.
