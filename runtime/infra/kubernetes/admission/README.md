# AccordLock admission webhook — fail-closed deployment candidate

This directory is a **candidate**, not a production deployment and not an
instruction to apply it to a live cluster.  The checked-in base is intentionally
blocked by an invalid image registry, an empty webhook CA bundle, and explicit
non-secret configuration placeholders.  `validate.py` must refuse it.

The resources are JSON because JSON is a Kubernetes manifest format and can be
parsed exactly with Python's standard library.  `kustomization.yaml` composes
them without generators or remote bases.

## Exact scope

The registration is deliberately narrow:

- `admissionregistration.k8s.io/v1` and `AdmissionReview` `v1` only;
- `UPDATE` only;
- `apps/v1` namespaced `Deployment` objects only;
- a namespace must have `accordlock.io/enabled: "true"`;
- the old or new object must match `accordlock.io/protected: "true"` under
  Kubernetes object-selector behavior;
- `failurePolicy: Fail`, `matchPolicy: Equivalent`,
  `sideEffects: NoneOnDryRun`, and a two-second API-server timeout.

This base therefore does **not** authorize initial `CREATE` operations and does
not protect any other Kubernetes kind.  The two routing labels are not
self-protecting.  The cluster's existing authorization/admission policy must
prevent unauthorized users from removing the namespace opt-in or protected
object label.  Expanding operations, resources, selectors, or versions requires
a new review and corresponding conformance tests.

## Objects

The Kustomize package contains:

- the `accordlock-system` namespace with the Restricted Pod Security profile;
- an `accordlock-webhook` ServiceAccount with token automount disabled and no Role,
  ClusterRole, or binding;
- a non-secret ConfigMap containing the runtime profile;
- three hardened webhook replicas, required hostname anti-affinity, preferred
  zone anti-affinity, HTTPS probes, explicit resource bounds, non-root UID/GID,
  a read-only root filesystem, `RuntimeDefault` seccomp, no privilege
  escalation, and all Linux capabilities dropped;
- a ClusterIP HTTPS Service, a `policy/v1` PodDisruptionBudget, and the
  validating webhook registration.

The process receives no Kubernetes API token.  It reads only mounted TLS and
PostgreSQL material and its non-secret environment.  Database migrations are
not performed by this Deployment; schema provisioning and migration are a
separate controlled operation.  Readiness must remain false if the state store
or expected schema is unavailable.

## Secret contract — names and keys only

`secrets.contract.json` is a non-Kubernetes contract and is not a Kustomize
resource.  This prevents the base from creating, blanking, or taking ownership
of operational secrets.  Before a rollout, a separate secrets system must
provision these objects in `accordlock-system`:

| Secret | Required keys | Use |
| --- | --- | --- |
| `accordlock-webhook-server-tls` | `tls.crt`, `tls.key` | HTTPS server identity |
| `accordlock-postgres-auth` | `password` | PostgreSQL password file |
| `accordlock-postgres-ca` | `ca.crt` | PostgreSQL server trust anchor |

The server certificate must be valid for at least
`accordlock-webhook.accordlock-system.svc`; include the fully qualified cluster-domain
name used in the target cluster as well.  `caBundle` must contain base64-encoded
PEM CA material which validates that serving certificate.  It is not a secret,
but it must come from the actual issuance chain and must be rotated coherently
with the serving certificate.

`accordlock-postgres-client-tls` (`tls.crt`, `tls.key`) is an optional contract.  It
is deliberately absent from the base Deployment.  Add its volume and the
runtime's optional client-certificate path variables only if the chosen
PostgreSQL profile supports and requires client certificates; review that as a
separate overlay.  Never place a password, private key, bearer token, connection
URL containing credentials, or secret value in the ConfigMap or Kustomize tree.

The base anticipates the file-oriented remote TLS state contract:

```text
ACCORDLOCK_STATE_POSTGRES_SERVER_NAME
ACCORDLOCK_STATE_POSTGRES_PORT
ACCORDLOCK_STATE_POSTGRES_DATABASE
ACCORDLOCK_STATE_POSTGRES_USER
ACCORDLOCK_STATE_POSTGRES_PASSWORD_PATH
ACCORDLOCK_STATE_POSTGRES_CA_PATH
ACCORDLOCK_STATE_POSTGRES_CONNECT_TIMEOUT_MS
```

It intentionally does not use credential-bearing `ACCORDLOCK_STATE_POSTGRES_URL`.
Do not deploy an image until its exact binary configuration contract matches
these variables and that match is covered by tests.

### Stable observer identity

Admission evidence uses the separately configured
`ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY`, not the serving-certificate bytes.  The
value must be a canonical
`urn:accordlock:observer:<segment>[:<segment>...]` identifier shared by replicas of
this logical webhook service.  It is hashed under a dedicated domain before it
enters the admission authorization.  TLS material is loaded once at startup
and can rotate independently without changing this logical identity.

The observer identifier is non-secret configuration, but changing it is an
authority transition rather than a cosmetic rollout.  Keep it stable during
ordinary certificate renewal.  A deliberate logical-identity rotation must
drain or resolve in-flight operations and activate the matching state/config
transition before new replicas become ready.

## Critical EKS caller-authentication boundary

The `caBundle` makes the Kubernetes API server authenticate the **webhook
server**.  Server-authenticated HTTPS alone does not make the webhook
authenticate the **caller**.  This base does not claim generic API-server mTLS
on managed EKS.

An ordinary workload that can reach the ClusterIP may otherwise submit a forged
`AdmissionReview`.  Fields such as `request.userInfo`, transaction identifiers,
and AUTHORIZATION_IDs are data in that request; they are not substitutes for transport caller
authentication.  Application-level checks cannot repair an unauthenticated
transport premise.

Before describing this deployment as production-safe on EKS, an operator must
provide and independently test at least one supported caller boundary:

1. a source-network restriction that authorizations the relevant EKS control-plane ENI
   path and denies ordinary workload sources, implemented with the cluster's
   verified security-group/CNI/network-policy behavior; or
2. a supported API-server webhook client-authentication mechanism which the
   webhook actually verifies.

The acceptance test must demonstrate both directions: a real API-server
admission call succeeds, and a pod in every ordinary workload trust zone cannot
connect or cannot authenticate.  Record the EKS version, CNI, topology, source
addresses/security groups observed, and negative-test evidence.  Do not infer
this boundary from a diagram or from possession of unpredictable-looking IDs.

Primary platform references:

- [Kubernetes dynamic admission control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Amazon EKS control-plane traffic](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-egress.html)
- [Amazon EKS network-security practices](https://docs.aws.amazon.com/eks/latest/best-practices/network-security.html)

No generic NetworkPolicy is included because the correct API-server source path
is cluster/CNI-specific.  Adding an unverified allow rule would create a false
security claim; adding a generic deny could also block the control plane and the
node-originated probes.  The environment-specific network control and its test
evidence belong in a reviewed deployment overlay.

## Materialization and preflight

Keep this reviewed base immutable.  Copy it to an environment-specific private
deployment repository, then replace only:

1. the image with a registry/repository plus an immutable SHA-256 digest and no
   tag;
2. every `REPLACE_...` non-secret ConfigMap value with the exact destination,
   identity, executor, and PostgreSQL values;
3. `caBundle` with base64-encoded PEM CA material from the server-certificate
   chain;
4. each pod-template revision annotation with the corresponding external
   ConfigMap/Secret version identifier.

The revision annotations are non-secret rollout triggers.  Environment
variables and the process's TLS/PostgreSQL configuration are read at startup;
updating a ConfigMap or Secret object alone is not a completed rotation.

Provision the three required Secret objects out of band.  Verify their names
and key presence without printing their data.  Then run, from the materialized
copy:

```powershell
python .\test_validate.py
python .\validate.py
kubectl kustomize .
```

The first command tests the checker.  The second must print `PASS`.  The third
only renders resources; it does not apply them.  The validator is intentionally
independent of `kubectl`, a live cluster, third-party YAML parsers, and network
access.  It refuses:

- `example.invalid`, mutable tags, tag-plus-digest references, or malformed
  digests;
- an empty, malformed, or non-PEM `caBundle`;
- unresolved configuration placeholders;
- literal Secret resources or literal secret-like environment values;
- RBAC, token automount, privilege regressions, probe downgrades, selector/rule
  broadening, missing resource bounds, or drift in the declared secret contract.

The static preflight does not prove that an image digest is trustworthy, a
certificate is currently valid, a live Secret contains the right material, the
database schema is correct, or the EKS caller boundary exists.  Those are
separate release evidence.

## Safe activation sequence

There is intentionally no deployment script here and no command has been run
against a cluster.  A reviewed operator procedure should, at minimum:

1. verify the image provenance, SBOM, vulnerability report, signature, and exact
   digest;
2. provision and migrate PostgreSQL through a separately authorized job;
3. provision the three required secrets without committing their values;
4. materialize configuration, run the static tests/preflight, and retain the
   rendered output as release evidence;
5. establish and negatively test the EKS caller boundary;
6. deploy Namespace, ServiceAccount, ConfigMap, Deployment, Service, and PDB;
7. wait for three ready endpoints and exercise `/livez`, `/readyz`, and a denied
   out-of-scope request;
8. register the `ValidatingWebhookConfiguration` last;
9. opt in one canary namespace and one canary Deployment before broader labels.

Because `failurePolicy` is `Fail`, a selected Deployment update is denied when
the webhook is unavailable, times out, cannot authenticate its state store, or
returns a transport error.  This is the intended availability tradeoff.  Three
replicas, anti-affinity, and a PDB reduce planned disruption; they do not remove
the PostgreSQL dependency, correlated failures, certificate expiry, or network
partition risk.  Rollback and break-glass procedures must preserve an auditable
authority boundary and must be exercised before production activation.
