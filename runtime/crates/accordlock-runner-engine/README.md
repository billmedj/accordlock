# accordlock-runner-engine

This crate is the fail-closed composition root for an AccordLock execution
worker. It joins four already-separated boundaries without merging authority:

1. a short-lived, credential-free `RunnerDispatch` is validated against one
   exact environment profile and worker enrollment;
2. an injected channel authenticator binds the live caller to the exact
   domain-separated dispatch digest;
3. read-only GitHub, ECR and Kubernetes adapters collect four evidence
   assertions through worker-owned authenticated transports;
4. the execution bridge reconstructs the exact EKS proposal and authorization binding.

Provider credentials, TLS state, GitHub tokens, AWS SigV4 material and
Kubernetes bearer credentials remain inside the injected transports. They are
not fields of any dispatch, authentication result, engine result or
serializable execution-worker protocol object.

`trusted_provider_sources_for_profile` derives every repository, workflow,
account, region, cluster, namespace, Deployment and container route from the
validated environment profile. Callers inject only the fixed HTTPS endpoints,
bounded response size and authenticated transport capabilities; they cannot
substitute the protected target fields independently of the profile.

## Production execution status

The engine exposes no shell, generic network operation or provider mutation
interface. `prepare_production_deployment` always returns a
`ReadinessBlockedDeployment` carrying the blockers exported by
`accordlock-enforcement`. It performs no EKS write and has no readiness
override. The existing native EKS enforcement path remains the only place an
external action may eventually occur after its live RBAC, authenticated webhook
caller, and Kubernetes audience checks become mechanically activatable.

`run_local_deployment_exhibit` is the account-free integration path for this
boundary. It requires the exact authorized Deployment snapshot, verifies its
committed projection hash and preconditions, and derives the compact JSON Patch
with `accordlock-k8s`, the request builder used by the native executor. The
transaction and authorization identifiers are committed before patch
derivation. A successful exhibit consumes the normal replay reservation and
returns `NotSent`; it is not a reusable production preview and has no
transport, credential, or readiness override.

The exhibit does not create an `AuthorizedProviderAttempt`, obtain a brokered
bearer, instantiate a `NativeEksTransport`, or mutate Kubernetes. Those remain
separate live gates together with destination admission, bypass denial, RBAC,
token audience, and post-state evidence.

This is a real observation and preparation root, not a simulated cloud client.
Network implementations and credentials must be supplied by worker-side
transport traits; this crate never fabricates either.

Trusted time is injected at bootstrap and sampled inside every public
operation. Request callers cannot choose the time used to validate profile,
enrollment, dispatch or authorization windows.

## Runner state

`EnterpriseRunner::new` keeps a bounded in-memory state implementation for
unit tests and account-free evaluation. `EnterpriseRunner::new_durable` accepts
an explicitly opened `SqliteRunnerStateStore` for a real single-host worker.
The object-safe `RunnerStateStore` contract also enables a separately reviewed
deployment adapter without changing runner protocol objects.

The SQLite profile atomically retains:

- a monotonic trusted-time high-water mark;
- independent dispatch and action-approval replay namespaces;
- opaque pending and committed reservation lifecycles; and
- one persisted hard capacity shared by every process opening that database.

Only digests, opaque reservation IDs, lifecycle values and bounded metadata are
stored. A reservation is inserted before provider collection or preparation.
A known pre-effect connector failure releases its exact pending row. Commit is
irreversible. A crash, unavailable commit result or failed release leaves a
pending row that blocks replay after restart. The store never guesses that an
ambiguous delivery had no effect. Committed rows are retained through their
verified dispatch or approval replay window and may then be pruned atomically;
pending rows are never removed by time-based collection.

SQLite is a single-host durability profile, not a distributed consensus or HA
claim. Do not place its files on a network filesystem or share one environment
between hosts. A deployed multi-host runner still requires a reviewed
linearizable state service, backup/restore evidence and the existing transactional
authorization-consumption boundaries before any live external action.
