# `accordlock-enforcement`

This crate contains the narrow EKS orchestration core, but its production entry
point is deliberately **fail-closed**. Its public execution call accepts only a
`DispatchAcquisitionRequest` containing a worker and acquisition ID. Scope is
fixed in `self`; no caller key, claim, transaction, or provider input crosses
this boundary. The deployment template, authority,
destination, credential profile, audience, commitments, trusted time, broker,
and native executor are fixed at trusted bootstrap or reloaded from
transactional state.

## Production readiness blockers

The exact-credential code path requires the modern Kubernetes credential
identifier in `TokenReview.user.extra`, proves equality with JWT `authorization_id`, carries
the ServiceAccount UID and credential ID through state, and requires both at
admission. The memory and PostgreSQL adversarial suites cover substitution,
same-ServiceAccount wrong-AUTHORIZATION_ID, commit ambiguity, and exact recovery. The
`ExactAdmissionCredentialBinding` blocker is therefore closed in code.

The route-confusion blocker is closed in code. One immutable
`EksRouteProfile` commits to the cluster/API identities, DNS/SNI name, pinned
socket, CA set, namespace, Deployment name/UID, attempt ServiceAccount
name/UID, and Kubernetes token audience. Broker, transport, executor, and
orchestrator own structurally equal profiles; orchestration construction
rejects the first differing field before any external operation. Production
no longer reports `UnifiedEksRouteBinding`.

The broker mutation lifecycle is now closed in code. The production broker
port prepares a state-backed operation, consumes an opaque state-issued
authority only after the durable `INTENT -> IN_FLIGHT` transition, performs the
one provider call inside the broker, and retains the exact journal receipt.
At trusted bootstrap, `EksEnforcement::new` issues the unique non-clonable,
store-bound `BrokerJournalCapability` only after all local route, transport and
policy validation succeeds, then keeps it in a private field with no accessor
or `Debug` exposure. Every productive CREATE, TokenRequest, TokenReview,
cleanup and reconciliation begin borrows that capability. Consequently public
raw observation variants, deserialized review claims and legacy-shaped request
constructors are inert outside the trusted enforcement object graph. Cloned
state handles share the one issuer, so a second enforcement composition over
the same handle family fails closed.
Create and delete ambiguity can only obtain GET authority through
`UNKNOWN -> RECONCILE_ONLY`; token ambiguity can never reissue. A delete
acknowledgement proves only uncertainty, so cleanup always follows it with an
authenticated GET and commits retirement only after exact absence. Memory and
PostgreSQL use the same compare-and-set transition model. Production therefore
no longer reports `DurableBrokerLifecycle`.

The durable attempt-facts boundary is now closed in composition. Production
construction no longer accepts an arbitrary `AttemptAuthoritySource` or an
already-built broker. It requires one `S: BrokerJournalState +
EksDestinationRegistryState + Clone`, fixes one tenant/environment `Scope`,
clones that exact state handle into `StateBackedAttemptAuthority<S>`, and
builds `EksCredentialBroker<StateBackedAttemptAuthority<S>, ...>` internally.
`load_current` therefore reloads rooted current facts and rejects revocation,
deadline expiry, authority drift, stale activation, or route mismatch;
`load_frozen_cleanup` succeeds only for the exact immutable broker-journal
lineage. Neither a volatile `DispatchMachine` nor an observed Secret can be
substituted as authority. Production no longer reports
`DurableAttemptFactsRegistry`.

The fixed scope is checked before the private mechanical path asks state for a
claim. A request for another tenant or environment is quarantined before any
broker, executor, or provider work.

Three live deployment/runtime proofs remain. Management credentials are now
split into three pairwise-distinct
operation-bound identities for Secret lifecycle, ServiceAccount TokenRequest,
and TokenReview. Each bearer is issued for one exact route and operation and
cannot be substituted across those boundaries. Live RBAC closure is still an
activation-time evidence requirement, but the former unioned-credential code
path is gone.

The remaining deployment/runtime boundaries are:

- the three configured management identities still need live proof that their
  effective RBAC closures equal the distinct committed scopes;
- the deployed webhook needs an environment-proved caller-origin boundary;
  server TLS alone authenticates only the webhook server;
- the exact Kubernetes API audience must be exercised against the live EKS
  endpoint before the profile is activated.

Production therefore reports exactly `ManagementRbacLiveProof`,
`AuthenticatedWebhookCallerBoundary`, and
`KubernetesApiAudienceLiveProof`. `ManagementRbacLiveProof` is narrower than
the removed unioned-identity defect: it asks for live proof that the three
configured identities and their effective Kubernetes RBAC closures really
match the distinct commitments. The public entry point returns those three
blockers unconditionally and exposes no readiness token or gate setter. The
mechanical sequence below is private, type-checked behind an uninhabited
private proof type, and exercised only by in-crate test doubles; it is not a
claim of complete mediation.

The path is intentionally singular:

1. ask state to select/recover one acquisition-bound `DispatchWork` and import
   that opaque work;
2. prepare the process-local dispatch machine;
3. durably journal the one Secret create as `IN_FLIGHT` before provider I/O;
4. commit its exact UID or reconcile the deterministic Secret name after
   ambiguity, never retrying create;
5. revalidate state, durably journal the one bound `TokenRequest`, and release
   its bearer only after the exact `TOKEN_ISSUED` commit;
6. begin exact durable review before `TokenReview`, then commit authenticated
   or rejected evidence; only the opaque reviewed proof continues;
7. derive the effect binding from state/broker material only;
8. durably commit `ATTEMPT_IN_FLIGHT` from the opaque proof before moving the bearer and one-shot
   attempt authority into `ExclusiveEksExecutor`;
9. record exact effect evidence or quarantine ambiguity;
10. journal one Secret delete, convert its acknowledgement to `UNKNOWN`, use
    GET-only reconciliation until exact absence, and assess credential
    retirement.

No public provider adapter exists. Production construction accepts a fixed
broker configuration, credential source, durable state handle, and
`ExclusiveEksExecutor`; it constructs the only accepted state-backed broker
authority internally. Test doubles live behind private traits compiled inside
this crate's tests. No outcome contains bearer bytes.

After restart, `BrokerArtifactPresent`, `AttemptInFlight` and
`RecoveryNoSend` never re-enter the productive path. State returns opaque
`DispatchRecoveryWork` containing the historical recovery key; enforcement
never reconstructs it from the new scheduler request. It then asks state for
an exact GET-only CREATE reconciliation request, exact cleanup request, or
durable absence proof. Every pre-attempt broker artifact enters
`RECOVERY_NO_SEND`, even after lease expiry; the recovered path has no bearer,
`DispatchImport`,
`AuthorizedProviderAttempt`, or executor call. Once exact absence and the
rooted safe-after bound are durable, state advances only that no-send lineage
to `RECOVERY_RETIRED` and releases its physical reservation. A crash after a
productive `ATTEMPT_IN_FLIGHT` CAS still performs cleanup only and never
asserts no-send.
Exact CREATE absence before TOKEN or review yields the state-derived
`CreationAlreadyAbsent` conclusion and retires without DELETE or a second HTTP
operation. The raw reconciliation observation alone is never sufficient.
Durable Secret absence also authorizes no further HTTP, but it reports
`Pending { safe_after }` until the state-rooted deletion-propagation and clock
uncertainty bound elapses. Even an exact TokenReview rejection recorded after
absence cannot shorten this bound: its durable timestamp does not prove when
the provider observation occurred relative to deletion.

Pre-0014 `CONTROL_BOOTSTRAP_V13` attempts are historical authority only. They
may continue exact frozen audit, admission, terminal and cleanup processing,
but an inert/recovered historical disposition never enters the productive
acquisition branch and cannot construct a `DispatchImport`, bearer,
`AuthorizedProviderAttempt`, or executor call.

The remaining production unblock is:

1. prove the three management identities' effective RBAC closure on the live
   cluster;
2. verify the webhook caller boundary from workload network zones; and
3. bootstrap a bound token and prove its configured audience on the exact live
   API server before activation.

## Deliberate limits

- The journal capability closes the safe-Rust object graph, not a global
  database identity. Independently opening a new PostgreSQL handle/process
  creates a fresh in-process issuer. Bootstrap code and database credentials
  therefore remain explicit TCB; workload-global enforcement requires
  database roles, sessions or stored procedures and is held for the next
  hardening phase.
- `DispatchMachine` remains process-local. A crash loses its local phases even
  though broker mutations and the provider `ATTEMPT_IN_FLIGHT` boundary are
  state-backed. Recovery can burn/close and clean up exact durable lineage, but
  loss of the bearer deliberately prevents resuming the provider effect.
- The broker's `AttemptAuthoritySource` is fixed to the rooted durable
  destination registry. It still cannot reconstruct a dispatch claim, retry
  authority, or journal mutation authority; those remain opaque state-issued
  capabilities.
- `BrokerCredentialSafetyPolicy` is fixed at trusted bootstrap and journaled
  before `TokenRequest`; the broker rejects any policy that differs from its
  configured lifetime and clock-uncertainty bounds before provider I/O.
- There is no live-EKS test here. Production TLS, API-server behavior, RBAC,
  admission mediation, and bound-token invalidation still require an external
  cluster harness.
- After the validated bearer is moved into the executor it is destroyed, so
  post-execution retirement normally uses verified Secret absence plus the
  conservative invalidation delay (at least 60 seconds), not another
  `TokenReview`.
- A `TokenReview` rejection observed before Secret deletion is deliberately
  discarded as retirement evidence. It cannot turn a later GET-absence into
  terminal confirmation; cleanup remains pending until the conservative
  safe-after bound.
- A rejection recorded after deletion is likewise not an early-retirement
  capability. Any lineage that reached credential issuance waits for the full
  deletion-propagation and clock-uncertainty bound.
- `RECOVERY_RETIRED` releases the durable physical reservation only for the
  narrowly proved no-send restart lineage. Productive `ATTEMPT_IN_FLIGHT`,
  ambiguous provider effects, historical v13 attempts and ordinary terminal
  cleanup still have no generic automatic reservation-release transition;
  they remain fail-closed for manual reconciliation.
- The journal prevents unsafe broker mutation resend; it does not claim
  provider-side exactly-once behavior. Any ambiguous create, token issuance,
  provider send, deletion, observation, or durable attempt commit is
  fail-closed. This crate never retries a mutation after ambiguity.
