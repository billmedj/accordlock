# AccordLock dispatch reference machine

This crate is a deterministic, in-memory reference machine for the security
transitions between authorization consumption and an external effect. It exists to
make race, expiry, fencing, credential-loss, and ambiguous-result rules
executable before they are implemented in PostgreSQL and Kubernetes.

It is not a dispatcher, credential broker, executor, database adapter, or proof
of crash safety. In particular, it cannot stop a stale process from using a
credential that it already possesses. Production claims require durable
transactions, exclusive credential paths, destination-side controls, fault
injection, and independent review.

The production-facing import path is acquisition-backed. State selects one
`DispatchWork` from a server-scoped `DispatchAcquisitionRequest`; the bridge can
create `DispatchImport` only by consuming that work. The import retains the
non-serializable `DispatchAcquisitionAuthority`, and every pre-attempt state
check borrows that same authority. It derives owner, physical route, authorization and
control lineage, commitments, trusted times, and deadline from the opaque work.
There is no productive import from a claim token, caller key, or naked
`DispatchSnapshot`.

The bridge revalidates the exact acquisition before bound-object creation and
before token issuance. TokenReview is durably journaled through a one-shot I/O
authority; only the resulting non-clonable `ReviewedDispatchCredential` can
cross the final attempt boundary. A returned token
after revocation, authority change, or deadline failure is retained only for
invalidation and never becomes `CredentialReady`. Immediately before the
provider attempt, `authorize_provider_attempt_from_state` consumes the import
and opaque review proof and asks state to commit `ATTEMPT_IN_FLIGHT`. That state
commit is the durable linearization point. Only after it succeeds does the
local machine enter `Executing` and return a non-clonable
`AuthorizedProviderAttempt`. It retains only the stable claim token plus the
committed acquisition tuple (ID, global lease fence, worker, acquisition time,
lease, deadline, review and rooted EKS profile facts). It never reconstructs a
live lease from the stable token. A repeated or ambiguous mark returns no execution
authority. Zero or multiple matching destination registrations fail closed.
The API server identity is nevertheless a trusted registration premise; the
bridge does not discover or attest it.

This bridge does not make the in-memory machine a production transaction
coordinator. The state snapshot transaction, the local machine transition, and
the external provider call are separate operations. It provides no external
exactly-once guarantee, provider-side fence, high-availability takeover,
terminal-state persistence, crash recovery, or automated reconciliation. The
reference `InMemoryStore` only simulates the claim protocol and is not durable;
production durability depends on the PostgreSQL claim and
`ATTEMPT_IN_FLIGHT` records. Exact provider success remains a separate
authenticated observation and is never inferred from authorization.

A claim commits before local route and projection derivation completes. If
that local import then fails, the claim is intentionally not reconstructed or
retried. Safety is preserved, but liveness requires manual investigation.

Crash recovery can use only the opaque historical acquisition key selected by
state to close any pre-attempt CREATE, TOKEN, or review artifact as durable
`RECOVERY_NO_SEND` and return an inert `RecoveredAttemptCommit`. The close
remains valid after acquisition lease expiry because it is frozen cleanup, not
a productive lease revalidation. The type contains only audit acquisition
facts and has no conversion to `AuthorizedProviderAttempt`; without the
in-process bearer, recovery can reconcile or clean up but cannot resume the
provider effect. After state-authenticated non-creation or Secret retirement,
state alone may advance the claim to `RECOVERY_RETIRED` and release its
reservation.

The current machine enforces these local invariants:

- one active logical owner for each canonical physical resource identity;
- at most one live credential reservation for a physical resource;
- monotone fencing tokens and rejection of stale lease holders;
- monotone trusted time and bounded dispatch deadlines;
- exact authority equality before preparation and final release;
- immutable template, logical-operation, command, and provider-wire commitments
  imported at consumption and retained through final effect classification;
- a bound-object observation cannot select new command or provider-wire
  commitments after consumption;
- credential subject, audience, bound-object UID, digest, and lifetime equality
  with the prepared execution profile, including a lower `not_before` bound at
  issuance start minus configured clock uncertainty;
- one imported authorization `authorization_id`, canonical authorization hash, and consumption-receipt
  commitment per dispatch lifecycle, with replay under a new transaction
  rejected;
- no retry after unknown credential issuance or ambiguous effect release;
- no `EXECUTED` classification from the pre-release `EffectBinding` alone;
  provider success and exact reconciliation require a fresh exact-effect
  observation;
- exact-effect evidence names the transaction and canonical physical resource,
  repeats the complete command, wire, RBAC, and token binding, and contains
  non-zero authenticated-response and canonical-post-state commitments;
- the observed resource UID must equal the registered physical UID, the opaque
  resource version must be nonempty, and the observation time must be strictly
  newer than the provider-attempt or reconciliation start and no later than the
  trusted transition time;
- the observer identifier uses a restricted lower-case canonical form and is
  accompanied by a non-zero authentication-context commitment;
- a domain-separated canonical commitment to accepted exact-effect evidence is
  retained in the lifecycle and exposed through `effect_evidence_snapshot`;
- reservation retention until a credential is invalidated and safely expired.

Time validation is transactional at the oracle boundary. A rejected call does
not advance the global high-water mark unless that call deliberately changes
the lifecycle, such as cancelling release after an authority or deadline
failure. An unknown transaction carrying an arbitrary future timestamp cannot
poison later valid transitions.

The local create model has distinct intent and in-flight phases. A production
adapter must persist equivalent state before relying on crash recovery. Within
the model, lease-loss recovery can only reconcile the deterministic object
name; it cannot authorize a second create request. Credential issuance also
rechecks durable authority and deadline, and a late or invalid token response
enters invalidation rather than becoming releasable.

The machine now refuses to begin the external bound-object create after a
relevant authority change, emergency stop, or deadline. A fenced claim is bound
to its transaction, physical resource, template, and operation. A valid
credential for another subject, audience, or bound object enters invalidation,
and a different operation, command, or provider-wire commitment cannot cross
`EFFECT_RELEASED` or be classified as the successful effect.

The machine deliberately refuses to infer “no prior effect” merely from token
invalidation and expiry. Those facts prevent future use but do not prove that a
past provider call had no effect. Until an authenticated, operation-bound
destination-observation profile exists, an unestablished no-effect result goes
to manual resolution.

Two premises remain outside this oracle. Every `now` argument must come from a
trusted monotone database or service clock, and every `PhysicalResourceId` must
be derived from authenticated provider identity rather than logical aliases.
The machine rejects malformed components and time rollback, but its Rust API
cannot establish either external premise by itself.

Provider success and exact-effect reconciliation use the same
`ExactEffectEvidence` proof shape because both establish the same post-state
predicate. The retained evidence hash commits, with length-delimited fields, to
the route, physical identity, complete effect binding, response, post-state,
observed UID and resource version, time, observer identity, and observer
authentication context. Wrong-route, stale, future, empty, and binding-swapped
evidence is rejected without advancing the phase or populating the audit
snapshot.

Bound-object matching, pre-issuance cleanup, and credential invalidation remain
separately typed and commitment-bound. Cleanup evidence names the transaction,
physical destination, deterministic object, server UID when known, authorization
commitments, and token digest when one was returned. Evidence for another route
is rejected. These types prevent accidental or stale cross-routing, but the
oracle still assumes their caller authenticated the relevant provider response,
post-state projection, observer identity, and authentication context. A
non-zero commitment does not establish payload truth by itself.
