# Bounded safety models

`AuthorizationLifecycle.tla` is a small, finite model of the local candidate's authorization
lifecycle. It covers issuance under an authority epoch, clock advancement,
authority rotation, eligible consumption, rejection after an epoch mismatch or
expiry, and rejection of replay after consumption. The consumption deadline is
exclusive: consumption is allowed only when `now < consumeBefore`, matching the
Rust authorization verifier. `Issue` is enabled only when it can create a nonempty
initial validity interval, and the model records `issuedAt` to check that fact.

The checked invariants are:

- an authorization is consumed at most once;
- every issued authorization had `issuedAt < consumeBefore` when created;
- receipt and outbox creation are atomic with consumption;
- a successful consumption used the epoch stamped on the authorization;
- no consumption effect exists before successful consumption.

`DispatchClaim.tla` is a separate bounded model of the transition from one
consumed authorization to one dispatch claim and then to one `ATTEMPT_IN_FLIGHT`
authority. It allows the raw clock to move both forward and backward. An
exactly routed, authenticated request with a current clock sample records that
sample in a persistent high-water mark, including when it is rejected at the
effective dispatch or lease boundary. `DispatchDeadline` abstracts the frozen
non-lease bound in the consumption receipt: the minimum induced by the signed
authorization lifetime, maximum dispatch delay, profile cap, and immutable dependency
expiries. A sample below the high-water mark is rejected as a rollback. It is
not clamped and accepted. Unknown identities, wrong claim owners, conflicting
claims, and misrouted tokens are rejected without changing the high-water mark.

The dispatch-claim invariants check:

- at most one successful claim;
- at most one attempt authority;
- no attempt authority before a matching claim;
- the high-water mark never decreases and covers every accepted authenticated
  clock sample;
- identity or route rejection cannot advance the high-water mark;
- rollback rejection creates neither a claim nor an attempt authority;
- after an authenticated observation of the exclusive effective dispatch or
  lease boundary, a later clock rollback cannot create a claim or attempt
  authority.

`PhysicalReservation.tla` isolates the v1 physical-resource reservation rule.
Its bounded universe contains three transactions and two physical resources;
two transactions deliberately target the same resource. Reservation and claim
creation are one abstract atomic transition. The model then explores attempt
start, clock advancement beyond the lease, rejection of competing claims, and
loss of volatile worker state. There is deliberately no release, expiry
takeover, or worker takeover transition.

The physical-reservation invariants check:

- every claim has the exact physical reservation and every reservation has its
  originating claim;
- two transactions targeting one physical resource cannot both claim it;
- claim fences are positive and distinct;
- once a resource has a first owner, its reservation is never removed or
  transferred;
- worker loss and lease expiry retain that reservation.

`AdmissionAuthorization.tla` isolates the durable one-shot admission boundary.
An admissible request is bound to the active transaction, physical resource,
claim, fence, provider-request commitment, old/new object commitments, and
executor/observer identity commitments. Its full record is the model's
collision-free symbolic request commitment. The model explores exact recovery,
same-UID mutation of each evidence field, UID substitution, transaction/claim/
fence/resource/provider mismatch, authority rotation, grant revocation, and
deadline expiry.

"One-shot" here means one durable authorization write for each admission UID,
transaction, claim, fence, and provider-request commitment. It does not mean
that only one API call can succeed: an exact retry may recover the previously
written row without writing a second authorization. Recovery rechecks the exact
request and the current authority, grant, and exclusive deadline. A stale or
mutated retry is rejected.

The admission invariants check:

- the write count and persisted authorization agree, with at most one durable
  write per UID;
- persisted rows remain bound to the modeled claim, fence, physical resource,
  and provider-request commitment;
- transaction, claim, fence, and provider-request uniqueness indexes point to
  the same authorization;
- no two durable authorizations alias any of those unique identities;
- every successful recovery was current, exact, and based on an existing
  durable row;
- rejected attempts do not create authorization state.

`BrokerJournal.tla` models the three one-shot EKS broker mutations: immutable
Secret create, bound `TokenRequest`, and exact-UID Secret delete. An intent is
durable before `IN_FLIGHT` creates a single volatile send authority. A crash
from `IN_FLIGHT` records `UNKNOWN` and destroys that authority. Create and
delete can then enter `RECONCILE_ONLY`, whose reconstructable authority authorizations
authenticated GET only. Token issuance has neither reconciliation nor a resend
path. A delete HTTP acknowledgement is deliberately only `UNKNOWN`; durable
absence must be established by GET.

The model makes `reconciliation_count` an explicit GET-authority generation.
Create absence and exact-UID delete presence each consume one compare-and-swap
generation, journal the last outcome/evidence/time, and return the next GET-only
generation. A lost response can recover that generation only when the stored
count is exactly the expected count plus one and the pending outcome/evidence
also match. An older generation or different evidence is rejected. Bounded
paths authorization repeated pending observations followed later by matching create
or absent delete. A conflicting create, conflicting delete, or wrong delete UID
is terminal.

The broker-journal invariants check:

- at most one mutation send per operation and no send before durable
  `IN_FLIGHT`;
- no mutation authority survives a crash or reappears from GET-only
  reconciliation;
- token issuance is never reissued or reconciled;
- each reconciliation generation wins at most one pending CAS, while an exact
  commit-ambiguous recovery does not increment the count again;
- accepted authenticated clock samples are covered by a monotone durable
  high-water mark, while rollback rejection is read-only;
- pending outcome/evidence/time fields agree with their operation and count;
- `COMMITTED` contains only matching create, issued token, or absent delete,
  while `TERMINAL` contains only the corresponding conflict outcomes;
- late create-matching and delete-absent markers can be set only after their
  respective pending observation.

`TerminalRetirement.tla` models the v12 boundary that converts an exact
`ATTEMPT_IN_FLIGHT` claim into immutable terminal history and releases its
active physical reservation. Its bounded universe starts with two active
attempts on different resources. A third transaction targets the first
resource and can reclaim it only after the first owner terminalizes, so TLC
explores release/reclaim interleavings without allowing overlap.

The model treats commitments and signatures as collision-free symbolic values.
Exact registry material may be registered only when its full commitment,
schema, and rooted activation agree with the historical v11 activation. The
successful evidence symbol denotes two independently signed, canonical,
purpose-separated envelopes: exact effect and credential retirement. There is
no successful `NO_EFFECT` symbol. Wrong routing, registry, envelope, signature,
purpose, durable context, schema, or recovery tuple is rejected before the
trusted clock high-water mark can move.

The final v12 DELETE-absence action atomically creates its exact append-only
observation and trusted `observed_at`. One modeled attempt represents a legacy
pre-v12 committed delete: it can never receive that observation, which makes
the absence of backfill explicit. DELETE acknowledgement, GET alone, and a
missing observation are only rejection variants. Once the two envelopes and
the state-derived context authenticate, a future-evidence rejection persists
the trusted clock sample; rollback remains read-only. A successful commit
atomically writes terminal history, retains the claim fence, changes the claim
to `TERMINAL`, and releases the reservation. A lost response changes none of
those facts, and only the byte-exact symbolic retry can recover it without a
second write. Restart leaves durable safety state intact.

The terminal-retirement invariants check:

- registered verifier material is the exact schema-v1 material whose full
  commitment was already committed by the matching v11 activation;
- deletion observations and terminal records are append-only and exact, and a
  legacy DELETE row is never backfilled;
- terminalization requires intact durable lineage, the exact deletion
  observation, the rooted registry, and both purpose-separated signatures;
- tampered or schema-drifted durable input fails closed;
- `ATTEMPT_IN_FLIGHT -> TERMINAL`, history creation, fence retention, and
  reservation release are atomic;
- a concurrent claimant can reuse a released physical resource but can never
  overlap an active prior owner;
- trusted time accepted by success or authenticated future rejection is
  covered by the monotone high-water mark, while unauthenticated, mismatched,
  and rollback rejections cannot poison it;
- a commit-ambiguous response already has the complete atomic result, terminal
  writes occur once, and only the exact terminal ID and envelope tuple recover.

`DurableControlQueue.tla` models the v13 signature-authenticated submission
intake and durable control worker. Fresh acceptance atomically consumes the
nonce, stores the immutable payload submission and first-wire audit marker,
creates the `ACCEPTED` status projection/event, and enqueues READY `EVALUATE`
work. A lost commit response returns `OutcomeUnknown` with that same complete
durable result. Exact historical recovery revalidates through the frozen
verifier/binding, returns only an inert recovered reference, and deliberately
ignores current expiry, HWM rollback, and verifier rotation/removal. An
equivalent JSON wire representation may therefore recover the same signed
payload commitment without replacing the first-wire audit value.

The queue advances through `EVALUATE -> ISSUE -> CONSUME -> DONE`. READY work
or an expired lease may be claimed under an append-only claim ID and globally
increasing fence. A returned claim yields the only current opaque lease token;
a lost claim response must recover the exact active ID, while takeover leaves
old claims and volatile tokens unable to authorize the new fence. Evaluator,
issuer, and consumer are distinct roles and may claim only their matching
phase; evaluation work carries the full current authority vector symbolically.
Claim terminal history has three disjoint variants. An exact retry of a
successfully committed phase returns inert `PhaseCompleted`; a pre-kernel deny
returns the immutable `DecisionFinalized` decision and never a phase-completion
row; a post-decision ISSUE/CONSUME failure returns inert `WorkFinalized` and
never phase success. All three paths ignore current time/HWM/authority and
reconstruct no lease or execution capability. EVALUATE and ISSUE
`PhaseCompleted` receipts expose no ConsumeKey identity; only successful
CONSUME carries the exact ConsumeKey identity needed for historical
dispatch/outbox recovery.

Evaluation is one atomic commit of the signed evaluation, control decision,
inert `PhaseCompleted` receipt, revision-2 status/event, and next queue phase.
There is no durable unlinked-decision gap. A lost response observes that same
complete state, and its exact claim retry recovers only the completed receipt
without checking or advancing the clock/HWM. An `ALLOW` decision creates the
explicit revision-2 `AUTHORIZED` projection and READY `ISSUE` work; it never
leaves the projection at `ACCEPTED`. From `AUTHORIZED`, the next durable status
is either revision-3 `AUTHORIZATION_ISSUED` or revision-3 `FAILED_CLOSED`. A later
CONSUME result is revision 4 and first requires the `AUTHORIZATION_ISSUED` event.
Pre-kernel authority change has
deterministic priority over signed-ingress expiry; either atomically finalizes
a deny with no kernel outcome, evaluation nonce, signed evaluation, or selected
grant. Its claim history is `DecisionFinalized`, never `PhaseCompleted`.
Issuance is instead one atomic commit of authorization, control link, status,
and READY `CONSUME` work. Consumption is one atomic commit of receipt/outbox,
control link, `DISPATCH_PENDING`, and DONE. A lost response from either atomic
commit is only `OutcomeUnknown`; exact durable recovery is historical and inert.
If ISSUE or CONSUME becomes impossible before its atomic artifact exists, the
work becomes `FAILED_CLOSED` without rewriting the existing kernel/control
decision. Its immutable reason and origin phase distinguish authority change,
ingress expiry, authorization expiry, grant loss, and CONSUME-only dispatch-window
expiry. Restart removes only volatile
lease/evaluation delivery; exact recovery or expired-lease takeover resumes
eligible durable work.

The runtime performs claim creation and its preflight finalization in one SQL
transaction. The model conservatively separates those two actions so it can
explore a transient lease, but every effect action repeats the frozen boundary
conditions: once a preflight failure is applicable, no kernel, authorization, or
consumption action can use that lease. The modeled terminal commit and recovery
variant still match the runtime atomically.

The v13 invariants check:

- nonce consumption, submission, status/event, and initial READY work are
  all-or-nothing, including after an unknown commit outcome;
- recovered submission references are historical and inert, first-wire audit
  data is immutable, and bad signatures or payload conflicts cannot consume a
  second nonce or create partial work;
- authenticated clock samples are covered by a monotone HWM, rollback is
  rejected, and historical submission recovery does not depend on current
  time or current verifier state;
- claim records are append-only, IDs/fences are globally fresh in the bounded
  domain, exactly one current lease matches the queue, and old fences cannot
  authorize after takeover;
- evaluator, issuer, and consumer claims are role-separated, and the active
  evaluation lease is bound to its captured current authority vector;
- `PhaseCompleted`, `DecisionFinalized`, and `WorkFinalized` histories are
  append-only, unique, pairwise disjoint by claim, and recover through distinct
  clock/currentness-inert variants; only successful CONSUME carries a
  ConsumeKey identity;
- authority change wins over expiry before kernel execution; both paths end in
  `CONTROL_DENIED` without a signed kernel decision or downstream effect, while
  a corrupted frozen ingress row creates no business denial or capability;
- the signed kernel outcome remains distinct from the control outcome:
  kernel deny and an absent current grant map to deny, while exactly one
  server-selected current grant maps to allow;
- the normal runtime profile admits only zero or one current grant. Multiple
  current grants are structural persistence corruption: they are rejected
  before a control decision and are not modeled as a business `MANUAL` branch;
- the evaluation nonce is deterministic and server-derived, no request grant
  exists in the model, and only the one-current-grant branch selects a grant;
- an allowed linked decision is projected as revision-2 `AUTHORIZED`, whose
  only revision-3 successors are `AUTHORIZATION_ISSUED` or `FAILED_CLOSED`; revision 4
  requires the durable authorization link first;
- signed evaluation, control decision, completed EVALUATE claim, revision-2
  status/event, and next queue phase are one all-or-nothing commit; its exact
  completed-claim retry is historical, clock-inert, and never relinks work;
- authorization+issuance-link and receipt/outbox+consumption-link are each
  all-or-nothing with their exact phase/status CAS, including after an unknown
  response;
- post-decision failed-closed work retains the original decision and origin
  phase, writes no consumption, and distinguishes authorization expiry in ISSUE with
  no authorization from authorization expiry in CONSUME with an already-linked authorization;
- `DISPATCH_WINDOW_EXPIRED` exists only after a linked authorization in CONSUME and is
  recovered as `WorkFinalized`, never as phase success;
- deny decisions terminate without issuance, while control allow alone reaches
  `AUTHORIZED`, issuance, consumption, and `DISPATCH_PENDING`.

`DurableDispatchAcquisition.tla` models the v14 boundary after successful v13
CONSUME. Its two already-completed v13 roots form an ordered durable outbox and
deliberately target the same physical EKS resource. A v13 `PhaseCompleted`
receipt is only an inert prerequisite: it is never reconstructed as v14
dispatch authority.

Acquisition is server-selected. The request supplies a worker and a fresh retry
identity, but no queue item, stable claim ID, or physical resource. The server
chooses the oldest item across the requested Scope's union of actionable
productive and historical-recovery candidates; neither class has priority over
the other. The
first acquisition creates one
immutable stable dispatch claim and one append-only lease generation; an
expired generation may be taken over by appending a higher globally fresh lease
fence without rewriting the stable claim identity or fence. Only the latest,
live, artifact-free generation can yield or exactly recover volatile authority.
Lost acquisition commits retain their complete durable generation, while
expired and superseded retries are inert and artifact-bearing histories are
quarantined rather than reminted.

Both the dispatch-scope and ingress-scope durable clocks are sampled together.
An authenticated sample advances both high-water marks, while a raw sample
below either side is rejected without mutation. Before acquisition, a
server-selected root whose dispatch deadline has durably expired, whose
authority changed, or whose grant was revoked receives an exact inert queue
disposition. A disposition has priority-ordered reasons, is exactly recoverable
after a lost response, and releases an existing stable claim's physical
reservation so later work on the shared resource can progress.

The productive path binds every downstream fact to the latest acquisition and
orders the one-shot boundaries as broker CREATE, broker TOKEN, credential-review
begin and terminal result, then provider `ATTEMPT_IN_FLIGHT`. Credential review
has a distinct volatile I/O authority. Its authenticated durable result may
reconstruct only the exact review proof, including after restart; that proof is
then consumed by the separate attempt CAS. A rejected review cannot create an
attempt, and a broker intent already prevents lease takeover or generic
acquisition-authority reconstruction.

On any later scheduling call, including before or after process restart, the
server can instead return `RECOVERY_REQUIRED` for the oldest actionable
historical item without requiring the caller to know its stable claim,
acquisition UUID, or original worker. The implementation's recovery work value
is opaque; the model represents it as a collision-free symbolic selector
derived from the latest durable acquisition. Discovery is read-only: the new
request identity remains unbound, and no lease generation, disposition, clock
sample, or authority grant is created. Drained attempt cleanup and a
`RECOVERY_NO_SEND` item that is not yet retirement-ready are excluded from the
actionable set, and `NO_WORK` is authorized only when neither acquisition nor
useful recovery work exists.

An exact latest broker-bearing claim with no attempt, admission, or terminal
fact can be closed as explicit `RECOVERY_NO_SEND`, even while a live worker is
racing to commit the attempt boundary; the two claim CAS operations are
mutually exclusive. The closure grants no productive capability and
deliberately retains the physical reservation. Normal retirement requires an
exact durable `DELETE_ABSENT` observation and a rooted propagation delay. The
derived safe-after bound is persisted immutably, retirement cannot occur before
it, and the retiring CAS advances both high-water marks before changing the
claim to `RECOVERY_RETIRED` and releasing the reservation. A distinct
no-credential profile covers an uncertain CREATE reconciled as
`CREATE_ABSENT` when no TOKEN, review, attempt, admission, terminal, or cleanup
exists. Because that history proves that no credential was created, it retires
directly at the frozen GET observation without DELETE or propagation delay.

The v14 invariants check:

- completed v13 roots remain prerequisites only, stable claim identity is
  immutable, and append-only acquisition IDs and lease fences stay fresh;
- FIFO server selection, exact inert dispositions, and exclusive reservation
  of the shared physical resource hold across takeover, closure, retirement,
  and later acquisition;
- both high-water marks are monotone and cover every accepted acquisition,
  cleanup, disposition, and retirement clock sample;
- authority responses are exact, latest, current, live, and artifact-free,
  while unknown, inert, quarantined, rollback, no-work, and recovery-required
  responses mint no authority;
- recovery discovery selects the oldest actionable durable history and is
  byte-inert, and scheduling exposes only work with a useful next transition;
- broker, review, admission, and attempt facts bind the latest acquisition,
  their one-shot CAS counts and ordering hold, and provider attempt consumes
  only the latest review-authenticated generation;
- `RECOVERY_NO_SEND` retains the reservation and cannot contain an attempt,
  while `RECOVERY_RETIRED` is reached only through the immutable delayed
  `DELETE_ABSENT` profile or the separate `CREATE_ABSENT` no-credential profile;
- cleanup and restart reconstruct no productive mutation authority, and stale
  authority copies cannot produce effects after takeover.

These are engineering models, not proofs of the Rust, PostgreSQL, or Kubernetes
implementations. The models use atomic abstract transitions. They do not model
SQL statements or isolation, database crash recovery, process crash timing,
network partitions, commit ambiguity, Kubernetes retries or persistence,
signatures, SHA-256, hash collisions, token parsing, provider behavior, or an
API server. `PhysicalReservation.tla` models loss of volatile worker state, not
the mechanism by which PostgreSQL survives a crash. `AdmissionAuthorization.tla`
assumes a pre-existing exact `ATTEMPT_IN_FLIGHT` claim and reservation; it does
not compose all earlier models into one proof. `BrokerJournal.tla` abstracts
transaction isolation and commitments symbolically; it does not prove that a
real response or GET observation is authentic, that an exact UID is collision
free, or that a cleanup caller has the required lineage/route/UID. The mapping
from an "exactly
routed, authenticated request" to concrete production authentication and
database constraints remains an implementation and review obligation.
`TerminalRetirement.tla` does not compose the earlier models into one proof and
does not prove SHA-256 collision resistance, Ed25519, canonical CBOR, SQL
isolation, PostgreSQL foreign keys/triggers, or that production rows match the
symbolic durable lineage. Its corruption actions represent a detected invalid
read; they are not a model of an attacker bypassing PostgreSQL immutability.
`DurableControlQueue.tla` contains one submission/nonce and three fixed-role
workers. It
does not prove multi-submission scheduling, fairness, liveness, starvation
freedom, SQL isolation, database recovery, cryptography, hash collision
resistance, external kernel determinism, authority/grant correctness, or the
Rust capability boundary. Claim IDs and global fences are separate domains in
the implementation; the bounded model aliases them to one fresh natural-number
namespace to shrink the bounded state space while preserving uniqueness and
stale-token checks. The queue actions are atomic abstractions of database
transactions, not a proof that their SQL implementation has those atomicity
properties.
The complete `AuthorityVector` is one collision-free symbolic value in this
model; its concrete fields and comparison code are not modeled.
The checked normal profile assumes the database mono-grant invariant (zero or
one current grant). A multiple-current-grant row set is structural corruption
handled by runtime validation before decision persistence; it is intentionally
outside `Spec`, rather than represented as an executable manual-resolution
state or as a partially written decision.
`DurableDispatchAcquisition.tla` fixes two ordered roots on one shared physical
resource, two workers, at most three acquisition identities, a finite clock,
and one-tick leases and retirement delay in the checked configuration. It does
allow at most two simultaneously held authority copies and three durable
authority grants per acquisition. The third grant is the minimum bound that
still explores two concurrent copies before restart and, in a separate trace,
two reconstructed copies after restart; a fourth grant would only repeat that
same copy race with a higher audit serial under the one-tick lease bound.
The configuration declares acquisition IDs and workers as separate, disjoint
finite model-value sets; the ordered integer queue `Items` is a third domain.
The model does not use a checker-level permutation set. Instead, actions that
durably introduce a request identity or worker apply exact
alpha-canonicalization. An unused, append-only request ID is represented by a
single `CHOOSE`-selected unused value. A durable acquisition or disposition may
reuse any persisted worker or introduce
one representative of the unseen workers; recovery keeps using the worker
already bound into its durable record. Because the model compares these opaque
names only for equality, this selects one representative of each fresh-name
orbit without changing the configured safety verdict. It does quotient raw
name-labelled traces and is not a liveness or named-trace equivalence claim.
The model does not compose the complete v13 queue, broker-journal internals,
admission, terminal evidence, or PostgreSQL implementation into one proof.
Stable IDs, commitments, authenticated observations, broker/review evidence,
and the opaque recovery selector are collision-free symbolic values. The model
does not prove Rust type opacity or capability custody, SQL
selection/pagination, transaction isolation, database constraints or
privileges, real clock behavior, provider
authentication, cleanup routing, fairness, liveness, or starvation freedom.

`VIEW SafetyView` is a fail-closed quotient for the 26 configured safety
invariants. An ill-typed state maps to `<<FALSE>>`. A well-typed state retains
current clock/high-water facts; the future-relevant claim fields; acquisition
tuples without their hidden worker; `nextLeaseFence`; active artifact facts or
the smaller retired-artifact view; queue-disposition item/request-ID indexes;
authority-grant counts, held copies, and review-I/O counts only while they can
still affect a future transition; review proofs; restart count; and the 23
Boolean entries of `SafetyProofVector`.

The view projects the raw diagnostic observation, append-only clock histories,
receipt metadata, workers, and immutable audit/proof witnesses. Several
projected recoveries therefore become stuttering steps in the quotient. TLC
fingerprints a successor before checking its invariants, so simply dropping
those witnesses could hide a first bad state behind an earlier good state.
`SafetyProofVector` instead makes every violation that depends on projected
data fingerprint differently. Beyond the outer `TypeOK` guard,
`ServerSelectionIsFIFO` and `RestartRetainsDurableAcquisitionState`, the two
remaining configured invariants not in that vector, are functions of fields
retained directly by the view. This is an exact quotient for the configured
safety verdict, not for raw trace identity, liveness, branch counts, or a future
property that inspects projected fields.

## Reproducible invocation

The repository pins TLC/TLA+ tools v1.7.4 by SHA-256 in
`scripts/fetch_tla2tools.py`. Fetching is explicit because a verification run
must not silently download executable code:

```powershell
python scripts/fetch_tla2tools.py --output .local/tools/tla2tools.jar
./scripts/run-tla.ps1 -Jar .local/tools/tla2tools.jar
```

```sh
python3 scripts/fetch_tla2tools.py --output .local/tools/tla2tools.jar
./scripts/run-tla.sh .local/tools/tla2tools.jar
```

Alternatively set `TLA2TOOLS_JAR` to an already verified jar. The exhaustive
`run-tla.ps1` and `run-tla.sh` runners verify its SHA-256 before invoking Java,
run the seven legacy canonical configurations followed by the Max3
`DurableDispatchAcquisition.cfg` configuration with one TLC worker, and fail if
any model checker invocation reports an error. The smoke runners use TLC's
automatic worker selection; they run the seven legacy canonical configurations
followed by a complete reachable-state search of
`DurableDispatchAcquisitionSmoke.cfg` at
`MaxAcquisitions = 1`. The Max1 tier exercises the single-acquisition broker,
review, attempt, restart, and recovery paths with the canonical invariant list.
It cannot exercise multi-acquisition takeover, supersession, or later-item
ordering, and explicitly does not claim a completed Max2 or Max3 search. A
missing jar is a failure, not a skipped or successful model check.

Hosted pull-request reproducibility uses that Max1 smoke path. The intermediate
`DurableDispatchAcquisitionBoundedMax2.cfg` configuration remains available for
an intentional deep run, while the canonical Max3 search has a separate
`reproducibility-exhaustive` workflow for a labelled self-hosted Linux TLC
runner. In the technical preview that workflow is manual-only: no runner is
assumed to exist, and no push or schedule can leave public CI waiting for an
unprovisioned host. Provisioning, securing, and testing that runner is an
external gate. Any Max2 or exhaustive result is reported separately and is not
a blocking prerequisite for the hosted smoke delivery path.

The Max2 result recorded below was run manually with eight parallel TLC workers
against the same pinned jar, specification, alpha-canonicalization,
`SafetyView`, and invariant list. The configuration is now named
`DurableDispatchAcquisitionBoundedMax2.cfg` so a multi-hour bound cannot be
mistaken for the pull-request smoke gate. Its worker count, fingerprint index,
and seed are recorded explicitly because automatic worker selection can change
run metadata without changing the complete reachable-state verdict.

## Recorded local bounded runs

> **Historical evidence, not a current-revision result.** The counts below were
> recorded before the public AccordLock rename and before an immutable source
> commit existed. They are retained to disclose prior engineering work, but
> they do not satisfy the release checklist for this revision. Re-run the
> checked-in commands and bind new outputs to the exact release commit before
> making a formal-model claim for a release.

Using the configurations then present and the pinned v1.7.4 jar, TLC completed
the following seven bounded full reachable-state searches on 2026-08-16:

- `AuthorizationLifecycle.cfg`: 886 generated states, 306 distinct states, depth 10;
- `DispatchClaim.cfg`: 37,121 generated states, 4,218 distinct states, depth 9;
- `PhysicalReservation.cfg`: 20,346 generated states, 3,400 distinct states,
  depth 12;
- `AdmissionAuthorization.cfg`: 5,457 generated states, 640 distinct states,
  depth 9;
- `BrokerJournal.cfg`: 1,520,004 generated states, 250,052 distinct states,
  depth 27;
- `TerminalRetirement.cfg`: 4,371,625 generated states, 279,978 distinct
  states, depth 16.
- `DurableControlQueue.cfg`: 20,165,021 generated states, 839,417 distinct
  states, depth 21.

On 2026-08-21, TLC also completed the full reachable-state search for the
bounded `DurableDispatchAcquisitionBoundedMax2.cfg` configuration
(`MaxAcquisitions = 2`): 60,309,081 states generated, 4,785,228 distinct states,
zero states left on the queue, and complete graph depth 32. TLC reported no
error and finished in 1h 05min with eight workers, fingerprint index 37, and
seed `-3925543153898165861`.

That is a complete result for the Max2 bounded tier, not for the canonical Max3
`DurableDispatchAcquisition.cfg` configuration. The recorded set is seven
legacy canonical searches plus one bounded Max2 search; canonical Max3 remains
the responsibility of a manually dispatched self-hosted exhaustive run after
its runner has been provisioned and secured. Run Max2 intentionally with:

```sh
java -XX:+UseParallelGC -jar .local/tools/tla2tools.jar -workers 8 -cleanup \
  -config models/DurableDispatchAcquisitionBoundedMax2.cfg \
  models/DurableDispatchAcquisition.tla
```

The broker run bounds the raw clock to `0..1`, pending reconciliation to two
generations per operation, and recorded rollback rejection to one. Those
bounds retain clock rollback, two successive safe GET observations, exact
commit-ambiguous recovery, a losing stale/conflicting CAS, and both late
completion paths. TLC action coverage was nonzero for every one of those
transitions.

The terminal-retirement run bounds trusted time to `0..2`, request rejection
to one per trace, exact registry/terminal recovery to one, and restart to one.
Those bounds retain every rejection class as an alternative trace, a persisted
authenticated future-time rejection, rollback, one corruption or schema-drift
injection, exact registry registration, v12 deletion observation, legacy
no-backfill, returned and lost terminal commits, post-restart exact recovery,
and release followed by a competing reclaim.

The durable-control run bounds raw/trusted time to `0..2`, uses an exclusive
intake deadline of `2`, a one-tick lease, three fixed-role workers, one restart,
and at most
four globally fenced claims. The authorization boundary is `1`; authorization expiry can
therefore be explored in both ISSUE and CONSUME before the ingress boundary.
Three fixed-role workers cover evaluator, issuer, and consumer. Three claims
suffice for the complete allow path;
the fourth authorizations an expired-lease takeover while retaining a complete path.
The full search reached both fresh/unknown intake commits, original/equivalent
wire recovery with frozen verification, temporal and rollback rejection,
verifier rotation/removal, captured authority vectors, returned/lost claims,
lease recovery and takeover, strict worker-role filtering, all
zero/one-grant kernel/control branches, both pre-kernel finalizations, all five
post-decision failure reasons including CONSUME-only dispatch-window expiry,
atomic returned/unknown issuance and consumption commits, three disjoint exact
inert claim-recovery variants, restart gaps, and the final `DISPATCH_PENDING`
projection. TLC enabled every modeled action class; the final instrumented run
counted 768 signed evaluation commits, 1,536 pre-kernel boundary finalizations,
43,848 `FinalizeImpossibleWork` transitions, 196,992 dispatch-window closures,
144 atomic issuance transitions, and 864 atomic consumption transitions.
Recovery coverage counted 1,491,840 `PhaseCompleted`, 6,912
`DecisionFinalized`, 332,856 `WorkFinalized`, 669,384 exact authorization, and 6,480
exact consumption transitions.
Exact-recovery, mismatch, no-work, rollback, and stutter actions can lead to an
already-known state because they are intentionally idempotent or read-only.

TLC reported no invariant violation in the seven legacy canonical bounded
searches or the recorded Max2 bounded search. These counts are
configuration-specific and are not evidence about unbounded state spaces, the
current source revision, or the implementation abstractions listed above.

## TLA+ tooling used for the recorded local runs

The recorded runs used TLA+ Tools v1.7.4. The jar has SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
Its manifest identifies TLA+ Tools v1.7.4, revision
`5a47802b5c391f59ecdd44117981f4ff8c0656ba`. During that run it existed only
as `%TEMP%/accordlock-tla2tools-v1.7.4.jar`; it was not silently vendored into this
repository. `fetch_tla2tools.py` retrieves the corresponding official v1.7.4
release and accepts it only if the same jar hash is observed.
