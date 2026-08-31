-------------------- MODULE DurableDispatchAcquisition --------------------
EXTENDS Naturals, FiniteSets

(***************************************************************************
This is a bounded safety model of the v14 server-selected dispatch
acquisition boundary.  Two already-completed v13 CONSUME roots stand for an
ordered durable outbox.  Concrete UUIDs, SQL rows, transactions, signatures,
hashes, snapshots, and opaque Rust capabilities are collision-free symbolic
values or atomic actions here.

The v13 PhaseCompleted receipt is a prerequisite and remains historical and
inert.  It is deliberately not an acquisition completion.  A v14 acquisition
is an append-only lease generation layered over one immutable stable dispatch
claim.  Only the latest, live, artifact-free generation can be recovered as
authority.  Historical and quarantined responses never reconstruct one.
***************************************************************************)

CONSTANTS
    MaxTime,
    LeaseLength,
    MaxAcquisitions,
    AcquisitionIds,
    Workers,
    MaxAuthorityCopies,
    MaxAuthorityGrantsPerAcquisition,
    RetirementDelay

ASSUME MaxTime >= 3
ASSUME LeaseLength > 0
ASSUME Cardinality(AcquisitionIds) = MaxAcquisitions
ASSUME Cardinality(Workers) = 2
ASSUME AcquisitionIds \intersect Workers = {}
ASSUME MaxAuthorityCopies >= 2
ASSUME MaxAuthorityGrantsPerAcquisition > MaxAuthorityCopies
ASSUME RetirementDelay > 0
ASSUME RetirementDelay <= MaxTime

Items == 1..2

(***************************************************************************
Both ordered queue items deliberately target one physical resource.  This
makes a claim-bound queue disposition prove more than FIFO progress: the
active reservation must exclude the later item, while DISPOSED (or TERMINAL)
must release that exact resource before the later item can be acquired.
***************************************************************************)
PhysicalResource(item) == "shared-eks-deployment"

NoAcquisition == "NO_ACQUISITION"
NoWorker == "NO_WORKER"
NoItem == 0
NoReason == "NO_REASON"

FreshGrant == "ACQUIRED_AUTHORITY"
RecoveryGrant == "RECOVERED_AUTHORITY"
GrantKinds == {FreshGrant, RecoveryGrant}

NoOutcome == "NO_OUTCOME"
AuthorityOutcome == "AUTHORITY"
OutcomeUnknown == "OUTCOME_UNKNOWN"
InertOutcome == "INERT"
QuarantinedOutcome == "QUARANTINED"
RecoveryRequiredOutcome == "RECOVERY_REQUIRED"
RollbackOutcome == "ROLLBACK_REJECTED"
NoWorkOutcome == "NO_WORK"
DisposedOutcome == "DISPOSED"
Outcomes == {
    NoOutcome,
    AuthorityOutcome,
    OutcomeUnknown,
    InertOutcome,
    QuarantinedOutcome,
    RecoveryRequiredOutcome,
    RollbackOutcome,
    NoWorkOutcome,
    DisposedOutcome
}

AcquiredReason == "ACQUIRED"
RecoveredReason == "RECOVERED"
ExpiredReason == "EXPIRED"
SupersededReason == "SUPERSEDED"
BrokerReason == "BROKER_ARTIFACT_PRESENT"
AdmissionReason == "ADMISSION_ARTIFACT_PRESENT"
AttemptReason == "ATTEMPT_IN_FLIGHT"
RecoveryNoSendReason == "RECOVERY_NO_SEND"
RecoveryRetiredReason == "RECOVERY_RETIRED"
TerminalReason == "TERMINAL"
QueueDisposedReason == "QUEUE_DISPOSED"
DeadlineDispositionReason == "DISPATCH_DEADLINE_EXPIRED"
AuthorityChangedReason == "AUTHORITY_CHANGED"
GrantRevokedReason == "GRANT_REVOKED"
ScopeRollbackReason == "SCOPE_ROLLBACK"
IngressRollbackReason == "INGRESS_ROLLBACK"
DualRollbackReason == "DUAL_ROLLBACK"
Reasons == {
    NoReason,
    AcquiredReason,
    RecoveredReason,
    ExpiredReason,
    SupersededReason,
    BrokerReason,
    AdmissionReason,
    AttemptReason,
    RecoveryNoSendReason,
    RecoveryRetiredReason,
    TerminalReason,
    ScopeRollbackReason,
    IngressRollbackReason,
    DualRollbackReason,
    QueueDisposedReason,
    DeadlineDispositionReason,
    AuthorityChangedReason,
    GrantRevokedReason
}

QueueDispositionReasons == {
    DeadlineDispositionReason,
    AuthorityChangedReason,
    GrantRevokedReason
}

AttemptReturned == "ATTEMPT_RETURNED"
AttemptLost == "ATTEMPT_OUTCOME_UNKNOWN"
AttemptDeliveryKinds == {AttemptReturned, AttemptLost}

ReviewAuthenticated == "REVIEW_AUTHENTICATED"
ReviewRejected == "REVIEW_REJECTED"
ReviewOutcomes == {ReviewAuthenticated, ReviewRejected}
ReviewReturned == "REVIEW_COMMIT_RETURNED"
ReviewLost == "REVIEW_COMMIT_OUTCOME_UNKNOWN"
ReviewDeliveryKinds == {ReviewReturned, ReviewLost}

DispatchDeadline(item) ==
    CASE item = 1 -> MaxTime - 1
      [] item = 2 -> MaxTime

ExpectedClaimId(item) ==
    CASE item = 1 -> "stable-claim-one"
      [] item = 2 -> "stable-claim-two"

ExpectedClaimFence(item) == item

StableClaimIds == {ExpectedClaimId(item) : item \in Items}

Min(a, b) == IF a <= b THEN a ELSE b
Max(a, b) == IF a >= b THEN a ELSE b

VARIABLES
    clock,
    claims,
    acquisitions,
    nextLeaseFence,
    artifacts,
    audit,
    volatileState,
    observation

vars == <<
    clock,
    claims,
    acquisitions,
    nextLeaseFence,
    artifacts,
    audit,
    volatileState,
    observation
>>

NoObservation == [
    outcome |-> NoOutcome,
    reason |-> NoReason,
    requestId |-> NoAcquisition,
    worker |-> NoWorker,
    item |-> NoItem,
    beforeScope |-> clock.scope,
    beforeIngress |-> clock.ingress,
    beforeAcquisitionCount |-> Cardinality(acquisitions),
    beforeDispositionCount |-> Cardinality(audit.queueDispositions),
    beforeAuthorityGrantCount |-> Cardinality(audit.authorityGrants)
]

RequestObservation(outcome, reason, requestId, worker, item) == [
    outcome |-> outcome,
    reason |-> reason,
    requestId |-> requestId,
    worker |-> worker,
    item |-> item,
    beforeScope |-> clock.scope,
    beforeIngress |-> clock.ingress,
    beforeAcquisitionCount |-> Cardinality(acquisitions),
    beforeDispositionCount |-> Cardinality(audit.queueDispositions),
    beforeAuthorityGrantCount |-> Cardinality(audit.authorityGrants)
]

Init ==
    /\ clock = [
        raw |-> 0,
        scope |-> [item \in Items |-> 0],
        ingress |-> [item \in Items |-> 0],
        scopeHistory |-> [item \in Items |-> {0}],
        ingressHistory |-> [item \in Items |-> {0}],
        externalScopeSeen |-> FALSE,
        externalIngressSeen |-> FALSE
       ]
    /\ claims = [
        phaseCompleted |-> [item \in Items |-> TRUE],
        phaseCompletionExecutable |-> [item \in Items |-> FALSE],
        present |-> [item \in Items |-> FALSE],
        disposed |-> [item \in Items |-> FALSE],
        recoveryNoSend |-> [item \in Items |-> FALSE],
        recoveryRetired |-> [item \in Items |-> FALSE],
        recoveryOrigin |-> [item \in Items |-> NoAcquisition],
        recoveryOriginFence |-> [item \in Items |-> 0],
        recoverySafeAfter |-> [item \in Items |-> 0],
        recoveryRetiredAt |-> [item \in Items |-> 0],
        id |-> [item \in Items |-> NoAcquisition],
        fence |-> [item \in Items |-> 0],
        authorityCurrent |-> [item \in Items |-> TRUE],
        grantRevoked |-> [item \in Items |-> FALSE]
       ]
    /\ acquisitions = {}
    /\ nextLeaseFence = 0
    /\ artifacts = [
        broker |-> [item \in Items |-> FALSE],
        brokerCreate |-> [item \in Items |-> FALSE],
        brokerCreateWrites |-> [item \in Items |-> 0],
        createAbsent |-> [item \in Items |-> FALSE],
        createAbsentWrites |-> [item \in Items |-> 0],
        createAbsentObservedAt |-> [item \in Items |-> 0],
        brokerToken |-> [item \in Items |-> FALSE],
        brokerTokenWrites |-> [item \in Items |-> 0],
        brokerOrigin |-> [item \in Items |-> NoAcquisition],
        brokerOriginFence |-> [item \in Items |-> 0],
        brokerBindingVersion |-> [item \in Items |-> 0],
        reviewStarted |-> [item \in Items |-> FALSE],
        reviewAuthenticated |-> [item \in Items |-> FALSE],
        reviewRejected |-> [item \in Items |-> FALSE],
        reviewBeginWrites |-> [item \in Items |-> 0],
        reviewTerminalWrites |-> [item \in Items |-> 0],
        reviewOrigin |-> [item \in Items |-> NoAcquisition],
        reviewOriginFence |-> [item \in Items |-> 0],
        reviewBindingVersion |-> [item \in Items |-> 0],
        reviewObservedAt |-> [item \in Items |-> 0],
        admission |-> [item \in Items |-> FALSE],
        admissionOrigin |-> [item \in Items |-> NoAcquisition],
        attempt |-> [item \in Items |-> FALSE],
        attemptOrigin |-> [item \in Items |-> NoAcquisition],
        attemptOriginFence |-> [item \in Items |-> 0],
        attemptBindingVersion |-> [item \in Items |-> 0],
        terminal |-> [item \in Items |-> FALSE],
        cleanup |-> [item \in Items |-> FALSE],
        deleteAbsent |-> [item \in Items |-> FALSE],
        deleteAbsentWrites |-> [item \in Items |-> 0],
        cleanupFence |-> [item \in Items |-> 0],
        cleanupAcquisitionCount |-> [item \in Items |-> 0],
        cleanupAuthorityGrantCount |-> [item \in Items |-> 0],
        cleanupAttempt |-> [item \in Items |-> FALSE],
        cleanupObservedAt |-> [item \in Items |-> 0]
       ]
    /\ audit = [
        queueDispositions |-> {},
        authorityGrants |-> {},
        authorityGrantCount |-> [
            acquisitionId \in AcquisitionIds |-> 0
        ],
        unknownCommits |-> {},
        unknownDispositionCommits |-> {},
        inertReceipts |-> {},
        quarantineReceipts |-> {},
        unknownReviewBegins |-> {},
        reviewCommits |-> {},
        attemptCommits |-> {},
        recoveryClosures |-> {},
        recoveryRetirements |-> {}
       ]
    /\ volatileState = [
        held |-> [acquisitionId \in AcquisitionIds |-> 0],
        reviewIo |-> [acquisitionId \in AcquisitionIds |-> 0],
        reviewProof |-> [acquisitionId \in AcquisitionIds |-> 0],
        restartCount |-> 0
       ]
    /\ observation = [
        outcome |-> NoOutcome,
        reason |-> NoReason,
        requestId |-> NoAcquisition,
        worker |-> NoWorker,
        item |-> NoItem,
        beforeScope |-> [item \in Items |-> 0],
        beforeIngress |-> [item \in Items |-> 0],
        beforeAcquisitionCount |-> 0,
        beforeDispositionCount |-> 0,
        beforeAuthorityGrantCount |-> 0
       ]

AcquisitionsFor(item) ==
    {record \in acquisitions : record[1] = item}

HasAcquisitions(item) == AcquisitionsFor(item) # {}

HasAcquisitionId(acquisitionId) ==
    \E record \in acquisitions : record[2] = acquisitionId

AcquisitionForId(acquisitionId) ==
    CHOOSE record \in acquisitions : record[2] = acquisitionId

HasDispositionId(requestId) ==
    \E receipt \in audit.queueDispositions : receipt[2] = requestId

DispositionForId(requestId) ==
    CHOOSE receipt \in audit.queueDispositions : receipt[2] = requestId

DispositionsFor(item) ==
    {receipt \in audit.queueDispositions : receipt[1] = item}

HasQueueDisposition(item) == DispositionsFor(item) # {}

RequestIdentityUsed(requestId) ==
    HasAcquisitionId(requestId) \/ HasDispositionId(requestId)

(***************************************************************************
Acquisition IDs and workers are opaque names.  Introducing every unused name
and asking TLC to quotient the resulting permutations generates the same
orbit many times and then pays to canonicalize it.  The two predicates below
instead introduce one representative of each fresh-name orbit directly.

Request identities are append-only, so all unused IDs are interchangeable.
Workers become durable only in an acquisition or queue disposition.  A
durable action may reuse any already-seen worker or introduce exactly one
representative of the still-unseen workers.  Existing recovery actions remain
free to use the worker already bound into their durable record.  Because the
specification, actions, and invariants compare these values only for equality,
this is exact alpha-canonicalization rather than a reduction of behavior.
***************************************************************************)
PersistedWorkers ==
    {record[4] : record \in acquisitions}
        \cup {receipt[3] : receipt \in audit.queueDispositions}

CanonicalFreshRequestId(requestId) ==
    /\ requestId \in AcquisitionIds
    /\ ~RequestIdentityUsed(requestId)
    /\ requestId =
        CHOOSE candidate \in AcquisitionIds :
            ~RequestIdentityUsed(candidate)

CanonicalPersistentWorker(worker) ==
    /\ worker \in Workers
    /\ \/ worker \in PersistedWorkers
       \/ /\ worker \notin PersistedWorkers
          /\ worker =
              CHOOSE candidate \in Workers :
                  candidate \notin PersistedWorkers

UnusedRequestIds ==
    {requestId \in AcquisitionIds : ~RequestIdentityUsed(requestId)}

CanonicalObservationRequestId ==
    CHOOSE requestId \in UnusedRequestIds : TRUE

CanonicalObservationWorker ==
    CHOOSE worker \in Workers : TRUE

LatestFence(item) ==
    CHOOSE fence \in 1..nextLeaseFence :
        /\ \E record \in acquisitions :
            /\ record[1] = item
            /\ record[3] = fence
        /\ \A record \in AcquisitionsFor(item) : record[3] <= fence

LatestAcquisition(item) ==
    CHOOSE record \in acquisitions :
        /\ record[1] = item
        /\ record[3] = LatestFence(item)

LatestAcquisitionId(item) == LatestAcquisition(item)[2]
LatestLeaseUntil(item) == LatestAcquisition(item)[6]

ItemForAcquisition(acquisitionId) == AcquisitionForId(acquisitionId)[1]

DualHighWater(item) == Max(clock.scope[item], clock.ingress[item])

CurrentDispatchFacts(item) ==
    /\ claims.authorityCurrent[item]
    /\ ~claims.grantRevoked[item]

DeadlineDurablyExpired(item) ==
    \/ DualHighWater(item) >= DispatchDeadline(item)
    \/ /\ clock.raw >= DualHighWater(item)
       /\ clock.raw >= DispatchDeadline(item)

DispositionReason(item) ==
    IF DeadlineDurablyExpired(item)
    THEN DeadlineDispositionReason
    ELSE IF ~claims.authorityCurrent[item]
    THEN AuthorityChangedReason
    ELSE GrantRevokedReason

CanDispose(item) ==
    \/ DeadlineDurablyExpired(item)
    \/ /\ clock.raw >= DualHighWater(item)
       /\ ~CurrentDispatchFacts(item)

NoArtifacts(item) ==
    /\ ~artifacts.broker[item]
    /\ ~artifacts.admission[item]
    /\ ~artifacts.attempt[item]
    /\ ~artifacts.terminal[item]
    /\ ~claims.recoveryNoSend[item]
    /\ ~claims.recoveryRetired[item]

ReservationActive(item) ==
    /\ claims.present[item]
    /\ ~claims.disposed[item]
    /\ ~claims.recoveryRetired[item]
    /\ ~artifacts.terminal[item]

PhysicalResourceAvailable(item) ==
    ~\E other \in Items :
        /\ other # item
        /\ PhysicalResource(other) = PhysicalResource(item)
        /\ ReservationActive(other)

ArtifactReason(item) ==
    IF artifacts.terminal[item] THEN TerminalReason
    ELSE IF claims.recoveryRetired[item] THEN RecoveryRetiredReason
    ELSE IF claims.recoveryNoSend[item] THEN RecoveryNoSendReason
    ELSE IF artifacts.attempt[item] THEN AttemptReason
    ELSE IF artifacts.broker[item] THEN BrokerReason
    ELSE AdmissionReason

(***************************************************************************
The SQL worker owns selection.  A request contains only worker and
acquisition retry identity; there is intentionally no item argument in any
acquisition action.  Active leases are skipped.  Artifact-bearing claims are
not acquisition candidates, but actionable historical recovery is selected
server-side before later queue work.  An expired dispatch root remains
selectable until its temporal observation has durably advanced both
high-water marks.
***************************************************************************)
Candidate(item) ==
    /\ claims.phaseCompleted[item]
    /\ ~HasQueueDisposition(item)
    /\ ~claims.disposed[item]
    /\ NoArtifacts(item)
    /\ PhysicalResourceAvailable(item)
    /\ \/ ~claims.present[item]
       \/ /\ HasAcquisitions(item)
          /\ \/ clock.raw >= LatestLeaseUntil(item)
             \/ DualHighWater(item) >= LatestLeaseUntil(item)

CandidateItems == {item \in Items : Candidate(item)}

(***************************************************************************
An artifact-bearing active claim is not acquisition-eligible, but it remains
server-discoverable after a crash.  The caller need not know the historical
claim/acquisition UUID: state returns an opaque recovery selector for the
oldest durable item.  RETIRED, DISPOSED, and TERMINAL history is already inert
and no longer participates in recovery scheduling.
***************************************************************************)
RecoveryRetirementReady(item) ==
    /\ artifacts.cleanup[item]
    /\ artifacts.deleteAbsent[item]
    /\ artifacts.cleanupObservedAt[item] + RetirementDelay <= MaxTime
    /\ clock.raw >= DualHighWater(item)
    /\ clock.raw >=
        IF claims.recoverySafeAfter[item] = 0
        THEN artifacts.cleanupObservedAt[item] + RetirementDelay
        ELSE claims.recoverySafeAfter[item]

RecoveryNoCredentialReady(item) ==
    /\ artifacts.createAbsent[item]
    /\ artifacts.brokerCreate[item]
    /\ ~artifacts.brokerToken[item]
    /\ ~artifacts.reviewStarted[item]
    /\ ~artifacts.attempt[item]
    /\ ~artifacts.admission[item]
    /\ ~artifacts.terminal[item]
    /\ ~artifacts.cleanup[item]

RecoveryCandidate(item) ==
    /\ claims.phaseCompleted[item]
    /\ claims.present[item]
    /\ HasAcquisitions(item)
    /\ ~claims.disposed[item]
    /\ ~claims.recoveryRetired[item]
    /\ ~artifacts.terminal[item]
    /\ \/ /\ claims.recoveryNoSend[item]
           /\ \/ /\ ~artifacts.cleanup[item]
                    /\ ~artifacts.createAbsent[item]
              \/ RecoveryRetirementReady(item)
              \/ RecoveryNoCredentialReady(item)
       \/ /\ ~claims.recoveryNoSend[item]
           /\ \/ /\ (artifacts.attempt[item]
                        \/ artifacts.admission[item])
                    /\ ~artifacts.cleanup[item]
              \/ /\ ~artifacts.attempt[item]
                    /\ ~artifacts.admission[item]
                    /\ artifacts.broker[item]

RecoveryCandidateItems == {item \in Items : RecoveryCandidate(item)}

ServerWorkItems == CandidateItems \cup RecoveryCandidateItems

SelectedServerItem ==
    CHOOSE item \in ServerWorkItems :
        \A earlier \in ServerWorkItems : item <= earlier

SelectedItem ==
    CHOOSE item \in CandidateItems :
        \A earlier \in CandidateItems : item <= earlier

DualRecordedAt(item, sample) ==
    [clock EXCEPT
        !.scope[item] = sample,
        !.ingress[item] = sample,
        !.scopeHistory[item] = @ \cup {sample},
        !.ingressHistory[item] = @ \cup {sample}
    ]

DualRecordedClock(item) == DualRecordedAt(item, clock.raw)

LeaseUntilFor(item) ==
    Min(clock.raw + LeaseLength, DispatchDeadline(item))

IsLatest(acquisitionId) ==
    /\ HasAcquisitionId(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        LatestAcquisitionId(item) = acquisitionId

CurrentLiveAcquisition(acquisitionId) ==
    /\ IsLatest(acquisitionId)
    /\ LET record == AcquisitionForId(acquisitionId) IN
        /\ ~claims.disposed[record[1]]
        /\ CurrentDispatchFacts(record[1])
        /\ clock.raw >= DualHighWater(record[1])
        /\ clock.raw >= record[5]
        /\ clock.raw < record[6]
        /\ clock.raw < DispatchDeadline(record[1])
        /\ ~artifacts.attempt[record[1]]
        /\ ~artifacts.terminal[record[1]]
        /\ ~artifacts.cleanup[record[1]]
        /\ ~claims.recoveryNoSend[record[1]]
        /\ ~claims.recoveryRetired[record[1]]

CurrentHeldAuthority(acquisitionId) ==
    /\ volatileState.held[acquisitionId] > 0
    /\ CurrentLiveAcquisition(acquisitionId)

OriginsMatch(acquisitionId) ==
    LET item == ItemForAcquisition(acquisitionId) IN
        /\ (artifacts.broker[item] =>
            artifacts.brokerOrigin[item] = acquisitionId)
        /\ (artifacts.reviewStarted[item] =>
            artifacts.reviewOrigin[item] = acquisitionId)
        /\ (artifacts.admission[item] =>
            artifacts.admissionOrigin[item] = acquisitionId)
        /\ (claims.recoveryNoSend[item] \/ claims.recoveryRetired[item] =>
            claims.recoveryOrigin[item] = acquisitionId)

AuthorityGrantsFor(item) ==
    {grant \in audit.authorityGrants :
        ItemForAcquisition(grant[1]) = item}

RollbackReason(item) ==
    IF clock.raw < clock.scope[item]
       /\ clock.raw < clock.ingress[item]
    THEN DualRollbackReason
    ELSE IF clock.raw < clock.scope[item]
    THEN ScopeRollbackReason
    ELSE IngressRollbackReason

SetRawClock(sample) ==
    /\ sample \in 0..MaxTime
    /\ clock' = [clock EXCEPT !.raw = sample]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

(***************************************************************************
These two actions stand for other authenticated users of the independently
keyed durable clocks.  They make rollback against only one side of the dual
boundary reachable without weakening acquisition behavior.
***************************************************************************)
AdvanceExternalScope ==
    /\ ~clock.externalScopeSeen
    /\ clock.raw >= clock.scope[2]
    /\ clock' = [clock EXCEPT
        !.scope[2] = clock.raw,
        !.scopeHistory[2] = @ \cup {clock.raw},
        !.externalScopeSeen = TRUE
       ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

AdvanceExternalIngress ==
    /\ ~clock.externalIngressSeen
    /\ clock.raw >= clock.ingress[2]
    /\ clock' = [clock EXCEPT
        !.ingress[2] = clock.raw,
        !.ingressHistory[2] = @ \cup {clock.raw},
        !.externalIngressSeen = TRUE
       ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

(***************************************************************************
Authority rotation and grant revocation are authenticated durable changes
external to the queue worker.  Either makes an otherwise immutable queue
root non-productive; the worker persists an inert disposition rather than
repeatedly starving later FIFO work.
***************************************************************************)
RotateAuthority(item) ==
    /\ item \in Items
    /\ claims.authorityCurrent[item]
    /\ claims' = [claims EXCEPT !.authorityCurrent[item] = FALSE]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

RevokeGrant(item) ==
    /\ item \in Items
    /\ ~claims.grantRevoked[item]
    /\ claims' = [claims EXCEPT !.grantRevoked[item] = TRUE]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

(***************************************************************************
One invalid candidate is disposed per transaction.  The request identity is
global across acquisitions and dispositions, so a lost commit response can
be recovered exactly without rerunning FIFO selection.  Deadline has strict
priority over authority rotation and grant revocation.  A durable HWM at or
past the deadline is itself an irreversible observation even during raw
clock rollback.  If a stable claim already exists, the same transaction
marks it DISPOSED and releases its physical reservation.
***************************************************************************)
DisposeNext(worker, requestId, delivered) ==
    /\ worker \in Workers
    /\ requestId \in AcquisitionIds
    /\ delivered \in BOOLEAN
    /\ CanonicalPersistentWorker(worker)
    /\ CanonicalFreshRequestId(requestId)
    /\ ~RequestIdentityUsed(requestId)
    /\ CandidateItems # {}
    /\ SelectedServerItem = SelectedItem
    /\ LET item == SelectedItem IN
        /\ CanDispose(item)
        /\ (claims.present[item] =>
            /\ HasAcquisitions(item)
            /\ \/ clock.raw >= LatestLeaseUntil(item)
               \/ DualHighWater(item) >= LatestLeaseUntil(item))
        /\ LET reason == DispositionReason(item) IN
            /\ clock' = DualRecordedAt(
                item,
                IF DualHighWater(item) >= DispatchDeadline(item)
                THEN DualHighWater(item)
                ELSE clock.raw)
            /\ claims' =
                IF claims.present[item]
                THEN [claims EXCEPT !.disposed[item] = TRUE]
                ELSE claims
            /\ audit' = [audit EXCEPT
                !.queueDispositions = @ \cup {
                    <<item,
                      requestId,
                      worker,
                      reason,
                      IF DualHighWater(item) >= DispatchDeadline(item)
                      THEN DualHighWater(item)
                      ELSE clock.raw,
                      IF claims.present[item]
                      THEN LatestAcquisitionId(item)
                      ELSE NoAcquisition>>
                },
                !.unknownDispositionCommits =
                    IF delivered THEN @ ELSE @ \cup {requestId}
               ]
            /\ observation' = RequestObservation(
                IF delivered THEN DisposedOutcome ELSE OutcomeUnknown,
                IF delivered THEN reason ELSE NoReason,
                requestId,
                worker,
                item)
    /\ UNCHANGED <<
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

DisposeDeadlineReturned(worker, requestId) ==
    /\ CandidateItems # {}
    /\ DispositionReason(SelectedItem) = DeadlineDispositionReason
    /\ DisposeNext(worker, requestId, TRUE)

DisposeUnclaimedDeadlineReturned(worker, requestId) ==
    /\ CandidateItems # {}
    /\ ~claims.present[SelectedItem]
    /\ DisposeDeadlineReturned(worker, requestId)

DisposeClaimBoundDeadlineReturned(worker, requestId) ==
    /\ CandidateItems # {}
    /\ claims.present[SelectedItem]
    /\ DisposeDeadlineReturned(worker, requestId)

DisposeDeadlineLost(worker, requestId) ==
    /\ CandidateItems # {}
    /\ DispositionReason(SelectedItem) = DeadlineDispositionReason
    /\ DisposeNext(worker, requestId, FALSE)

DisposeAuthorityChanged(worker, requestId, delivered) ==
    /\ CandidateItems # {}
    /\ DispositionReason(SelectedItem) = AuthorityChangedReason
    /\ DisposeNext(worker, requestId, delivered)

DisposeGrantRevoked(worker, requestId, delivered) ==
    /\ CandidateItems # {}
    /\ DispositionReason(SelectedItem) = GrantRevokedReason
    /\ DisposeNext(worker, requestId, delivered)

AcquireNext(worker, acquisitionId, delivered) ==
    /\ worker \in Workers
    /\ acquisitionId \in AcquisitionIds
    /\ delivered \in BOOLEAN
    /\ CanonicalPersistentWorker(worker)
    /\ CanonicalFreshRequestId(acquisitionId)
    /\ ~RequestIdentityUsed(acquisitionId)
    /\ CandidateItems # {}
    /\ SelectedServerItem = SelectedItem
    /\ nextLeaseFence < MaxAcquisitions
    /\ LET item == SelectedItem IN
        /\ CurrentDispatchFacts(item)
        /\ clock.raw >= DualHighWater(item)
        /\ clock.raw < DispatchDeadline(item)
        /\ LeaseUntilFor(item) > clock.raw
        /\ (claims.present[item] =>
            /\ HasAcquisitions(item)
            /\ clock.raw >= LatestLeaseUntil(item)
            /\ NoArtifacts(item))
        /\ clock' = DualRecordedClock(item)
        /\ claims' =
            IF claims.present[item]
            THEN claims
            ELSE [claims EXCEPT
                !.present[item] = TRUE,
                !.id[item] = ExpectedClaimId(item),
                !.fence[item] = ExpectedClaimFence(item)
            ]
        /\ acquisitions' = acquisitions \cup {
            <<item,
              acquisitionId,
              nextLeaseFence + 1,
              worker,
              clock.raw,
              LeaseUntilFor(item)>>
           }
        /\ nextLeaseFence' = nextLeaseFence + 1
        /\ audit' = [audit EXCEPT
            !.authorityGrants =
                IF delivered
                THEN @ \cup {
                    <<acquisitionId, FreshGrant, clock.raw, 1>>
                }
                ELSE @,
            !.authorityGrantCount[acquisitionId] =
                IF delivered THEN 1 ELSE @,
            !.unknownCommits =
                IF delivered THEN @ ELSE @ \cup {acquisitionId}
           ]
        /\ volatileState' = [volatileState EXCEPT
            !.held[acquisitionId] = IF delivered THEN 1 ELSE @
           ]
        /\ observation' = RequestObservation(
            IF delivered THEN AuthorityOutcome ELSE OutcomeUnknown,
            IF delivered THEN AcquiredReason ELSE NoReason,
            acquisitionId,
            worker,
            item)
    /\ UNCHANGED artifacts

AcquireFreshReturned(worker, acquisitionId) ==
    /\ CandidateItems # {}
    /\ ~claims.present[SelectedItem]
    /\ ~(SelectedItem = 2 /\ HasQueueDisposition(1))
    /\ AcquireNext(worker, acquisitionId, TRUE)

AcquireFreshAfterDispositionReturned(worker, acquisitionId) ==
    /\ CandidateItems # {}
    /\ SelectedItem = 2
    /\ HasQueueDisposition(1)
    /\ ~claims.present[SelectedItem]
    /\ AcquireNext(worker, acquisitionId, TRUE)

AcquireFreshLost(worker, acquisitionId) ==
    /\ CandidateItems # {}
    /\ ~claims.present[SelectedItem]
    /\ AcquireNext(worker, acquisitionId, FALSE)

AcquireTakeoverReturned(worker, acquisitionId) ==
    /\ CandidateItems # {}
    /\ claims.present[SelectedItem]
    /\ AcquireNext(worker, acquisitionId, TRUE)

AcquireTakeoverLost(worker, acquisitionId) ==
    /\ CandidateItems # {}
    /\ claims.present[SelectedItem]
    /\ AcquireNext(worker, acquisitionId, FALSE)

RejectAcquireRollback ==
    /\ UnusedRequestIds # {}
    /\ CandidateItems # {}
    /\ SelectedServerItem = SelectedItem
    /\ LET item == SelectedItem IN
        /\ clock.raw < DualHighWater(item)
        /\ DualHighWater(item) < DispatchDeadline(item)
        /\ observation' = RequestObservation(
            RollbackOutcome,
            RollbackReason(item),
            CanonicalObservationRequestId,
            CanonicalObservationWorker,
            item)
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

RecoverLive(worker, acquisitionId) ==
    /\ worker \in Workers
    /\ acquisitionId \in AcquisitionIds
    /\ HasAcquisitionId(acquisitionId)
    /\ LET record == AcquisitionForId(acquisitionId) IN
        /\ record[4] = worker
        /\ LatestAcquisitionId(record[1]) = acquisitionId
        /\ ~claims.disposed[record[1]]
        /\ CurrentDispatchFacts(record[1])
        /\ NoArtifacts(record[1])
        /\ volatileState.held[acquisitionId] < MaxAuthorityCopies
        /\ audit.authorityGrantCount[acquisitionId]
            < MaxAuthorityGrantsPerAcquisition
        /\ clock.raw >= DualHighWater(record[1])
        /\ clock.raw >= record[5]
        /\ clock.raw < record[6]
        /\ clock.raw < DispatchDeadline(record[1])
        /\ clock' = DualRecordedClock(record[1])
        /\ audit' = [audit EXCEPT
            !.authorityGrants = @ \cup {
                <<acquisitionId,
                  RecoveryGrant,
                  clock.raw,
                  audit.authorityGrantCount[acquisitionId] + 1>>
            },
            !.authorityGrantCount[acquisitionId] = @ + 1
           ]
        /\ volatileState' = [volatileState EXCEPT
            !.held[acquisitionId] = @ + 1
           ]
        /\ observation' = RequestObservation(
            AuthorityOutcome,
            RecoveredReason,
            acquisitionId,
            worker,
            record[1])
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts
       >>

RecoverExpired(worker, acquisitionId) ==
    /\ worker \in Workers
    /\ acquisitionId \in AcquisitionIds
    /\ HasAcquisitionId(acquisitionId)
    /\ LET record == AcquisitionForId(acquisitionId) IN
        /\ record[4] = worker
        /\ LatestAcquisitionId(record[1]) = acquisitionId
        /\ ~claims.disposed[record[1]]
        /\ NoArtifacts(record[1])
        /\ \/ DualHighWater(record[1]) >= record[6]
           \/ /\ clock.raw >= DualHighWater(record[1])
              /\ \/ clock.raw >= record[6]
                 \/ clock.raw >= DispatchDeadline(record[1])
        /\ clock' =
            IF DualHighWater(record[1]) >= record[6]
            THEN clock
            ELSE DualRecordedClock(record[1])
        /\ audit' = [audit EXCEPT
            !.inertReceipts = @ \cup {
                <<acquisitionId, ExpiredReason>>
            }
           ]
        /\ observation' = RequestObservation(
            InertOutcome,
            ExpiredReason,
            acquisitionId,
            worker,
            record[1])
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

RecoverSuperseded(worker, acquisitionId) ==
    /\ worker \in Workers
    /\ acquisitionId \in AcquisitionIds
    /\ HasAcquisitionId(acquisitionId)
    /\ LET record == AcquisitionForId(acquisitionId) IN
        /\ record[4] = worker
        /\ LatestAcquisitionId(record[1]) # acquisitionId
        /\ audit' = [audit EXCEPT
            !.inertReceipts = @ \cup {
                <<acquisitionId, SupersededReason>>
            }
           ]
        /\ observation' = RequestObservation(
            InertOutcome,
            SupersededReason,
            acquisitionId,
            worker,
            record[1])
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

RecoverDisposition(worker, requestId) ==
    /\ worker \in Workers
    /\ requestId \in AcquisitionIds
    /\ HasDispositionId(requestId)
    /\ LET receipt == DispositionForId(requestId) IN
        /\ receipt[3] = worker
        /\ observation' = RequestObservation(
            DisposedOutcome,
            receipt[4],
            requestId,
            worker,
            receipt[1])
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

RecoverQueueDisposed(worker, acquisitionId) ==
    /\ worker \in Workers
    /\ acquisitionId \in AcquisitionIds
    /\ HasAcquisitionId(acquisitionId)
    /\ LET record == AcquisitionForId(acquisitionId) IN
        /\ record[4] = worker
        /\ LatestAcquisitionId(record[1]) = acquisitionId
        /\ claims.disposed[record[1]]
        /\ \E receipt \in DispositionsFor(record[1]) :
            receipt[6] = acquisitionId
        /\ audit' = [audit EXCEPT
            !.quarantineReceipts = @ \cup {
                <<acquisitionId, QueueDisposedReason>>
            }
           ]
        /\ observation' = RequestObservation(
            QuarantinedOutcome,
            QueueDisposedReason,
            acquisitionId,
            worker,
            record[1])
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

RecoverQuarantined(worker, acquisitionId, reason) ==
    /\ worker \in Workers
    /\ acquisitionId \in AcquisitionIds
    /\ reason \in {
        BrokerReason,
        AdmissionReason,
        AttemptReason,
        RecoveryNoSendReason,
        RecoveryRetiredReason,
        TerminalReason
       }
    /\ HasAcquisitionId(acquisitionId)
    /\ LET record == AcquisitionForId(acquisitionId) IN
        /\ record[4] = worker
        /\ LatestAcquisitionId(record[1]) = acquisitionId
        /\ ~NoArtifacts(record[1])
        /\ reason = ArtifactReason(record[1])
        /\ audit' = [audit EXCEPT
            !.quarantineReceipts = @ \cup {
                <<acquisitionId, reason>>
            }
           ]
        /\ observation' = RequestObservation(
            QuarantinedOutcome,
            reason,
            acquisitionId,
            worker,
            record[1])
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

RejectRecoveryRollback(worker, acquisitionId) ==
    /\ worker \in Workers
    /\ acquisitionId \in AcquisitionIds
    /\ HasAcquisitionId(acquisitionId)
    /\ LET record == AcquisitionForId(acquisitionId) IN
        /\ record[4] = worker
        /\ LatestAcquisitionId(record[1]) = acquisitionId
        /\ NoArtifacts(record[1])
        /\ clock.raw < DualHighWater(record[1])
        /\ observation' = RequestObservation(
            RollbackOutcome,
            RollbackReason(record[1]),
            acquisitionId,
            worker,
            record[1])
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

(***************************************************************************
Downstream durable facts remain bound to the same latest acquisition.  A
broker INTENT already bars takeover and reconstruction after restart, but an
already-held in-process authority may continue along its exact origin.  The
provider-attempt transition consumes that generation's volatile authority.
***************************************************************************)
CreateBrokerIntent(acquisitionId) ==
    /\ acquisitionId \in AcquisitionIds
    /\ CurrentHeldAuthority(acquisitionId)
    /\ OriginsMatch(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ ~artifacts.broker[item]
        /\ ~artifacts.attempt[item]
        /\ artifacts' = [artifacts EXCEPT
            !.broker[item] = TRUE,
            !.brokerCreate[item] = TRUE,
            !.brokerCreateWrites[item] = 1,
            !.brokerOrigin[item] = acquisitionId,
            !.brokerOriginFence[item] =
                AcquisitionForId(acquisitionId)[3],
            !.brokerBindingVersion[item] = 2
           ]
        /\ clock' = DualRecordedClock(item)
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        audit,
        volatileState
       >>

(***************************************************************************
A second recovered copy may race the TOKEN operation against CREATE.  The
TOKEN journal CAS is enabled only after the CREATE INTENT is durably visible;
neither copy can create a second row for either operation.
***************************************************************************)
CreateTokenBrokerIntent(acquisitionId) ==
    /\ acquisitionId \in AcquisitionIds
    /\ CurrentHeldAuthority(acquisitionId)
    /\ OriginsMatch(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ artifacts.brokerCreate[item]
        /\ artifacts.brokerCreateWrites[item] = 1
        /\ ~artifacts.createAbsent[item]
        /\ ~artifacts.brokerToken[item]
        /\ ~artifacts.attempt[item]
        /\ artifacts' = [artifacts EXCEPT
            !.brokerToken[item] = TRUE,
            !.brokerTokenWrites[item] = 1
           ]
        /\ clock' = DualRecordedClock(item)
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        audit,
        volatileState
       >>

(***************************************************************************
TokenReview is a distinct provider boundary.  Its durable begin CAS is bound
to the exact committed CREATE and TOKEN rows and returns at most one volatile
I/O authority.  Losing that authority after the begin commit cannot recreate
it.  A terminal authenticated or rejected observation consumes it; an
authenticated commit may be recovered exactly because recovery performs no
provider I/O and the later ATTEMPT remains a separate CAS.
***************************************************************************)
BeginCredentialReview(acquisitionId, delivered) ==
    /\ acquisitionId \in AcquisitionIds
    /\ delivered \in BOOLEAN
    /\ CurrentHeldAuthority(acquisitionId)
    /\ OriginsMatch(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ artifacts.brokerCreate[item]
        /\ artifacts.brokerToken[item]
        /\ ~artifacts.reviewStarted[item]
        /\ ~artifacts.attempt[item]
        /\ artifacts' = [artifacts EXCEPT
            !.reviewStarted[item] = TRUE,
            !.reviewBeginWrites[item] = 1,
            !.reviewOrigin[item] = acquisitionId,
            !.reviewOriginFence[item] =
                AcquisitionForId(acquisitionId)[3],
            !.reviewBindingVersion[item] = 2
           ]
        /\ clock' = DualRecordedClock(item)
        /\ audit' = [audit EXCEPT
            !.unknownReviewBegins =
                IF delivered THEN @ ELSE @ \cup {acquisitionId}
           ]
        /\ volatileState' = [volatileState EXCEPT
            !.reviewIo[acquisitionId] = IF delivered THEN 1 ELSE 0
           ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<claims, acquisitions, nextLeaseFence>>

RecordCredentialReview(acquisitionId, outcome, delivered) ==
    /\ acquisitionId \in AcquisitionIds
    /\ outcome \in ReviewOutcomes
    /\ delivered \in BOOLEAN
    /\ IsLatest(acquisitionId)
    /\ OriginsMatch(acquisitionId)
    /\ volatileState.reviewIo[acquisitionId] = 1
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ claims.present[item]
        /\ ~claims.disposed[item]
        /\ ~claims.recoveryRetired[item]
        /\ ~artifacts.terminal[item]
        /\ clock.raw >= DualHighWater(item)
        /\ (outcome = ReviewAuthenticated =>
            clock.raw < AcquisitionForId(acquisitionId)[6])
        /\ artifacts.reviewStarted[item]
        /\ ~artifacts.reviewAuthenticated[item]
        /\ ~artifacts.reviewRejected[item]
        /\ artifacts.reviewTerminalWrites[item] = 0
        /\ artifacts' = [artifacts EXCEPT
            !.reviewAuthenticated[item] = (outcome = ReviewAuthenticated),
            !.reviewRejected[item] = (outcome = ReviewRejected),
            !.reviewTerminalWrites[item] = 1,
            !.reviewObservedAt[item] = clock.raw
           ]
        /\ clock' = DualRecordedClock(item)
        /\ audit' = [audit EXCEPT
            !.reviewCommits = @ \cup {
                <<acquisitionId,
                  outcome,
                  IF delivered THEN ReviewReturned ELSE ReviewLost>>
            }
           ]
        /\ volatileState' = [volatileState EXCEPT
            !.reviewIo[acquisitionId] = 0,
            !.reviewProof[acquisitionId] =
                IF outcome = ReviewAuthenticated /\ delivered THEN 1 ELSE 0
           ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<claims, acquisitions, nextLeaseFence>>

RecoverAuthenticatedReviewProof(acquisitionId) ==
    /\ acquisitionId \in AcquisitionIds
    /\ HasAcquisitionId(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ artifacts.reviewAuthenticated[item]
        /\ artifacts.reviewOrigin[item] = acquisitionId
        /\ volatileState.reviewProof[acquisitionId] < MaxAuthorityCopies
        /\ volatileState' = [volatileState EXCEPT
            !.reviewProof[acquisitionId] = @ + 1
           ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit
       >>

RecoverAuthenticatedReviewInProcess(acquisitionId) ==
    /\ volatileState.restartCount = 0
    /\ RecoverAuthenticatedReviewProof(acquisitionId)

RecoverAuthenticatedReviewAfterRestart(acquisitionId) ==
    /\ volatileState.restartCount > 0
    /\ RecoverAuthenticatedReviewProof(acquisitionId)

RecordAdmission(acquisitionId) ==
    /\ acquisitionId \in AcquisitionIds
    /\ HasAcquisitionId(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ artifacts.attempt[item]
        /\ artifacts.attemptOrigin[item] = acquisitionId
        /\ ~artifacts.admission[item]
        /\ ~artifacts.terminal[item]
        /\ artifacts' = [artifacts EXCEPT
            !.admission[item] = TRUE,
            !.admissionOrigin[item] = acquisitionId
           ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        audit,
        volatileState
       >>

(***************************************************************************
The authenticated review proof is the sole post-review input to the durable
ATTEMPT CAS.  A restart may reconstruct this proof without reconstructing a
generic acquisition authority.  This action models only the state boundary;
it does not recreate bearer custody or provider-wire authority after restart.
***************************************************************************)
CommitProviderAttemptBoundary(acquisitionId, delivered) ==
    /\ acquisitionId \in AcquisitionIds
    /\ delivered \in BOOLEAN
    /\ CurrentLiveAcquisition(acquisitionId)
    /\ OriginsMatch(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ artifacts.brokerCreate[item]
        /\ artifacts.brokerToken[item]
        /\ artifacts.reviewAuthenticated[item]
        /\ ~artifacts.reviewRejected[item]
        /\ volatileState.reviewProof[acquisitionId] > 0
        /\ ~artifacts.attempt[item]
        /\ artifacts' = [artifacts EXCEPT
            !.attempt[item] = TRUE,
            !.attemptOrigin[item] = acquisitionId,
            !.attemptOriginFence[item] =
                AcquisitionForId(acquisitionId)[3],
            !.attemptBindingVersion[item] = 2
           ]
        /\ clock' = DualRecordedClock(item)
        /\ audit' = [audit EXCEPT
            !.attemptCommits = @ \cup {
                <<acquisitionId,
                  IF delivered THEN AttemptReturned ELSE AttemptLost>>
            }
           ]
        /\ volatileState' = [volatileState EXCEPT
            !.reviewProof[acquisitionId] = @ - 1
           ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence
       >>

CommitLiveProviderAttempt(acquisitionId, delivered) ==
    /\ volatileState.restartCount = 0
    /\ CommitProviderAttemptBoundary(acquisitionId, delivered)

(***************************************************************************
Any durable broker/review artifact on an exact latest CLAIMED generation
proves that takeover is forbidden, while the absence of ATTEMPT proves that no
provider authority crossed the durable boundary.  Discovery may race a live
worker before or after restart, so the frozen closure and live attempt CAS must
both be enabled and exactly one may win.  The closure is a different claim
state from ATTEMPT: it consumes no acquisition authority, does not sample time,
cannot authorize admission or provider work, and retains the physical
reservation until exact Secret absence has aged past the rooted retirement
bound.  CREATE-only, TOKEN, review-in-flight, rejected, and authenticated
histories all share this path.
***************************************************************************)
CloseBrokerArtifactNoSend(acquisitionId) ==
    /\ acquisitionId \in AcquisitionIds
    /\ IsLatest(acquisitionId)
    /\ OriginsMatch(acquisitionId)
    /\ LET item == ItemForAcquisition(acquisitionId) IN
        /\ claims.present[item]
        /\ ~claims.disposed[item]
        /\ artifacts.broker[item]
        /\ artifacts.brokerOrigin[item] = acquisitionId
        /\ ~artifacts.attempt[item]
        /\ ~artifacts.admission[item]
        /\ ~artifacts.terminal[item]
        /\ ~claims.recoveryNoSend[item]
        /\ ~claims.recoveryRetired[item]
        /\ claims' = [claims EXCEPT
            !.recoveryNoSend[item] = TRUE,
            !.recoveryOrigin[item] = acquisitionId,
            !.recoveryOriginFence[item] =
                AcquisitionForId(acquisitionId)[3]
           ]
        /\ audit' = [audit EXCEPT
            !.recoveryClosures = @ \cup {acquisitionId}
           ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

(***************************************************************************
Retirement is an independent trusted-time CAS.  The exact historical cleanup
must have durably observed the bound Secret absent.  RECOVERY_NO_SEND keeps
the shared physical reservation active; RECOVERY_RETIRED releases it only at
or after absence + RetirementDelay, while advancing both durable clocks.  A
Pending response may first persist that safe-after bound.  Once persisted it
is immutable: a late terminal TokenReview observation cannot replace it with
a different timestamp.
***************************************************************************)
PersistRecoveryNoSendSafeAfter(item) ==
    /\ item \in Items
    /\ claims.recoveryNoSend[item]
    /\ ~claims.recoveryRetired[item]
    /\ artifacts.cleanup[item]
    /\ artifacts.deleteAbsent[item]
    /\ claims.recoverySafeAfter[item] = 0
    /\ artifacts.cleanupObservedAt[item] + RetirementDelay <= MaxTime
    /\ clock.raw >= DualHighWater(item)
    /\ clock' = DualRecordedClock(item)
    /\ claims' = [claims EXCEPT
        !.recoverySafeAfter[item] =
            artifacts.cleanupObservedAt[item] + RetirementDelay
       ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

RetireRecoveryNoSend(item) ==
    /\ item \in Items
    /\ claims.recoveryNoSend[item]
    /\ ~claims.recoveryRetired[item]
    /\ RecoveryRetirementReady(item)
    /\ clock' = DualRecordedClock(item)
    /\ claims' = [claims EXCEPT
        !.recoveryNoSend[item] = FALSE,
        !.recoveryRetired[item] = TRUE,
        !.recoverySafeAfter[item] =
            IF claims.recoverySafeAfter[item] = 0
            THEN artifacts.cleanupObservedAt[item] + RetirementDelay
            ELSE claims.recoverySafeAfter[item],
        !.recoveryRetiredAt[item] = clock.raw
       ]
    /\ audit' = [audit EXCEPT
        !.recoveryRetirements = @ \cup {claims.recoveryOrigin[item]}
       ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

(***************************************************************************
A reconciled CREATE absence with no TOKEN, review, attempt, admission, or
terminal fact proves that no credential ever existed.  It is therefore a
separate no-effect retirement profile: no deletion-propagation delay is
needed, and the frozen GET observation supplies both safe-after and retired-at.
***************************************************************************)
RetireRecoveryNoCredential(item) ==
    /\ item \in Items
    /\ claims.recoveryNoSend[item]
    /\ ~claims.recoveryRetired[item]
    /\ RecoveryNoCredentialReady(item)
    /\ claims' = [claims EXCEPT
        !.recoveryNoSend[item] = FALSE,
        !.recoveryRetired[item] = TRUE,
        !.recoverySafeAfter[item] = artifacts.createAbsentObservedAt[item],
        !.recoveryRetiredAt[item] = artifacts.createAbsentObservedAt[item]
       ]
    /\ audit' = [audit EXCEPT
        !.recoveryRetirements = @ \cup {claims.recoveryOrigin[item]}
       ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        acquisitions,
        nextLeaseFence,
        artifacts,
        volatileState
       >>

RecordTerminal(item) ==
    /\ item \in Items
    /\ artifacts.attempt[item]
    /\ ~artifacts.terminal[item]
    /\ artifacts' = [artifacts EXCEPT !.terminal[item] = TRUE]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        audit,
        volatileState
       >>

(***************************************************************************
Cleanup/reconciliation is historical journal work.  Its trusted sample
advances both HWM keys, but it neither reconstructs acquisition authority nor
creates a provider attempt.  It may run immediately after a durable broker or
review artifact is discovered on restart; waiting for lease expiry is not a
safety prerequisite.  Snapshots make that property state-checkable after the
cleanup action.
***************************************************************************)
ReconcileBrokerHistorically(item) ==
    /\ item \in Items
    /\ artifacts.broker[item]
    /\ ~artifacts.cleanup[item]
    /\ ~artifacts.createAbsent[item]
    /\ HasAcquisitions(item)
    /\ clock.raw >= DualHighWater(item)
    /\ clock' = DualRecordedClock(item)
        /\ artifacts' = [artifacts EXCEPT
            !.cleanup[item] = TRUE,
            !.deleteAbsent[item] = TRUE,
            !.deleteAbsentWrites[item] = 1,
            !.cleanupFence[item] = LatestFence(item),
        !.cleanupAcquisitionCount[item] =
            Cardinality(AcquisitionsFor(item)),
        !.cleanupAuthorityGrantCount[item] =
            Cardinality(AuthorityGrantsFor(item)),
            !.cleanupAttempt[item] = artifacts.attempt[item],
            !.cleanupObservedAt[item] = clock.raw
           ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        audit,
        volatileState
       >>

(***************************************************************************
GET-only reconciliation of an uncertain CREATE may prove the deterministic
empty Secret absent.  TOKEN requires a durable matching CREATE, so this fact
irreversibly excludes credential and provider authority for the generation.
***************************************************************************)
ObserveCreateAbsentHistorically(item) ==
    /\ item \in Items
    /\ artifacts.brokerCreate[item]
    /\ ~artifacts.brokerToken[item]
    /\ ~artifacts.createAbsent[item]
    /\ ~artifacts.cleanup[item]
    /\ HasAcquisitions(item)
    /\ clock.raw >= DualHighWater(item)
    /\ clock' = DualRecordedClock(item)
    /\ artifacts' = [artifacts EXCEPT
        !.createAbsent[item] = TRUE,
        !.createAbsentWrites[item] = 1,
        !.createAbsentObservedAt[item] = clock.raw
       ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        claims,
        acquisitions,
        nextLeaseFence,
        audit,
        volatileState
       >>

ReconcileBrokerBeforeLeaseExpiry(item) ==
    /\ HasAcquisitions(item)
    /\ clock.raw < LatestLeaseUntil(item)
    /\ ReconcileBrokerHistorically(item)

ReconcileBrokerAtOrAfterLeaseExpiry(item) ==
    /\ HasAcquisitions(item)
    /\ clock.raw >= LatestLeaseUntil(item)
    /\ ReconcileBrokerHistorically(item)

(***************************************************************************
The server discovers the oldest durable recovery item without requiring the
caller to know its historical claim, acquisition UUID, or worker.  The new
request identity remains entirely unbound: the returned opaque selector is
derived from the latest durable acquisition and this read creates neither a
new acquisition generation nor an authority grant.
***************************************************************************)
DiscoverRecoveryRequired ==
    /\ UnusedRequestIds # {}
    /\ ServerWorkItems # {}
    /\ SelectedServerItem \in RecoveryCandidateItems
    /\ LET item == SelectedServerItem IN
       LET historicalId == LatestAcquisitionId(item) IN
        /\ observation' = RequestObservation(
            RecoveryRequiredOutcome,
            ArtifactReason(item),
            historicalId,
            CanonicalObservationWorker,
            item)
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

NoWork ==
    /\ UnusedRequestIds # {}
    /\ ServerWorkItems = {}
    /\ observation' = RequestObservation(
        NoWorkOutcome,
        NoReason,
        CanonicalObservationRequestId,
        CanonicalObservationWorker,
        NoItem)
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit,
        volatileState
       >>

Restart ==
    /\ volatileState.restartCount = 0
    /\ volatileState' = [volatileState EXCEPT
        !.held = [acquisitionId \in AcquisitionIds |-> 0],
        !.reviewIo = [acquisitionId \in AcquisitionIds |-> 0],
        !.reviewProof = [acquisitionId \in AcquisitionIds |-> 0],
        !.restartCount = 1
       ]
    /\ observation' = NoObservation
    /\ UNCHANGED <<
        clock,
        claims,
        acquisitions,
        nextLeaseFence,
        artifacts,
        audit
       >>

Next ==
    \/ \E sample \in 0..MaxTime : SetRawClock(sample)
    \/ AdvanceExternalScope
    \/ AdvanceExternalIngress
    \/ \E item \in Items : RotateAuthority(item)
    \/ \E item \in Items : RevokeGrant(item)
    \/ \E worker \in Workers, requestId \in AcquisitionIds :
        DisposeUnclaimedDeadlineReturned(worker, requestId)
    \/ \E worker \in Workers, requestId \in AcquisitionIds :
        DisposeClaimBoundDeadlineReturned(worker, requestId)
    \/ \E worker \in Workers, requestId \in AcquisitionIds :
        DisposeDeadlineLost(worker, requestId)
    \/ \E worker \in Workers,
          requestId \in AcquisitionIds,
          delivered \in BOOLEAN :
        DisposeAuthorityChanged(worker, requestId, delivered)
    \/ \E worker \in Workers,
          requestId \in AcquisitionIds,
          delivered \in BOOLEAN :
        DisposeGrantRevoked(worker, requestId, delivered)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        AcquireFreshReturned(worker, acquisitionId)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        AcquireFreshAfterDispositionReturned(worker, acquisitionId)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        AcquireFreshLost(worker, acquisitionId)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        AcquireTakeoverReturned(worker, acquisitionId)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        AcquireTakeoverLost(worker, acquisitionId)
    \/ RejectAcquireRollback
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        RecoverLive(worker, acquisitionId)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        RecoverExpired(worker, acquisitionId)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        RecoverSuperseded(worker, acquisitionId)
    \/ \E worker \in Workers, requestId \in AcquisitionIds :
        RecoverDisposition(worker, requestId)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        RecoverQueueDisposed(worker, acquisitionId)
    \/ \E worker \in Workers,
          acquisitionId \in AcquisitionIds,
          reason \in {
            BrokerReason,
            AdmissionReason,
            AttemptReason,
            RecoveryNoSendReason,
            RecoveryRetiredReason,
            TerminalReason
          } :
        RecoverQuarantined(worker, acquisitionId, reason)
    \/ \E worker \in Workers, acquisitionId \in AcquisitionIds :
        RejectRecoveryRollback(worker, acquisitionId)
    \/ DiscoverRecoveryRequired
    \/ \E acquisitionId \in AcquisitionIds :
        CreateBrokerIntent(acquisitionId)
    \/ \E acquisitionId \in AcquisitionIds :
        CreateTokenBrokerIntent(acquisitionId)
    \/ \E acquisitionId \in AcquisitionIds, delivered \in BOOLEAN :
        BeginCredentialReview(acquisitionId, delivered)
    \/ \E acquisitionId \in AcquisitionIds,
          outcome \in ReviewOutcomes,
          delivered \in BOOLEAN :
        RecordCredentialReview(acquisitionId, outcome, delivered)
    \/ \E acquisitionId \in AcquisitionIds :
        RecoverAuthenticatedReviewInProcess(acquisitionId)
    \/ \E acquisitionId \in AcquisitionIds :
        RecoverAuthenticatedReviewAfterRestart(acquisitionId)
    \/ \E acquisitionId \in AcquisitionIds, delivered \in BOOLEAN :
        CommitLiveProviderAttempt(acquisitionId, delivered)
    \/ \E acquisitionId \in AcquisitionIds :
        CloseBrokerArtifactNoSend(acquisitionId)
    \/ \E item \in Items : PersistRecoveryNoSendSafeAfter(item)
    \/ \E item \in Items : RetireRecoveryNoSend(item)
    \/ \E item \in Items : RetireRecoveryNoCredential(item)
    \/ \E acquisitionId \in AcquisitionIds :
        RecordAdmission(acquisitionId)
    \/ \E item \in Items : RecordTerminal(item)
    \/ \E item \in Items : ReconcileBrokerBeforeLeaseExpiry(item)
    \/ \E item \in Items : ReconcileBrokerAtOrAfterLeaseExpiry(item)
    \/ \E item \in Items : ObserveCreateAbsentHistorically(item)
    \/ NoWork
    \/ Restart

Spec == Init /\ [][Next]_vars

ClockType == [
    raw : 0..MaxTime,
    scope : [Items -> 0..MaxTime],
    ingress : [Items -> 0..MaxTime],
    scopeHistory : [Items -> SUBSET (0..MaxTime)],
    ingressHistory : [Items -> SUBSET (0..MaxTime)],
    externalScopeSeen : BOOLEAN,
    externalIngressSeen : BOOLEAN
]

ClaimsType == [
    phaseCompleted : [Items -> BOOLEAN],
    phaseCompletionExecutable : [Items -> BOOLEAN],
    present : [Items -> BOOLEAN],
    disposed : [Items -> BOOLEAN],
    recoveryNoSend : [Items -> BOOLEAN],
    recoveryRetired : [Items -> BOOLEAN],
    recoveryOrigin : [Items -> AcquisitionIds \cup {NoAcquisition}],
    recoveryOriginFence : [Items -> 0..MaxAcquisitions],
    recoverySafeAfter : [Items -> 0..MaxTime],
    recoveryRetiredAt : [Items -> 0..MaxTime],
    id : [Items -> StableClaimIds \cup {NoAcquisition}],
    fence : [Items -> 0..Cardinality(Items)],
    authorityCurrent : [Items -> BOOLEAN],
    grantRevoked : [Items -> BOOLEAN]
]

ArtifactType == [
    broker : [Items -> BOOLEAN],
    brokerCreate : [Items -> BOOLEAN],
    brokerCreateWrites : [Items -> 0..1],
    createAbsent : [Items -> BOOLEAN],
    createAbsentWrites : [Items -> 0..1],
    createAbsentObservedAt : [Items -> 0..MaxTime],
    brokerToken : [Items -> BOOLEAN],
    brokerTokenWrites : [Items -> 0..1],
    brokerOrigin : [Items -> AcquisitionIds \cup {NoAcquisition}],
    brokerOriginFence : [Items -> 0..MaxAcquisitions],
    brokerBindingVersion : [Items -> 0..2],
    reviewStarted : [Items -> BOOLEAN],
    reviewAuthenticated : [Items -> BOOLEAN],
    reviewRejected : [Items -> BOOLEAN],
    reviewBeginWrites : [Items -> 0..1],
    reviewTerminalWrites : [Items -> 0..1],
    reviewOrigin : [Items -> AcquisitionIds \cup {NoAcquisition}],
    reviewOriginFence : [Items -> 0..MaxAcquisitions],
    reviewBindingVersion : [Items -> 0..2],
    reviewObservedAt : [Items -> 0..MaxTime],
    admission : [Items -> BOOLEAN],
    admissionOrigin : [Items -> AcquisitionIds \cup {NoAcquisition}],
    attempt : [Items -> BOOLEAN],
    attemptOrigin : [Items -> AcquisitionIds \cup {NoAcquisition}],
    attemptOriginFence : [Items -> 0..MaxAcquisitions],
    attemptBindingVersion : [Items -> 0..2],
    terminal : [Items -> BOOLEAN],
    cleanup : [Items -> BOOLEAN],
    deleteAbsent : [Items -> BOOLEAN],
    deleteAbsentWrites : [Items -> 0..1],
    cleanupFence : [Items -> 0..MaxAcquisitions],
    cleanupAcquisitionCount : [Items -> 0..MaxAcquisitions],
    cleanupAuthorityGrantCount : [
        Items -> 0..(2 * MaxAcquisitions * (MaxTime + 1))
    ],
    cleanupAttempt : [Items -> BOOLEAN],
    cleanupObservedAt : [Items -> 0..MaxTime]
]

AcquisitionType ==
    Items
        \X AcquisitionIds
        \X (1..MaxAcquisitions)
        \X Workers
        \X (0..MaxTime)
        \X (0..MaxTime)

AuthorityGrantType ==
    AcquisitionIds
        \X GrantKinds
        \X (0..MaxTime)
        \X (1..MaxAuthorityGrantsPerAcquisition)

QueueDispositionType ==
    Items
        \X AcquisitionIds
        \X Workers
        \X QueueDispositionReasons
        \X (0..MaxTime)
        \X (AcquisitionIds \cup {NoAcquisition})

AuditType == [
    queueDispositions : SUBSET QueueDispositionType,
    authorityGrants : SUBSET AuthorityGrantType,
    authorityGrantCount : [
        AcquisitionIds -> 0..MaxAuthorityGrantsPerAcquisition
    ],
    unknownCommits : SUBSET AcquisitionIds,
    unknownDispositionCommits : SUBSET AcquisitionIds,
    inertReceipts : SUBSET (
        AcquisitionIds \X {ExpiredReason, SupersededReason}
    ),
    quarantineReceipts : SUBSET (
        AcquisitionIds
            \X {
                BrokerReason,
                AdmissionReason,
                AttemptReason,
                RecoveryNoSendReason,
                RecoveryRetiredReason,
                TerminalReason,
                QueueDisposedReason
               }
    ),
    unknownReviewBegins : SUBSET AcquisitionIds,
    reviewCommits : SUBSET (
        AcquisitionIds \X ReviewOutcomes \X ReviewDeliveryKinds
    ),
    attemptCommits : SUBSET (
        AcquisitionIds \X AttemptDeliveryKinds
    ),
    recoveryClosures : SUBSET AcquisitionIds,
    recoveryRetirements : SUBSET AcquisitionIds
]

VolatileType == [
    held : [AcquisitionIds -> 0..MaxAuthorityCopies],
    reviewIo : [AcquisitionIds -> 0..1],
    reviewProof : [AcquisitionIds -> 0..MaxAuthorityCopies],
    restartCount : 0..1
]

ObservationType == [
    outcome : Outcomes,
    reason : Reasons,
    requestId : AcquisitionIds \cup {NoAcquisition},
    worker : Workers \cup {NoWorker},
    item : Items \cup {NoItem},
    beforeScope : [Items -> 0..MaxTime],
    beforeIngress : [Items -> 0..MaxTime],
    beforeAcquisitionCount : 0..MaxAcquisitions,
    beforeDispositionCount : 0..Cardinality(Items),
    beforeAuthorityGrantCount :
        0..(2 * MaxAcquisitions * (MaxTime + 1))
]

TypeOK ==
    /\ clock \in ClockType
    /\ claims \in ClaimsType
    /\ acquisitions \subseteq AcquisitionType
    /\ nextLeaseFence \in 0..MaxAcquisitions
    /\ artifacts \in ArtifactType
    /\ audit \in AuditType
    /\ volatileState \in VolatileType
    /\ observation \in ObservationType

PhaseCompletedIsPrerequisiteAndInert ==
    /\ \A item \in Items :
        /\ claims.phaseCompleted[item]
        /\ ~claims.phaseCompletionExecutable[item]
    /\ \A record \in acquisitions :
        claims.phaseCompleted[record[1]]

StableClaimIdentityIsImmutable ==
    /\ \A item \in Items :
        /\ (claims.present[item] <=> HasAcquisitions(item))
        /\ (claims.disposed[item] => claims.present[item])
        /\ (claims.recoveryNoSend[item] => claims.present[item])
        /\ (claims.recoveryRetired[item] => claims.present[item])
        /\ ~(claims.recoveryNoSend[item] /\ claims.recoveryRetired[item])
        /\ (claims.present[item] =>
            /\ claims.id[item] = ExpectedClaimId(item)
            /\ claims.fence[item] = ExpectedClaimFence(item))
        /\ (~claims.present[item] =>
            /\ claims.id[item] = NoAcquisition
            /\ claims.fence[item] = 0
            /\ ~claims.recoveryNoSend[item]
            /\ ~claims.recoveryRetired[item])
    /\ claims.present[1] /\ claims.present[2] =>
        /\ claims.id[1] # claims.id[2]
        /\ claims.fence[1] # claims.fence[2]

AcquisitionHistoryIsAppendOnlyFreshAndFenced ==
    /\ Cardinality(acquisitions) = nextLeaseFence
    /\ \A first, second \in acquisitions :
        /\ (first[2] = second[2] => first = second)
        /\ (first[3] = second[3] => first = second)
    /\ \A fence \in 1..nextLeaseFence :
        \E record \in acquisitions : record[3] = fence
    /\ \A record \in acquisitions :
        /\ record[5] < record[6]
        /\ record[6] <= DispatchDeadline(record[1])
        /\ record[3] <= nextLeaseFence
    /\ \A first, later \in acquisitions :
        first[1] = later[1] /\ first[3] < later[3] =>
            first[6] <= later[5]

QueueDispositionsAreExactInertAndReleaseClaims ==
    /\ \A first, second \in audit.queueDispositions :
        /\ (first[1] = second[1] => first = second)
        /\ (first[2] = second[2] => first = second)
    /\ \A receipt \in audit.queueDispositions :
        /\ ~HasAcquisitionId(receipt[2])
        /\ receipt[4] \in QueueDispositionReasons
        /\ IF receipt[6] = NoAcquisition
              THEN ~claims.present[receipt[1]]
              ELSE /\ HasAcquisitionId(receipt[6])
                   /\ ItemForAcquisition(receipt[6]) = receipt[1]
                   /\ LatestAcquisitionId(receipt[1]) = receipt[6]
                   /\ claims.disposed[receipt[1]]
    /\ \A item \in Items :
        /\ (claims.disposed[item] <=>
            \E receipt \in DispositionsFor(item) :
                receipt[6] # NoAcquisition)
        /\ (claims.disposed[item] =>
            /\ ~Candidate(item)
            /\ \A acquisitionId \in AcquisitionIds :
                HasAcquisitionId(acquisitionId)
                    /\ ItemForAcquisition(acquisitionId) = item =>
                    ~CurrentHeldAuthority(acquisitionId))

ActivePhysicalReservationIsExclusive ==
    Cardinality({item \in Items : ReservationActive(item)}) <= 1

RecoveryRetirementReleasesSharedResource ==
    claims.recoveryRetired[1]
        /\ ~claims.present[2]
        /\ ~HasQueueDisposition(2)
        /\ clock.raw < DispatchDeadline(2)
        /\ CurrentDispatchFacts(2) =>
        /\ ~ReservationActive(1)
        /\ PhysicalResourceAvailable(2)
        /\ Candidate(2)

RecoveryNoSendIsExplicitInertAndSafelyRetired ==
    /\ \A item \in Items :
        /\ (claims.recoveryNoSend[item] \/ claims.recoveryRetired[item] <=>
            claims.recoveryOrigin[item] \in audit.recoveryClosures)
        /\ (claims.recoveryRetired[item] <=>
            claims.recoveryOrigin[item] \in audit.recoveryRetirements)
        /\ (claims.recoveryNoSend[item] =>
            /\ ReservationActive(item)
            /\ claims.recoverySafeAfter[item] \in {
                0,
                artifacts.cleanupObservedAt[item] + RetirementDelay
               }
            /\ (claims.recoverySafeAfter[item] # 0 =>
                /\ artifacts.cleanup[item]
                /\ artifacts.deleteAbsent[item]
                /\ claims.recoverySafeAfter[item] <= MaxTime)
            /\ claims.recoveryRetiredAt[item] = 0)
        /\ (claims.recoveryNoSend[item] \/ claims.recoveryRetired[item] =>
            /\ HasAcquisitionId(claims.recoveryOrigin[item])
            /\ LatestAcquisitionId(item) = claims.recoveryOrigin[item]
            /\ claims.recoveryOriginFence[item] =
                AcquisitionForId(claims.recoveryOrigin[item])[3]
            /\ artifacts.broker[item]
            /\ artifacts.brokerOrigin[item] = claims.recoveryOrigin[item]
            /\ artifacts.brokerCreate[item]
            /\ ~artifacts.attempt[item]
            /\ ~artifacts.admission[item]
            /\ ~artifacts.terminal[item])
        /\ (claims.recoveryRetired[item] =>
            /\ ~ReservationActive(item)
            /\ \/ /\ artifacts.cleanup[item]
                    /\ artifacts.deleteAbsent[item]
                    /\ claims.recoverySafeAfter[item] =
                        artifacts.cleanupObservedAt[item] + RetirementDelay
                    /\ claims.recoveryRetiredAt[item] >=
                        claims.recoverySafeAfter[item]
                    /\ claims.recoveryRetiredAt[item] \in
                        clock.scopeHistory[item]
                    /\ claims.recoveryRetiredAt[item] \in
                        clock.ingressHistory[item]
               \/ /\ RecoveryNoCredentialReady(item)
                    /\ claims.recoverySafeAfter[item] =
                        artifacts.createAbsentObservedAt[item]
                    /\ claims.recoveryRetiredAt[item] =
                        artifacts.createAbsentObservedAt[item]
                    /\ claims.recoveryRetiredAt[item] \in
                        clock.scopeHistory[item]
                    /\ claims.recoveryRetiredAt[item] \in
                        clock.ingressHistory[item])
    /\ \A acquisitionId \in audit.recoveryClosures :
        /\ HasAcquisitionId(acquisitionId)
        /\ LET item == ItemForAcquisition(acquisitionId) IN
            /\ artifacts.broker[item]
            /\ artifacts.brokerOrigin[item] = acquisitionId
            /\ ~artifacts.attempt[item]
    /\ audit.recoveryRetirements \subseteq audit.recoveryClosures

AuthorityCopiesAreBoundedAndAudited ==
    /\ \A acquisitionId \in AcquisitionIds :
        /\ audit.authorityGrantCount[acquisitionId] =
            Cardinality({grant \in audit.authorityGrants :
                grant[1] = acquisitionId})
        /\ volatileState.held[acquisitionId]
            <= audit.authorityGrantCount[acquisitionId]
        /\ \A serial \in 1..audit.authorityGrantCount[acquisitionId] :
            \E grant \in audit.authorityGrants :
                /\ grant[1] = acquisitionId
                /\ grant[4] = serial
    /\ \A first, second \in audit.authorityGrants :
        first[1] = second[1] /\ first[4] = second[4] =>
            first = second
    /\ \A grant \in audit.authorityGrants :
        /\ HasAcquisitionId(grant[1])
        /\ LET record == AcquisitionForId(grant[1]) IN
            /\ grant[3] >= record[5]
            /\ grant[3] < record[6]
            /\ grant[3] < DispatchDeadline(record[1])

ServerSelectionIsFIFO ==
    (HasAcquisitions(2) \/ HasQueueDisposition(2)) =>
        \/ HasAcquisitions(1)
        \/ HasQueueDisposition(1)

DualHighWaterIsMonotoneAndCovered ==
    /\ \A item \in Items :
        /\ clock.scope[item] \in clock.scopeHistory[item]
        /\ clock.ingress[item] \in clock.ingressHistory[item]
        /\ \A sample \in clock.scopeHistory[item] :
            sample <= clock.scope[item]
        /\ \A sample \in clock.ingressHistory[item] :
            sample <= clock.ingress[item]
    /\ \A receipt \in audit.queueDispositions :
        /\ receipt[5] \in clock.scopeHistory[receipt[1]]
        /\ receipt[5] \in clock.ingressHistory[receipt[1]]
        /\ receipt[5] <= clock.scope[receipt[1]]
        /\ receipt[5] <= clock.ingress[receipt[1]]
        /\ (receipt[4] = DeadlineDispositionReason =>
            receipt[5] >= DispatchDeadline(receipt[1]))

AuthorityResponsesAreExactCurrentAndLive ==
    observation.outcome = AuthorityOutcome =>
        /\ observation.reason \in {AcquiredReason, RecoveredReason}
        /\ volatileState.held[observation.requestId] > 0
        /\ IsLatest(observation.requestId)
        /\ LET record == AcquisitionForId(observation.requestId) IN
            /\ record[1] = observation.item
            /\ record[4] = observation.worker
            /\ ~claims.disposed[record[1]]
            /\ CurrentDispatchFacts(record[1])
            /\ clock.raw >= DualHighWater(record[1])
            /\ clock.raw < record[6]
            /\ clock.raw < DispatchDeadline(record[1])
            /\ NoArtifacts(record[1])
            /\ ~artifacts.cleanup[record[1]]

HistoricalResponsesNeverMintAuthority ==
    /\ observation.outcome \in {
        OutcomeUnknown,
        InertOutcome,
        QuarantinedOutcome,
        RecoveryRequiredOutcome,
        RollbackOutcome,
        NoWorkOutcome
       } =>
        Cardinality(audit.authorityGrants) =
            observation.beforeAuthorityGrantCount
    /\ observation.outcome = DisposedOutcome =>
        /\ HasDispositionId(observation.requestId)
        /\ LET receipt == DispositionForId(observation.requestId) IN
            /\ receipt[1] = observation.item
            /\ receipt[3] = observation.worker
            /\ receipt[4] = observation.reason
            /\ Cardinality(audit.authorityGrants) =
                observation.beforeAuthorityGrantCount
    /\ observation.outcome = InertOutcome =>
        <<observation.requestId, observation.reason>>
            \in audit.inertReceipts
    /\ observation.outcome = QuarantinedOutcome =>
        <<observation.requestId, observation.reason>>
            \in audit.quarantineReceipts
    /\ observation.outcome = OutcomeUnknown =>
        \/ /\ observation.requestId \in audit.unknownCommits
           /\ HasAcquisitionId(observation.requestId)
           /\ Cardinality(acquisitions) =
                observation.beforeAcquisitionCount + 1
           /\ Cardinality(audit.queueDispositions) =
                observation.beforeDispositionCount
        \/ /\ observation.requestId \in audit.unknownDispositionCommits
           /\ HasDispositionId(observation.requestId)
           /\ Cardinality(acquisitions) =
                observation.beforeAcquisitionCount
           /\ Cardinality(audit.queueDispositions) =
                observation.beforeDispositionCount + 1

ServerRecoveryDiscoveryIsFIFOAndByteInert ==
    /\ CandidateItems \intersect RecoveryCandidateItems = {}
    /\ observation.outcome = NoWorkOutcome => ServerWorkItems = {}
    /\ observation.outcome = RecoveryRequiredOutcome =>
        /\ ServerWorkItems # {}
        /\ observation.item = SelectedServerItem
        /\ observation.item \in RecoveryCandidateItems
        /\ observation.requestId =
            LatestAcquisitionId(observation.item)
        /\ observation.reason = ArtifactReason(observation.item)
        /\ clock.scope = observation.beforeScope
        /\ clock.ingress = observation.beforeIngress
        /\ Cardinality(acquisitions) =
            observation.beforeAcquisitionCount
        /\ Cardinality(audit.queueDispositions) =
            observation.beforeDispositionCount
        /\ Cardinality(audit.authorityGrants) =
            observation.beforeAuthorityGrantCount

RecoverySchedulingRequiresUsefulTransition ==
    \A item \in Items :
        /\ (artifacts.attempt[item]
                /\ artifacts.cleanup[item]
                /\ ~claims.recoveryNoSend[item] =>
            ~RecoveryCandidate(item))
        /\ (claims.recoveryNoSend[item]
                /\ artifacts.cleanup[item]
                /\ ~RecoveryRetirementReady(item) =>
            ~RecoveryCandidate(item))
        /\ (claims.recoveryNoSend[item]
                /\ ~claims.recoveryRetired[item]
                /\ RecoveryNoCredentialReady(item) =>
            RecoveryCandidate(item))

RollbackRejectionIsByteInert ==
    observation.outcome = RollbackOutcome =>
        /\ observation.reason \in {
            ScopeRollbackReason,
            IngressRollbackReason,
            DualRollbackReason
           }
        /\ clock.scope = observation.beforeScope
        /\ clock.ingress = observation.beforeIngress
        /\ Cardinality(acquisitions) =
            observation.beforeAcquisitionCount
        /\ Cardinality(audit.queueDispositions) =
            observation.beforeDispositionCount
        /\ Cardinality(audit.authorityGrants) =
            observation.beforeAuthorityGrantCount

InertAndQuarantineClassesAreDisjoint ==
    /\ \A receipt \in audit.inertReceipts :
        receipt \notin audit.quarantineReceipts
    /\ observation.outcome = InertOutcome =>
        observation.reason \in {ExpiredReason, SupersededReason}
    /\ observation.outcome = QuarantinedOutcome =>
        observation.reason \in {
            BrokerReason,
            AdmissionReason,
            AttemptReason,
            RecoveryNoSendReason,
            RecoveryRetiredReason,
            TerminalReason,
            QueueDisposedReason
           }

ArtifactsBindTheLatestAcquisition ==
    \A item \in Items :
        /\ (artifacts.broker[item] <=>
            artifacts.brokerOrigin[item] # NoAcquisition)
        /\ (artifacts.broker[item] <=>
            artifacts.brokerCreate[item] \/ artifacts.brokerToken[item])
        /\ (artifacts.brokerCreate[item] <=>
            artifacts.brokerCreateWrites[item] = 1)
        /\ (artifacts.createAbsent[item] <=>
            artifacts.createAbsentWrites[item] = 1)
        /\ (artifacts.createAbsent[item] =>
            /\ artifacts.brokerCreate[item]
            /\ ~artifacts.brokerToken[item]
            /\ artifacts.createAbsentObservedAt[item] \in
                clock.scopeHistory[item]
            /\ artifacts.createAbsentObservedAt[item] \in
                clock.ingressHistory[item])
        /\ (~artifacts.createAbsent[item] =>
            artifacts.createAbsentObservedAt[item] = 0)
        /\ (artifacts.brokerToken[item] <=>
            artifacts.brokerTokenWrites[item] = 1)
        /\ (artifacts.brokerToken[item] =>
            /\ artifacts.brokerCreate[item]
            /\ ~artifacts.createAbsent[item])
        /\ (artifacts.broker[item] <=>
            artifacts.brokerBindingVersion[item] = 2)
        /\ (~artifacts.broker[item] =>
            /\ artifacts.brokerOriginFence[item] = 0
            /\ artifacts.brokerBindingVersion[item] = 0)
        /\ (artifacts.reviewStarted[item] <=>
            artifacts.reviewBeginWrites[item] = 1)
        /\ (artifacts.reviewStarted[item] <=>
            artifacts.reviewOrigin[item] # NoAcquisition)
        /\ (artifacts.reviewAuthenticated[item] =>
            /\ artifacts.reviewStarted[item]
            /\ ~artifacts.reviewRejected[item])
        /\ (artifacts.reviewRejected[item] =>
            /\ artifacts.reviewStarted[item]
            /\ ~artifacts.reviewAuthenticated[item])
        /\ (artifacts.reviewTerminalWrites[item] = 1 <=>
            artifacts.reviewAuthenticated[item]
                \/ artifacts.reviewRejected[item])
        /\ (~artifacts.reviewStarted[item] =>
            /\ artifacts.reviewTerminalWrites[item] = 0
            /\ artifacts.reviewOriginFence[item] = 0
            /\ artifacts.reviewBindingVersion[item] = 0
            /\ artifacts.reviewObservedAt[item] = 0)
        /\ (artifacts.reviewTerminalWrites[item] = 1 =>
            /\ artifacts.reviewObservedAt[item] >=
                AcquisitionForId(artifacts.reviewOrigin[item])[5]
            /\ (artifacts.reviewAuthenticated[item] =>
                artifacts.reviewObservedAt[item] <
                    AcquisitionForId(artifacts.reviewOrigin[item])[6]))
        /\ (artifacts.admission[item] <=>
            artifacts.admissionOrigin[item] # NoAcquisition)
        /\ (artifacts.attempt[item] <=>
            artifacts.attemptOrigin[item] # NoAcquisition)
        /\ (artifacts.attempt[item] <=>
            artifacts.attemptBindingVersion[item] = 2)
        /\ (~artifacts.attempt[item] =>
            /\ artifacts.attemptOriginFence[item] = 0
            /\ artifacts.attemptBindingVersion[item] = 0)
        /\ (artifacts.broker[item] =>
            /\ HasAcquisitionId(artifacts.brokerOrigin[item])
            /\ ItemForAcquisition(artifacts.brokerOrigin[item]) = item
            /\ LatestAcquisitionId(item) = artifacts.brokerOrigin[item]
            /\ artifacts.brokerOriginFence[item] =
                AcquisitionForId(artifacts.brokerOrigin[item])[3]
            /\ artifacts.brokerBindingVersion[item] = 2)
        /\ (artifacts.reviewStarted[item] =>
            /\ artifacts.brokerCreate[item]
            /\ artifacts.brokerToken[item]
            /\ HasAcquisitionId(artifacts.reviewOrigin[item])
            /\ ItemForAcquisition(artifacts.reviewOrigin[item]) = item
            /\ LatestAcquisitionId(item) = artifacts.reviewOrigin[item]
            /\ artifacts.reviewOrigin[item] = artifacts.brokerOrigin[item]
            /\ artifacts.reviewOriginFence[item] =
                AcquisitionForId(artifacts.reviewOrigin[item])[3]
            /\ artifacts.reviewBindingVersion[item] = 2)
        /\ (artifacts.admission[item] =>
            /\ HasAcquisitionId(artifacts.admissionOrigin[item])
            /\ ItemForAcquisition(artifacts.admissionOrigin[item]) = item
            /\ LatestAcquisitionId(item) = artifacts.admissionOrigin[item]
            /\ artifacts.attempt[item]
            /\ artifacts.admissionOrigin[item] =
                artifacts.attemptOrigin[item])
        /\ (artifacts.attempt[item] =>
            /\ HasAcquisitionId(artifacts.attemptOrigin[item])
            /\ ItemForAcquisition(artifacts.attemptOrigin[item]) = item
            /\ LatestAcquisitionId(item) = artifacts.attemptOrigin[item]
            /\ artifacts.attemptOriginFence[item] =
                AcquisitionForId(artifacts.attemptOrigin[item])[3]
            /\ artifacts.attemptBindingVersion[item] = 2
            /\ artifacts.reviewAuthenticated[item]
            /\ artifacts.reviewOrigin[item] = artifacts.attemptOrigin[item]
            /\ ~claims.recoveryNoSend[item]
            /\ ~claims.recoveryRetired[item]
            /\ ~CurrentHeldAuthority(artifacts.attemptOrigin[item]))
        /\ (artifacts.terminal[item] => artifacts.attempt[item])
        /\ (artifacts.cleanup[item] <=> artifacts.deleteAbsent[item])
        /\ (artifacts.deleteAbsent[item] <=>
            artifacts.deleteAbsentWrites[item] = 1)
        /\ (~artifacts.cleanup[item] => artifacts.cleanupObservedAt[item] = 0)

BrokerIntentBarsRecoveryAndTakeover ==
    \A item \in Items :
        artifacts.broker[item] =>
            /\ ~Candidate(item)
            /\ \A grant \in AuthorityGrantsFor(item) :
                AcquisitionForId(grant[1])[3]
                    <= AcquisitionForId(artifacts.brokerOrigin[item])[3]

ProviderAttemptConsumesOnlyLatest ==
    \A item \in Items :
        artifacts.attempt[item] =>
            /\ artifacts.attemptOrigin[item] = LatestAcquisitionId(item)
            /\ ~CurrentHeldAuthority(artifacts.attemptOrigin[item])
            /\ \E delivery \in AttemptDeliveryKinds :
                <<artifacts.attemptOrigin[item], delivery>>
                    \in audit.attemptCommits

CredentialReviewIsBoundAndAtMostOnce ==
    /\ \A item \in Items :
        /\ (artifacts.reviewAuthenticated[item]
                \/ artifacts.reviewRejected[item] =>
            Cardinality({commit \in audit.reviewCommits :
                commit[1] = artifacts.reviewOrigin[item]}) = 1)
        /\ (artifacts.reviewRejected[item] => ~artifacts.attempt[item])
        /\ (artifacts.attempt[item] =>
            /\ artifacts.reviewAuthenticated[item]
            /\ ~artifacts.reviewRejected[item]
            /\ volatileState.reviewIo[
                artifacts.attemptOrigin[item]] = 0)
    /\ \A acquisitionId \in AcquisitionIds :
        /\ (volatileState.reviewIo[acquisitionId] = 1 =>
            /\ HasAcquisitionId(acquisitionId)
            /\ LET item == ItemForAcquisition(acquisitionId) IN
                /\ artifacts.reviewStarted[item]
                /\ artifacts.reviewOrigin[item] = acquisitionId
                /\ ~artifacts.reviewAuthenticated[item]
                /\ ~artifacts.reviewRejected[item])
        /\ (volatileState.reviewProof[acquisitionId] > 0 =>
            /\ HasAcquisitionId(acquisitionId)
            /\ LET item == ItemForAcquisition(acquisitionId) IN
                /\ artifacts.reviewAuthenticated[item]
                /\ artifacts.reviewOrigin[item] = acquisitionId)
        /\ (acquisitionId \in audit.unknownReviewBegins =>
            /\ HasAcquisitionId(acquisitionId)
            /\ volatileState.reviewIo[acquisitionId] = 0)
    /\ \A commit \in audit.reviewCommits :
        /\ HasAcquisitionId(commit[1])
        /\ LET item == ItemForAcquisition(commit[1]) IN
            /\ artifacts.reviewOrigin[item] = commit[1]
            /\ IF commit[2] = ReviewAuthenticated
                  THEN artifacts.reviewAuthenticated[item]
                  ELSE artifacts.reviewRejected[item]

BrokerAndAttemptCasAreAtMostOnceAndOrdered ==
    \A item \in Items :
        /\ artifacts.brokerCreateWrites[item] \in 0..1
        /\ artifacts.brokerTokenWrites[item] \in 0..1
        /\ artifacts.reviewBeginWrites[item] \in 0..1
        /\ artifacts.reviewTerminalWrites[item] \in 0..1
        /\ (artifacts.brokerTokenWrites[item] = 1 =>
            artifacts.brokerCreateWrites[item] = 1)
        /\ (artifacts.reviewBeginWrites[item] = 1 =>
            artifacts.brokerTokenWrites[item] = 1)
        /\ (artifacts.reviewTerminalWrites[item] = 1 =>
            artifacts.reviewBeginWrites[item] = 1)
        /\ (artifacts.attempt[item] =>
            /\ artifacts.reviewAuthenticated[item]
            /\ Cardinality({commit \in audit.attemptCommits :
                commit[1] = artifacts.attemptOrigin[item]}) = 1)

SupersededCopiesCannotProduceEffects ==
    \A acquisitionId \in AcquisitionIds :
        HasAcquisitionId(acquisitionId)
            /\ volatileState.held[acquisitionId] > 0
            /\ ~IsLatest(acquisitionId) =>
            ~CurrentHeldAuthority(acquisitionId)

TakeoverNeverRewritesStableClaim ==
    \A item \in Items :
        Cardinality(AcquisitionsFor(item)) > 1 =>
            /\ claims.id[item] = ExpectedClaimId(item)
            /\ claims.fence[item] = ExpectedClaimFence(item)
            /\ \A first, later \in AcquisitionsFor(item) :
                first[3] < later[3] => first[6] <= later[5]

CleanupNeverGrantsProductiveMutation ==
    \A item \in Items :
        artifacts.cleanup[item] =>
            /\ artifacts.broker[item]
            /\ artifacts.deleteAbsent[item]
            /\ artifacts.deleteAbsentWrites[item] = 1
            /\ artifacts.cleanupObservedAt[item] \in
                clock.scopeHistory[item]
            /\ artifacts.cleanupObservedAt[item] \in
                clock.ingressHistory[item]
            /\ artifacts.cleanupFence[item] = LatestFence(item)
            /\ artifacts.cleanupAcquisitionCount[item] =
                Cardinality(AcquisitionsFor(item))
            /\ artifacts.cleanupAuthorityGrantCount[item] =
                Cardinality(AuthorityGrantsFor(item))
            /\ artifacts.cleanupAttempt[item] = artifacts.attempt[item]
            /\ \A acquisitionId \in AcquisitionIds :
                HasAcquisitionId(acquisitionId)
                    /\ ItemForAcquisition(acquisitionId) = item =>
                    ~CurrentHeldAuthority(acquisitionId)

RestartRetainsDurableAcquisitionState ==
    volatileState.restartCount > 0 =>
        /\ nextLeaseFence = Cardinality(acquisitions)
        /\ \A record \in acquisitions :
            claims.present[record[1]]

(***************************************************************************
The append-only audit contains both operational indexes and proof history.
The view retains queue-disposition item/request-id indexes and authority-grant
counts only while those counts can affect a future durable transition.
Ambiguous disposition commits enable only witness-only recovery steps that
stutter in the quotient.  The remaining audit fields, the last request
observation, and the two append-only clock history sets are proof witnesses.
Current raw time, both high-water maps, and both external-sample flags remain
directly in the operational view.  Claims, artifacts, acquisition tuples, and
volatile counters are likewise projected or normalized only after an
absorbing condition makes the hidden facts unable to affect a future visible
successor.  Hidden workers, receipt metadata, and immutable proof fields
remain covered by their corresponding safety predicates below.

TLC fingerprints a state before checking its invariants, so merely dropping
those witnesses from VIEW could hide the first bad state behind a previously
seen good one.  SafetyProofVector retains the truth value of every invariant
that reads a projected witness.  Consequently a violating state has a
different fingerprint, while valid witness-only histories with the same
operational state are represented once.  Authority grant rows and eventually
inert counts are also safe to project: the exact count is retained while it can
affect the future and normalized only after absorbing blockers make it
irrelevant.  AuthorityCopiesAreBoundedAndAudited covers the hidden rows and
count values.
***************************************************************************)
QueueDispositionIndexView ==
    << {receipt[1] : receipt \in audit.queueDispositions},
       {receipt[2] : receipt \in audit.queueDispositions} >>

AuthorityFactsCanAffectFuture(item) ==
    /\ ~HasQueueDisposition(item)
    /\ ~claims.disposed[item]
    /\ ~claims.recoveryNoSend[item]
    /\ ~claims.recoveryRetired[item]
    /\ ~artifacts.attempt[item]
    /\ ~artifacts.terminal[item]
    /\ ~artifacts.cleanup[item]
    /\ DualHighWater(item) < DispatchDeadline(item)

ClaimsAuthorityOperationalView ==
    [item \in Items |->
        IF AuthorityFactsCanAffectFuture(item)
        THEN << claims.authorityCurrent[item],
                claims.grantRevoked[item] >>
        ELSE << TRUE, FALSE >>]

RecoverySafeAfterOperationalView ==
    [item \in Items |->
        IF claims.recoveryRetired[item]
        THEN 0
        ELSE claims.recoverySafeAfter[item]]

ClaimsOperationalView ==
    << claims.phaseCompleted,
       claims.present,
       claims.disposed,
       claims.recoveryNoSend,
       claims.recoveryRetired,
       claims.recoveryOrigin,
       RecoverySafeAfterOperationalView,
       ClaimsAuthorityOperationalView >>

AcquisitionOperationalView ==
    {<< record[1],
        record[2],
        record[3],
        record[5],
        record[6] >> :
        record \in acquisitions}

ActiveArtifactsOperationalView(item) ==
    << artifacts.broker[item],
       artifacts.brokerCreate[item],
       artifacts.brokerCreateWrites[item],
       artifacts.createAbsent[item],
       artifacts.createAbsentObservedAt[item],
       artifacts.brokerToken[item],
       artifacts.brokerOrigin[item],
       artifacts.reviewStarted[item],
       artifacts.reviewAuthenticated[item],
       artifacts.reviewRejected[item],
       artifacts.reviewTerminalWrites[item],
       artifacts.reviewOrigin[item],
       artifacts.admission[item],
       artifacts.admissionOrigin[item],
       artifacts.attempt[item],
       artifacts.attemptOrigin[item],
       artifacts.terminal[item],
       artifacts.cleanup[item],
       artifacts.deleteAbsent[item],
       artifacts.cleanupObservedAt[item] >>

RetiredArtifactsOperationalView(item) ==
    << artifacts.reviewAuthenticated[item],
       IF artifacts.reviewAuthenticated[item]
       THEN artifacts.reviewOrigin[item]
       ELSE NoAcquisition >>

ArtifactsOperationalView ==
    [item \in Items |->
        IF claims.recoveryRetired[item]
        THEN << TRUE, RetiredArtifactsOperationalView(item) >>
        ELSE << FALSE, ActiveArtifactsOperationalView(item) >>]

HeldCanAffectFuture(acquisitionId) ==
    IF ~HasAcquisitionId(acquisitionId)
    THEN TRUE
    ELSE
        LET record == AcquisitionForId(acquisitionId) IN
        LET item == record[1] IN
            /\ LatestAcquisitionId(item) = acquisitionId
            /\ ~claims.disposed[item]
            /\ CurrentDispatchFacts(item)
            /\ DualHighWater(item) < record[6]
            /\ DualHighWater(item) < DispatchDeadline(item)
            /\ ~artifacts.createAbsent[item]
            /\ ~artifacts.reviewStarted[item]
            /\ ~artifacts.attempt[item]
            /\ ~artifacts.terminal[item]
            /\ ~artifacts.cleanup[item]
            /\ ~claims.recoveryNoSend[item]
            /\ ~claims.recoveryRetired[item]

GrantCountCanAffectFuture(acquisitionId) ==
    IF ~HasAcquisitionId(acquisitionId)
    THEN TRUE
    ELSE
        /\ HeldCanAffectFuture(acquisitionId)
        /\ NoArtifacts(ItemForAcquisition(acquisitionId))

ReviewIoCanAffectFuture(acquisitionId) ==
    IF ~HasAcquisitionId(acquisitionId)
    THEN TRUE
    ELSE
        LET item == ItemForAcquisition(acquisitionId) IN
            /\ LatestAcquisitionId(item) = acquisitionId
            /\ ~claims.disposed[item]
            /\ ~claims.recoveryRetired[item]
            /\ ~artifacts.terminal[item]
            /\ ~artifacts.reviewAuthenticated[item]
            /\ ~artifacts.reviewRejected[item]

HeldOperationalView ==
    [acquisitionId \in AcquisitionIds |->
        IF HeldCanAffectFuture(acquisitionId)
        THEN volatileState.held[acquisitionId]
        ELSE 0]

AuthorityGrantCountOperationalView ==
    [acquisitionId \in AcquisitionIds |->
        IF GrantCountCanAffectFuture(acquisitionId)
        THEN audit.authorityGrantCount[acquisitionId]
        ELSE 0]

ReviewIoOperationalView ==
    [acquisitionId \in AcquisitionIds |->
        IF ReviewIoCanAffectFuture(acquisitionId)
        THEN volatileState.reviewIo[acquisitionId]
        ELSE 0]

VolatileOperationalView ==
    << HeldOperationalView,
       ReviewIoOperationalView,
       volatileState.reviewProof,
       volatileState.restartCount >>

AuditOperationalView ==
    << QueueDispositionIndexView,
       AuthorityGrantCountOperationalView >>

ClockOperationalView ==
    << clock.raw,
       clock.scope,
       clock.ingress,
       clock.externalScopeSeen,
       clock.externalIngressSeen >>

SafetyProofVector ==
    << PhaseCompletedIsPrerequisiteAndInert,
       StableClaimIdentityIsImmutable,
       AcquisitionHistoryIsAppendOnlyFreshAndFenced,
       QueueDispositionsAreExactInertAndReleaseClaims,
       ActivePhysicalReservationIsExclusive,
       RecoveryRetirementReleasesSharedResource,
       RecoveryNoSendIsExplicitInertAndSafelyRetired,
       AuthorityCopiesAreBoundedAndAudited,
       DualHighWaterIsMonotoneAndCovered,
       AuthorityResponsesAreExactCurrentAndLive,
       HistoricalResponsesNeverMintAuthority,
       ServerRecoveryDiscoveryIsFIFOAndByteInert,
       RecoverySchedulingRequiresUsefulTransition,
       RollbackRejectionIsByteInert,
       InertAndQuarantineClassesAreDisjoint,
       ArtifactsBindTheLatestAcquisition,
       BrokerIntentBarsRecoveryAndTakeover,
       ProviderAttemptConsumesOnlyLatest,
       CredentialReviewIsBoundAndAtMostOnce,
       BrokerAndAttemptCasAreAtMostOnceAndOrdered,
       SupersededCopiesCannotProduceEffects,
       TakeoverNeverRewritesStableClaim,
       CleanupNeverGrantsProductiveMutation >>

SafetyView ==
    IF TypeOK
    THEN << TRUE,
            ClockOperationalView,
            ClaimsOperationalView,
            AcquisitionOperationalView,
            nextLeaseFence,
            ArtifactsOperationalView,
            AuditOperationalView,
            VolatileOperationalView,
            SafetyProofVector >>
    ELSE << FALSE >>

=============================================================================
