----------------------------- MODULE BrokerJournal -----------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS MaxTime, MaxReconciliations, MaxRollbackRejects

CreateSecret == "CREATE_SECRET"
IssueToken == "ISSUE_TOKEN"
DeleteSecret == "DELETE_SECRET"
Operations == {CreateSecret, IssueToken, DeleteSecret}

NonePhase == "NONE"
Intent == "INTENT"
InFlight == "IN_FLIGHT"
Unknown == "UNKNOWN"
ReconcileOnly == "RECONCILE_ONLY"
Committed == "COMMITTED"
Terminal == "TERMINAL"
Phases == {
    NonePhase,
    Intent,
    InFlight,
    Unknown,
    ReconcileOnly,
    Committed,
    Terminal
}

NoOutcome == "NO_OUTCOME"
CreateMatching == "CREATE_MATCHING"
CreateAbsent == "CREATE_ABSENT"
CreateConflicting == "CREATE_CONFLICTING"
TokenIssued == "TOKEN_ISSUED"
DeleteAbsent == "DELETE_ABSENT"
DeletePresent == "DELETE_PRESENT"
DeleteConflicting == "DELETE_CONFLICTING"
Outcomes == {
    NoOutcome,
    CreateMatching,
    CreateAbsent,
    CreateConflicting,
    TokenIssued,
    DeleteAbsent,
    DeletePresent,
    DeleteConflicting
}

NoEvidence == 0
ExactEvidence == 1
EvidenceValues == {NoEvidence, ExactEvidence}

VARIABLES
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    rollbackRejects,
    phase,
    ioStarted,
    mutationSends,
    sendAuthority,
    responseHeld,
    getAuthority,
    getAuthorityGeneration,
    crashObserved,
    reconciliationCount,
    acceptedCasGenerations,
    lastReconciliationOutcome,
    lastReconciliationEvidence,
    lastReconciledAt,
    outcome,
    resultRecorded,
    exactPendingRecoveryObserved,
    staleOrConflictingCasRejected,
    lateCreateMatchingReached,
    lateDeleteAbsentReached

vars == <<
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    rollbackRejects,
    phase,
    ioStarted,
    mutationSends,
    sendAuthority,
    responseHeld,
    getAuthority,
    getAuthorityGeneration,
    crashObserved,
    reconciliationCount,
    acceptedCasGenerations,
    lastReconciliationOutcome,
    lastReconciliationEvidence,
    lastReconciledAt,
    outcome,
    resultRecorded,
    exactPendingRecoveryObserved,
    staleOrConflictingCasRejected,
    lateCreateMatchingReached,
    lateDeleteAbsentReached
>>

Init ==
    /\ rawClock = 0
    /\ highWaterMark = 0
    /\ highWaterHistory = {0}
    /\ authenticatedSamples = {}
    /\ rollbackRejects = 0
    /\ phase = [op \in Operations |-> NonePhase]
    /\ ioStarted = [op \in Operations |-> FALSE]
    /\ mutationSends = [op \in Operations |-> 0]
    /\ sendAuthority = [op \in Operations |-> FALSE]
    /\ responseHeld = [op \in Operations |-> FALSE]
    /\ getAuthority = [op \in Operations |-> FALSE]
    /\ getAuthorityGeneration = [op \in Operations |-> 0]
    /\ crashObserved = [op \in Operations |-> FALSE]
    /\ reconciliationCount = [op \in Operations |-> 0]
    /\ acceptedCasGenerations = [op \in Operations |-> {}]
    /\ lastReconciliationOutcome = [op \in Operations |-> NoOutcome]
    /\ lastReconciliationEvidence = [op \in Operations |-> NoEvidence]
    /\ lastReconciledAt = [op \in Operations |-> 0]
    /\ outcome = [op \in Operations |-> NoOutcome]
    /\ resultRecorded = [op \in Operations |-> FALSE]
    /\ exactPendingRecoveryObserved = FALSE
    /\ staleOrConflictingCasRejected = FALSE
    /\ lateCreateMatchingReached = FALSE
    /\ lateDeleteAbsentReached = FALSE

(***************************************************************************)
(* Every state transition which trusts time first rejects rollback.  A     *)
(* current authenticated sample advances the durable high-water mark.      *)
(***************************************************************************)
AcceptAuthenticatedClock ==
    /\ rawClock >= highWaterMark
    /\ highWaterMark' = rawClock
    /\ highWaterHistory' = highWaterHistory \cup {rawClock}
    /\ authenticatedSamples' = authenticatedSamples \cup {rawClock}

SetRawClock(t) ==
    /\ t \in 0..MaxTime
    /\ rawClock' = t
    /\ UNCHANGED <<
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        phase,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

Prepare(op) ==
    /\ op \in Operations
    /\ phase[op] = NonePhase
    /\ (op = CreateSecret \/ phase[CreateSecret] = Committed)
    /\ AcceptAuthenticatedClock
    /\ phase' = [phase EXCEPT ![op] = Intent]
    /\ UNCHANGED <<
        rawClock,
        rollbackRejects,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* The row becomes durably IN_FLIGHT before the sole volatile mutation     *)
(* authority exists.  This action itself does not model a network send.    *)
(***************************************************************************)
BeginIo(op) ==
    /\ op \in Operations
    /\ phase[op] = Intent
    /\ ~ioStarted[op]
    /\ AcceptAuthenticatedClock
    /\ phase' = [phase EXCEPT ![op] = InFlight]
    /\ ioStarted' = [ioStarted EXCEPT ![op] = TRUE]
    /\ sendAuthority' = [sendAuthority EXCEPT ![op] = TRUE]
    /\ UNCHANGED <<
        rawClock,
        rollbackRejects,
        mutationSends,
        responseHeld,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* The linear mutation authority is consumed by the network send.  A      *)
(* response is volatile until an authenticated result is durably committed.*)
(***************************************************************************)
SendMutation(op) ==
    /\ op \in Operations
    /\ phase[op] = InFlight
    /\ sendAuthority[op]
    /\ mutationSends[op] = 0
    /\ mutationSends' = [mutationSends EXCEPT ![op] = 1]
    /\ sendAuthority' = [sendAuthority EXCEPT ![op] = FALSE]
    /\ responseHeld' = [responseHeld EXCEPT ![op] = TRUE]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        phase,
        ioStarted,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* A crash destroys all volatile authorities.  IN_FLIGHT becomes UNKNOWN. *)
(* A GET-only authority lost in RECONCILE_ONLY can later be reconstructed. *)
(***************************************************************************)
Crash(op) ==
    /\ op \in Operations
    /\ phase[op] \in {InFlight, ReconcileOnly}
    /\ \/ sendAuthority[op]
       \/ responseHeld[op]
       \/ getAuthority[op]
    /\ phase' =
        [phase EXCEPT ![op] = IF @ = InFlight THEN Unknown ELSE @]
    /\ sendAuthority' = [sendAuthority EXCEPT ![op] = FALSE]
    /\ responseHeld' = [responseHeld EXCEPT ![op] = FALSE]
    /\ getAuthority' = [getAuthority EXCEPT ![op] = FALSE]
    /\ crashObserved' = [crashObserved EXCEPT ![op] = TRUE]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        ioStarted,
        mutationSends,
        getAuthorityGeneration,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

CommitDirectCreate ==
    /\ phase[CreateSecret] = InFlight
    /\ responseHeld[CreateSecret]
    /\ mutationSends[CreateSecret] = 1
    /\ phase' = [phase EXCEPT ![CreateSecret] = Committed]
    /\ responseHeld' = [responseHeld EXCEPT ![CreateSecret] = FALSE]
    /\ outcome' = [outcome EXCEPT ![CreateSecret] = CreateMatching]
    /\ resultRecorded' = [resultRecorded EXCEPT ![CreateSecret] = TRUE]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        ioStarted,
        mutationSends,
        sendAuthority,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

CommitDirectToken ==
    /\ phase[IssueToken] = InFlight
    /\ responseHeld[IssueToken]
    /\ mutationSends[IssueToken] = 1
    /\ phase' = [phase EXCEPT ![IssueToken] = Committed]
    /\ responseHeld' = [responseHeld EXCEPT ![IssueToken] = FALSE]
    /\ outcome' = [outcome EXCEPT ![IssueToken] = TokenIssued]
    /\ resultRecorded' = [resultRecorded EXCEPT ![IssueToken] = TRUE]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        ioStarted,
        mutationSends,
        sendAuthority,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* A successful HTTP acknowledgement for DELETE is not durable absence     *)
(* evidence.  It therefore enters UNKNOWN and must be followed by GET.     *)
(***************************************************************************)
AcknowledgeDeleteUnknown ==
    /\ phase[DeleteSecret] = InFlight
    /\ responseHeld[DeleteSecret]
    /\ mutationSends[DeleteSecret] = 1
    /\ phase' = [phase EXCEPT ![DeleteSecret] = Unknown]
    /\ responseHeld' = [responseHeld EXCEPT ![DeleteSecret] = FALSE]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        ioStarted,
        mutationSends,
        sendAuthority,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* Reconciliation is reconstructable for Secret create/delete only.       *)
(* Entering it irrevocably discards any mutation/response authority.       *)
(***************************************************************************)
BeginReconciliation(op) ==
    /\ op \in {CreateSecret, DeleteSecret}
    /\ phase[op] \in {InFlight, Unknown, ReconcileOnly}
    /\ AcceptAuthenticatedClock
    /\ phase' = [phase EXCEPT ![op] = ReconcileOnly]
    /\ sendAuthority' = [sendAuthority EXCEPT ![op] = FALSE]
    /\ responseHeld' = [responseHeld EXCEPT ![op] = FALSE]
    /\ getAuthority' = [getAuthority EXCEPT ![op] = TRUE]
    /\ getAuthorityGeneration' =
        [getAuthorityGeneration EXCEPT ![op] = reconciliationCount[op]]
    /\ UNCHANGED <<
        rawClock,
        rollbackRejects,
        ioStarted,
        mutationSends,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* A pending authenticated GET is committed with a compare-and-swap       *)
(* generation.  The next generation authorizes another GET, never a       *)
(* mutation.                                                               *)
(***************************************************************************)
CommitPendingReconciliation(op, pendingOutcome, responseDelivered) ==
    /\ op \in {CreateSecret, DeleteSecret}
    /\ responseDelivered \in BOOLEAN
    /\ phase[op] = ReconcileOnly
    /\ getAuthority[op]
    /\ getAuthorityGeneration[op] = reconciliationCount[op]
    /\ reconciliationCount[op] < MaxReconciliations
    /\ pendingOutcome = IF op = CreateSecret THEN CreateAbsent ELSE DeletePresent
    /\ AcceptAuthenticatedClock
    /\ reconciliationCount' =
        [reconciliationCount EXCEPT ![op] = @ + 1]
    /\ acceptedCasGenerations' =
        [acceptedCasGenerations EXCEPT
            ![op] = @ \cup {reconciliationCount[op]}]
    /\ lastReconciliationOutcome' =
        [lastReconciliationOutcome EXCEPT ![op] = pendingOutcome]
    /\ lastReconciliationEvidence' =
        [lastReconciliationEvidence EXCEPT ![op] = ExactEvidence]
    /\ lastReconciledAt' = [lastReconciledAt EXCEPT ![op] = rawClock]
    /\ getAuthority' =
        [getAuthority EXCEPT ![op] = responseDelivered]
    /\ getAuthorityGeneration' =
        [getAuthorityGeneration EXCEPT ![op] = reconciliationCount[op] + 1]
    /\ UNCHANGED <<
        rawClock,
        rollbackRejects,
        phase,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        crashObserved,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* A response-lost CAS is recovered only from the exact next count and     *)
(* exact outcome/evidence tuple.  Recovery returns the already-created     *)
(* next-generation GET authority; it does not execute a second CAS.        *)
(***************************************************************************)
RecoverExactPendingCommit(op, expectedGeneration, presentedEvidence) ==
    /\ op \in {CreateSecret, DeleteSecret}
    /\ expectedGeneration \in 0..(MaxReconciliations - 1)
    /\ presentedEvidence \in EvidenceValues
    /\ phase[op] = ReconcileOnly
    /\ ~getAuthority[op]
    /\ reconciliationCount[op] = expectedGeneration + 1
    /\ expectedGeneration \in acceptedCasGenerations[op]
    /\ lastReconciliationEvidence[op] = presentedEvidence
    /\ presentedEvidence = ExactEvidence
    /\ IF op = CreateSecret
       THEN lastReconciliationOutcome[op] = CreateAbsent
       ELSE lastReconciliationOutcome[op] = DeletePresent
    /\ getAuthority' = [getAuthority EXCEPT ![op] = TRUE]
    /\ getAuthorityGeneration' =
        [getAuthorityGeneration EXCEPT ![op] = reconciliationCount[op]]
    /\ exactPendingRecoveryObserved' = TRUE
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        phase,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* This represents the losing concurrent same-generation CAS, an older    *)
(* generation, or a same-count retry carrying different evidence.         *)
(***************************************************************************)
RejectStaleOrConflictingCas(op, expectedGeneration, presentedEvidence) ==
    /\ op \in {CreateSecret, DeleteSecret}
    /\ expectedGeneration \in 0..(MaxReconciliations - 1)
    /\ presentedEvidence \in EvidenceValues
    /\ phase[op] = ReconcileOnly
    /\ reconciliationCount[op] > expectedGeneration
    /\ \/ reconciliationCount[op] # expectedGeneration + 1
       \/ presentedEvidence # lastReconciliationEvidence[op]
    /\ staleOrConflictingCasRejected' = TRUE
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        rollbackRejects,
        phase,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

CommitReconciledCreateMatching ==
    /\ phase[CreateSecret] = ReconcileOnly
    /\ getAuthority[CreateSecret]
    /\ AcceptAuthenticatedClock
    /\ phase' = [phase EXCEPT ![CreateSecret] = Committed]
    /\ getAuthority' = [getAuthority EXCEPT ![CreateSecret] = FALSE]
    /\ outcome' = [outcome EXCEPT ![CreateSecret] = CreateMatching]
    /\ resultRecorded' = [resultRecorded EXCEPT ![CreateSecret] = TRUE]
    /\ lateCreateMatchingReached' =
        (lateCreateMatchingReached \/ reconciliationCount[CreateSecret] > 0)
    /\ UNCHANGED <<
        rawClock,
        rollbackRejects,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateDeleteAbsentReached
        >>

CommitReconciledDeleteAbsent ==
    /\ phase[DeleteSecret] = ReconcileOnly
    /\ getAuthority[DeleteSecret]
    /\ AcceptAuthenticatedClock
    /\ phase' = [phase EXCEPT ![DeleteSecret] = Committed]
    /\ getAuthority' = [getAuthority EXCEPT ![DeleteSecret] = FALSE]
    /\ outcome' = [outcome EXCEPT ![DeleteSecret] = DeleteAbsent]
    /\ resultRecorded' = [resultRecorded EXCEPT ![DeleteSecret] = TRUE]
    /\ lateDeleteAbsentReached' =
        (lateDeleteAbsentReached \/ reconciliationCount[DeleteSecret] > 0)
    /\ UNCHANGED <<
        rawClock,
        rollbackRejects,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached
        >>

(***************************************************************************)
(* For delete, this abstracts either a conflicting object or the expected  *)
(* name carrying the wrong immutable UID.                                  *)
(***************************************************************************)
CommitReconciledConflict(op) ==
    /\ op \in {CreateSecret, DeleteSecret}
    /\ phase[op] = ReconcileOnly
    /\ getAuthority[op]
    /\ AcceptAuthenticatedClock
    /\ phase' = [phase EXCEPT ![op] = Terminal]
    /\ getAuthority' = [getAuthority EXCEPT ![op] = FALSE]
    /\ outcome' =
        [outcome EXCEPT
            ![op] = IF op = CreateSecret
                    THEN CreateConflicting
                    ELSE DeleteConflicting]
    /\ resultRecorded' = [resultRecorded EXCEPT ![op] = TRUE]
    /\ UNCHANGED <<
        rawClock,
        rollbackRejects,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

(***************************************************************************)
(* A rollback is rejected before journal state or authority can change.    *)
(***************************************************************************)
RejectClockRollback(op) ==
    /\ op \in Operations
    /\ phase[op] \in {Intent, InFlight, Unknown, ReconcileOnly}
    /\ rawClock < highWaterMark
    /\ rollbackRejects < MaxRollbackRejects
    /\ rollbackRejects' = rollbackRejects + 1
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        phase,
        ioStarted,
        mutationSends,
        sendAuthority,
        responseHeld,
        getAuthority,
        getAuthorityGeneration,
        crashObserved,
        reconciliationCount,
        acceptedCasGenerations,
        lastReconciliationOutcome,
        lastReconciliationEvidence,
        lastReconciledAt,
        outcome,
        resultRecorded,
        exactPendingRecoveryObserved,
        staleOrConflictingCasRejected,
        lateCreateMatchingReached,
        lateDeleteAbsentReached
        >>

Stutter == UNCHANGED vars

Next ==
    \/ \E t \in 0..MaxTime : SetRawClock(t)
    \/ \E op \in Operations : Prepare(op)
    \/ \E op \in Operations : BeginIo(op)
    \/ \E op \in Operations : SendMutation(op)
    \/ \E op \in Operations : Crash(op)
    \/ CommitDirectCreate
    \/ CommitDirectToken
    \/ AcknowledgeDeleteUnknown
    \/ \E op \in {CreateSecret, DeleteSecret} : BeginReconciliation(op)
    \/ \E delivered \in BOOLEAN :
        CommitPendingReconciliation(CreateSecret, CreateAbsent, delivered)
    \/ \E delivered \in BOOLEAN :
        CommitPendingReconciliation(DeleteSecret, DeletePresent, delivered)
    \/ \E op \in {CreateSecret, DeleteSecret},
          generation \in 0..(MaxReconciliations - 1),
          evidence \in EvidenceValues :
        RecoverExactPendingCommit(op, generation, evidence)
    \/ \E op \in {CreateSecret, DeleteSecret},
          generation \in 0..(MaxReconciliations - 1),
          evidence \in EvidenceValues :
        RejectStaleOrConflictingCas(op, generation, evidence)
    \/ CommitReconciledCreateMatching
    \/ CommitReconciledDeleteAbsent
    \/ \E op \in {CreateSecret, DeleteSecret} : CommitReconciledConflict(op)
    \/ \E op \in Operations : RejectClockRollback(op)
    \/ Stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ rawClock \in 0..MaxTime
    /\ highWaterMark \in 0..MaxTime
    /\ highWaterHistory \subseteq 0..MaxTime
    /\ authenticatedSamples \subseteq 0..MaxTime
    /\ rollbackRejects \in 0..MaxRollbackRejects
    /\ phase \in [Operations -> Phases]
    /\ ioStarted \in [Operations -> BOOLEAN]
    /\ mutationSends \in [Operations -> 0..1]
    /\ sendAuthority \in [Operations -> BOOLEAN]
    /\ responseHeld \in [Operations -> BOOLEAN]
    /\ getAuthority \in [Operations -> BOOLEAN]
    /\ getAuthorityGeneration \in [Operations -> 0..MaxReconciliations]
    /\ crashObserved \in [Operations -> BOOLEAN]
    /\ reconciliationCount \in [Operations -> 0..MaxReconciliations]
    /\ acceptedCasGenerations \in
        [Operations -> SUBSET (0..(MaxReconciliations - 1))]
    /\ lastReconciliationOutcome \in [Operations -> Outcomes]
    /\ lastReconciliationEvidence \in [Operations -> EvidenceValues]
    /\ lastReconciledAt \in [Operations -> 0..MaxTime]
    /\ outcome \in [Operations -> Outcomes]
    /\ resultRecorded \in [Operations -> BOOLEAN]
    /\ exactPendingRecoveryObserved \in BOOLEAN
    /\ staleOrConflictingCasRejected \in BOOLEAN
    /\ lateCreateMatchingReached \in BOOLEAN
    /\ lateDeleteAbsentReached \in BOOLEAN

AtMostOneMutationSendPerOperation ==
    \A op \in Operations : mutationSends[op] <= 1

MutationSendRequiresDurableInFlight ==
    \A op \in Operations :
        mutationSends[op] = 1 => ioStarted[op]

LinearSendAuthorityIsSound ==
    \A op \in Operations :
        sendAuthority[op] =>
            /\ phase[op] = InFlight
            /\ ioStarted[op]
            /\ mutationSends[op] = 0
            /\ ~crashObserved[op]

NoSendAuthorityAfterCrash ==
    \A op \in Operations :
        crashObserved[op] => ~sendAuthority[op]

TokenNeverReissuedOrReconciled ==
    /\ mutationSends[IssueToken] <= 1
    /\ phase[IssueToken] # ReconcileOnly
    /\ ~getAuthority[IssueToken]
    /\ reconciliationCount[IssueToken] = 0
    /\ acceptedCasGenerations[IssueToken] = {}
    /\ lastReconciliationOutcome[IssueToken] = NoOutcome
    /\ lastReconciliationEvidence[IssueToken] = NoEvidence

GetOnlyAuthorityNeverRestoresMutation ==
    \A op \in Operations :
        (getAuthority[op] \/ reconciliationCount[op] > 0) =>
            /\ op \in {CreateSecret, DeleteSecret}
            /\ ~sendAuthority[op]

GetAuthorityIsPhaseBound ==
    \A op \in Operations :
        getAuthority[op] =>
            /\ phase[op] = ReconcileOnly
            /\ getAuthorityGeneration[op] = reconciliationCount[op]

OnePendingCasPerGeneration ==
    \A op \in Operations :
        /\ Cardinality(acceptedCasGenerations[op]) =
            reconciliationCount[op]
        /\ acceptedCasGenerations[op] =
            {generation \in 0..(MaxReconciliations - 1) :
                generation < reconciliationCount[op]}

HighWaterMarkMonotone ==
    \A seen \in highWaterHistory : seen <= highWaterMark

HighWaterMarkCoversAuthenticatedSamples ==
    \A sample \in authenticatedSamples : sample <= highWaterMark

PendingReconciliationStateIsSound ==
    \A op \in Operations :
        \/ /\ reconciliationCount[op] = 0
           /\ acceptedCasGenerations[op] = {}
           /\ lastReconciliationOutcome[op] = NoOutcome
           /\ lastReconciliationEvidence[op] = NoEvidence
           /\ lastReconciledAt[op] = 0
        \/ /\ reconciliationCount[op] > 0
           /\ phase[op] \in {ReconcileOnly, Committed, Terminal}
           /\ lastReconciledAt[op] <= highWaterMark
           /\ lastReconciliationEvidence[op] = ExactEvidence
           /\ IF op = CreateSecret
              THEN lastReconciliationOutcome[op] = CreateAbsent
              ELSE /\ op = DeleteSecret
                   /\ lastReconciliationOutcome[op] = DeletePresent

ResultPhaseIsSound ==
    \A op \in Operations :
        /\ (resultRecorded[op] <=> phase[op] \in {Committed, Terminal})
        /\ (phase[op] = Committed <=>
                \/ /\ op = CreateSecret
                   /\ outcome[op] = CreateMatching
                \/ /\ op = IssueToken
                   /\ outcome[op] = TokenIssued
                \/ /\ op = DeleteSecret
                   /\ outcome[op] = DeleteAbsent)
        /\ (phase[op] = Terminal <=>
                \/ /\ op = CreateSecret
                   /\ outcome[op] = CreateConflicting
                \/ /\ op = DeleteSecret
                   /\ outcome[op] = DeleteConflicting)
        /\ (phase[op] \notin {Committed, Terminal} =>
                outcome[op] = NoOutcome)

LateCompletionMarkersAreSound ==
    /\ lateCreateMatchingReached =>
        /\ phase[CreateSecret] = Committed
        /\ outcome[CreateSecret] = CreateMatching
        /\ reconciliationCount[CreateSecret] > 0
        /\ lastReconciliationOutcome[CreateSecret] = CreateAbsent
    /\ lateDeleteAbsentReached =>
        /\ phase[DeleteSecret] = Committed
        /\ outcome[DeleteSecret] = DeleteAbsent
        /\ reconciliationCount[DeleteSecret] > 0
        /\ lastReconciliationOutcome[DeleteSecret] = DeletePresent

=============================================================================
