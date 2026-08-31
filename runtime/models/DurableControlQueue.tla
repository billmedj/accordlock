------------------------- MODULE DurableControlQueue -------------------------
EXTENDS Naturals, FiniteSets

(***************************************************************************
This is a bounded safety model of the v13 durable control intake and work
queue.  Signatures, canonical encodings, commitments, UUIDs, SQL transactions,
signed kernel decisions, authorization issuance, and consumption receipts are
represented by collision-free symbolic values and atomic durable actions.

For tractability, a claim ID is represented by the same fresh natural number
as its globally increasing fence.  The implementation domains are distinct;
the model deliberately strengthens them into one collision-free namespace.
***************************************************************************)

CONSTANTS MaxTime, IntakeDeadline, AuthorizationDeadline, LeaseLength, MaxClaims

EvaluatorWorker == "worker-evaluator"
IssuerWorker == "worker-issuer"
ConsumerWorker == "worker-consumer"
Workers == {EvaluatorWorker, IssuerWorker, ConsumerWorker}

NoPayload == "NO_PAYLOAD"
ExactPayload == "EXACT_SIGNED_PAYLOAD"
DifferentPayload == "DIFFERENT_SIGNED_PAYLOAD"

NoWire == "NO_WIRE"
OriginalWire == "ORIGINAL_WIRE"
EquivalentWire == "EQUIVALENT_JSON_WIRE"
RecoveryWires == {OriginalWire, EquivalentWire}

OriginalVerifier == "ORIGINAL_VERIFIER"
RotatedVerifier == "ROTATED_VERIFIER"
RemovedVerifier == "REMOVED_VERIFIER"
Verifiers == {OriginalVerifier, RotatedVerifier, RemovedVerifier}

NoIntakeResponse == "NO_INTAKE_RESPONSE"
FreshResponse == "FRESH"
OutcomeUnknownResponse == "OUTCOME_UNKNOWN"
RecoveredResponse == "RECOVERED_INERT_REF"
BadSignatureResponse == "BAD_SIGNATURE"
PayloadConflictResponse == "PAYLOAD_CONFLICT"
TemporalResponse == "TEMPORAL_REJECT"
RollbackResponse == "ROLLBACK_REJECT"
IntakeResponses == {
    NoIntakeResponse,
    FreshResponse,
    OutcomeUnknownResponse,
    RecoveredResponse,
    BadSignatureResponse,
    PayloadConflictResponse,
    TemporalResponse,
    RollbackResponse
}

NoPhase == "NO_PHASE"
EvaluatePhase == "EVALUATE"
IssuePhase == "ISSUE"
ConsumePhase == "CONSUME"
DonePhase == "DONE"
Phases == {NoPhase, EvaluatePhase, IssuePhase, ConsumePhase, DonePhase}

NoQueue == "NO_QUEUE"
ReadyQueue == "READY"
LeasedQueue == "LEASED"
DoneQueue == "DONE"
QueueStates == {NoQueue, ReadyQueue, LeasedQueue, DoneQueue}

NoStatus == "NO_STATUS"
AcceptedStatus == "ACCEPTED"
AuthorizedStatus == "AUTHORIZED"
DeniedStatus == "CONTROL_DENIED"
AuthorizationIssuedStatus == "AUTHORIZATION_ISSUED"
DispatchPendingStatus == "DISPATCH_PENDING"
FailedClosedStatus == "FAILED_CLOSED"
Statuses == {
    NoStatus,
    AcceptedStatus,
    AuthorizedStatus,
    DeniedStatus,
    AuthorizationIssuedStatus,
    DispatchPendingStatus,
    FailedClosedStatus
}

NoKernel == "NO_KERNEL_OUTCOME"
KernelAllow == "ALLOW"
KernelDeny == "DENY"
KernelOutcomes == {NoKernel, KernelAllow, KernelDeny}

NoControl == "NO_CONTROL_OUTCOME"
ControlAllow == "ALLOW"
ControlDeny == "DENY"
ControlOutcomes == {NoControl, ControlAllow, ControlDeny}

NoReason == "NO_REASON"
KernelDenyReason == "KERNEL_DENY"
GrantUnavailableReason == "GRANT_UNAVAILABLE"
ControlAllowReason == "CONTROL_ALLOW"
IngressExpiredReason == "INGRESS_EXPIRED"
AuthorityChangedReason == "AUTHORITY_CHANGED"
AuthorizationExpiredReason == "AUTHORIZATION_EXPIRED"
DispatchWindowExpiredReason == "DISPATCH_WINDOW_EXPIRED"
DecisionReasons == {
    NoReason,
    KernelDenyReason,
    GrantUnavailableReason,
    ControlAllowReason,
    IngressExpiredReason,
    AuthorityChangedReason
}
PreKernelDecisionReasons == {AuthorityChangedReason, IngressExpiredReason}

NoWorkFailure == "NO_WORK_FAILURE"
WorkFailureReasons == {
    NoWorkFailure,
    IngressExpiredReason,
    AuthorityChangedReason,
    GrantUnavailableReason,
    AuthorizationExpiredReason,
    DispatchWindowExpiredReason
}
TerminalWorkFailureReasons == WorkFailureReasons \ {NoWorkFailure}

ZeroGrants == "ZERO_CURRENT_GRANTS"
OneGrant == "ONE_CURRENT_GRANT"
GrantModes == {ZeroGrants, OneGrant}

NoGrant == "NO_SELECTED_GRANT"
ServerGrant == "SERVER_SELECTED_GRANT"
SelectedGrants == {NoGrant, ServerGrant}

NoNonce == "NO_EVALUATION_NONCE"
DeterministicNonce == "H(state_instance,submission,request)"

NoCommitment == "NO_COMMITMENT"
ExactControlDecisionCommitment == "EXACT_CONTROL_DECISION"
ExactDecisionCommitment == "EXACT_SIGNED_DECISION"
ExactAuthorizationCommitment == "EXACT_AUTHORIZATION"
ExactConsumptionCommitment == "EXACT_CONSUMPTION"
WrongAuthorizationCommitment == "WRONG_AUTHORIZATION"
WrongConsumptionCommitment == "WRONG_CONSUMPTION"

ExactFrozenIntegrity == "EXACT_FROZEN_INGRESS"
CorruptFrozenIntegrity == "CORRUPT_FROZEN_INGRESS"
FrozenIntegrityStates == {ExactFrozenIntegrity, CorruptFrozenIntegrity}

OriginalAuthority == "ORIGINAL_AUTHORITY"
ChangedAuthority == "CHANGED_AUTHORITY"
Authorities == {OriginalAuthority, ChangedAuthority}
NoAuthorityVector == "NO_AUTHORITY_VECTOR"
AuthorityVectors == Authorities \cup {NoAuthorityVector}

NoCompletionIdentity == "NO_COMPLETION_IDENTITY"
ConsumeCompletionIdentity == "EXACT_CONSUME_KEY_IDENTITY"
CompletionIdentities == {
    NoCompletionIdentity,
    ConsumeCompletionIdentity
}

NoWorker == "NO_WORKER"
NoFence == 0

VARIABLES
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    currentVerifier,
    currentAuthority,
    intake,
    work,
    claim,
    decision,
    authorization,
    consumption,
    heldFence,
    knownDecisionFence,
    knownAuthorizationFence,
    knownConsumptionFence,
    restartSeen

vars == <<
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    currentVerifier,
    currentAuthority,
    intake,
    work,
    claim,
    decision,
    authorization,
    consumption,
    heldFence,
    knownDecisionFence,
    knownAuthorizationFence,
    knownConsumptionFence,
    restartSeen
>>

Min(a, b) == IF a <= b THEN a ELSE b

ExpectedControl(kernel, grantMode) ==
    IF kernel = KernelDeny THEN ControlDeny
    ELSE IF grantMode = ZeroGrants THEN ControlDeny
    ELSE ControlAllow

ExpectedReason(kernel, grantMode) ==
    IF kernel = KernelDeny THEN KernelDenyReason
    ELSE IF grantMode = ZeroGrants THEN GrantUnavailableReason
    ELSE ControlAllowReason

ExpectedGrant(kernel, grantMode) ==
    IF kernel = KernelAllow /\ grantMode = OneGrant
    THEN ServerGrant
    ELSE NoGrant

ExpectedStatus(control) ==
    IF control = ControlDeny THEN DeniedStatus ELSE AuthorizedStatus

WorkerForPhase(phase) ==
    CASE phase = EvaluatePhase -> EvaluatorWorker
      [] phase = IssuePhase -> IssuerWorker
      [] phase = ConsumePhase -> ConsumerWorker
      [] OTHER -> NoWorker

Init ==
    /\ rawClock = 0
    /\ highWaterMark = 0
    /\ highWaterHistory = {0}
    /\ authenticatedSamples = {}
    /\ currentVerifier = OriginalVerifier
    /\ currentAuthority = OriginalAuthority
    /\ intake = [
        present |-> FALSE,
        nonceOwner |-> NoPayload,
        payload |-> NoPayload,
        firstWire |-> NoWire,
        frozenVerifier |-> RemovedVerifier,
        frozenIntegrity |-> ExactFrozenIntegrity,
        frozenFirstIntegrity |-> ExactFrozenIntegrity,
        writes |-> 0,
        response |-> NoIntakeResponse,
        recoveredExecutable |-> FALSE
       ]
    /\ work = [
        phase |-> NoPhase,
        queueState |-> NoQueue,
        status |-> NoStatus,
        statusRevision |-> 0,
        statusEvents |-> {},
        grantAvailable |-> TRUE,
        dispatchWindowAvailable |-> TRUE,
        failureReason |-> NoWorkFailure,
        failurePhase |-> NoPhase,
        finalizationWrites |-> 0
       ]
    /\ claim = [
        globalFence |-> 0,
        activeFence |-> NoFence,
        activeWorker |-> NoWorker,
        activePhase |-> NoPhase,
        activeAuthorityVector |-> NoAuthorityVector,
        leaseUntil |-> 0,
        history |-> {},
        completed |-> {},
        decisionFinalized |-> {},
        workFinalized |-> {},
        recoveredCompletionFence |-> NoFence,
        recoveredCompletionPhase |-> NoPhase,
        recoveredCompletionIdentity |-> NoCompletionIdentity,
        recoveredCompletionExecutable |-> FALSE,
        recoveredDecisionFence |-> NoFence,
        recoveredDecisionReason |-> NoReason,
        recoveredDecisionExecutable |-> FALSE,
        recoveredWorkFence |-> NoFence,
        recoveredWorkPhase |-> NoPhase,
        recoveredWorkReason |-> NoWorkFailure,
        recoveredWorkExecutable |-> FALSE
       ]
    /\ decision = [
        present |-> FALSE,
        kernel |-> NoKernel,
        control |-> NoControl,
        reason |-> NoReason,
        grant |-> NoGrant,
        nonce |-> NoNonce,
        controlCommitment |-> NoCommitment,
        commitment |-> NoCommitment,
        writes |-> 0,
        linked |-> FALSE
       ]
    /\ authorization = [
        present |-> FALSE,
        commitment |-> NoCommitment,
        writes |-> 0,
        linked |-> FALSE,
        response |-> NoIntakeResponse,
        recoveredExecutable |-> FALSE
       ]
    /\ consumption = [
        present |-> FALSE,
        commitment |-> NoCommitment,
        writes |-> 0,
        linked |-> FALSE,
        response |-> NoIntakeResponse,
        recoveredExecutable |-> FALSE
       ]
    /\ heldFence = [worker \in Workers |-> NoFence]
    /\ knownDecisionFence = NoFence
    /\ knownAuthorizationFence = NoFence
    /\ knownConsumptionFence = NoFence
    /\ restartSeen = FALSE

RecordTrustedTime ==
    /\ rawClock >= highWaterMark
    /\ highWaterMark' = rawClock
    /\ highWaterHistory' = highWaterHistory \cup {rawClock}
    /\ authenticatedSamples' = authenticatedSamples \cup {rawClock}

SetRawClock(sample) ==
    /\ sample \in 0..MaxTime
    /\ rawClock' = sample
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RotateVerifier ==
    /\ currentVerifier = OriginalVerifier
    /\ currentVerifier' = RotatedVerifier
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

ChangeAuthority ==
    /\ intake.present
    /\ work.queueState # DoneQueue
    /\ currentAuthority = OriginalAuthority
    /\ currentAuthority' = ChangedAuthority
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RevokeSelectedGrant ==
    /\ decision.linked
    /\ decision.control = ControlAllow
    /\ work.phase \in {IssuePhase, ConsumePhase}
    /\ work.grantAvailable
    /\ work' = [work EXCEPT !.grantAvailable = FALSE]
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

CloseDispatchWindow ==
    /\ decision.linked
    /\ decision.control = ControlAllow
    /\ authorization.linked
    /\ work.phase = ConsumePhase
    /\ work.dispatchWindowAvailable
    /\ work' = [work EXCEPT !.dispatchWindowAvailable = FALSE]
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

InjectFrozenCorruption ==
    /\ intake.present
    /\ ~decision.present
    /\ intake.frozenIntegrity = ExactFrozenIntegrity
    /\ intake' = [intake EXCEPT
        !.frozenIntegrity = CorruptFrozenIntegrity,
        !.response = NoIntakeResponse
       ]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RemoveVerifier ==
    /\ currentVerifier \in {OriginalVerifier, RotatedVerifier}
    /\ currentVerifier' = RemovedVerifier
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

(***************************************************************************
The fresh intake transition is one abstract database transaction: v10 nonce,
immutable submission, status projection/event, and READY EVALUATE work appear
together.  delivered=FALSE represents a committed transaction whose response
was lost and returned OutcomeUnknown.
***************************************************************************)
AcceptFresh(delivered) ==
    /\ delivered \in BOOLEAN
    /\ ~intake.present
    /\ intake.nonceOwner = NoPayload
    /\ currentVerifier = OriginalVerifier
    /\ currentAuthority = OriginalAuthority
    /\ rawClock >= highWaterMark
    /\ rawClock < IntakeDeadline
    /\ RecordTrustedTime
    /\ intake' = [
        present |-> TRUE,
        nonceOwner |-> ExactPayload,
        payload |-> ExactPayload,
        firstWire |-> OriginalWire,
        frozenVerifier |-> OriginalVerifier,
        frozenIntegrity |-> ExactFrozenIntegrity,
        frozenFirstIntegrity |-> ExactFrozenIntegrity,
        writes |-> 1,
        response |-> IF delivered THEN FreshResponse ELSE OutcomeUnknownResponse,
        recoveredExecutable |-> FALSE
       ]
    /\ work' = [
        phase |-> EvaluatePhase,
        queueState |-> ReadyQueue,
        status |-> AcceptedStatus,
        statusRevision |-> 1,
        statusEvents |-> {<<1, AcceptedStatus>>},
        grantAvailable |-> TRUE,
        dispatchWindowAvailable |-> TRUE,
        failureReason |-> NoWorkFailure,
        failurePhase |-> NoPhase,
        finalizationWrites |-> 0
       ]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

(***************************************************************************
The exact historical path uses the immutable payload commitment and frozen
verifier/binding.  It intentionally does not inspect current time, HWM, or the
current verifier, and never reconstructs an executable ingress capability.
Equivalent JSON wire bytes recover the same payload submission while the
first-wire audit hash remains immutable.
***************************************************************************)
RecoverSubmission(wire) ==
    /\ wire \in RecoveryWires
    /\ intake.present
    /\ intake.payload = ExactPayload
    /\ intake.nonceOwner = ExactPayload
    /\ intake.frozenVerifier = OriginalVerifier
    /\ intake.frozenIntegrity = ExactFrozenIntegrity
    /\ intake' = [intake EXCEPT
        !.response = RecoveredResponse,
        !.recoveredExecutable = FALSE
       ]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectBadSignature ==
    /\ intake' = [intake EXCEPT !.response = BadSignatureResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectPayloadConflict ==
    /\ intake.present
    /\ intake.nonceOwner = ExactPayload
    /\ DifferentPayload # intake.payload
    /\ intake' = [intake EXCEPT !.response = PayloadConflictResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectIntakeTemporal ==
    /\ ~intake.present
    /\ currentVerifier = OriginalVerifier
    /\ rawClock >= highWaterMark
    /\ rawClock >= IntakeDeadline
    /\ RecordTrustedTime
    /\ intake' = [intake EXCEPT !.response = TemporalResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectIntakeRollback ==
    /\ ~intake.present
    /\ currentVerifier = OriginalVerifier
    /\ rawClock < highWaterMark
    /\ intake' = [intake EXCEPT !.response = RollbackResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

Claimable ==
    \/ work.queueState = ReadyQueue
    \/ /\ work.queueState = LeasedQueue
       /\ rawClock >= claim.leaseUntil

(***************************************************************************
claim_next_control_work_or_recover uses a caller-supplied collision-free ID.
The next global fence is the bounded symbolic ID here.  Claiming READY work or
taking over an expired lease is atomic; the old append-only claim record and
old volatile token remain but cannot authorize the new active fence.
***************************************************************************)
ClaimNext(worker, delivered) ==
    /\ worker \in Workers
    /\ delivered \in BOOLEAN
    /\ work.phase \in {EvaluatePhase, IssuePhase, ConsumePhase}
    /\ worker = WorkerForPhase(work.phase)
    /\ Claimable
    /\ claim.globalFence < MaxClaims
    /\ rawClock >= highWaterMark
    /\ RecordTrustedTime
    /\ LET newFence == claim.globalFence + 1 IN
       /\ claim' = [claim EXCEPT
            !.globalFence = newFence,
            !.activeFence = newFence,
            !.activeWorker = worker,
            !.activePhase = work.phase,
            !.activeAuthorityVector = currentAuthority,
            !.leaseUntil = Min(rawClock + LeaseLength, MaxTime + LeaseLength),
            !.history = claim.history
                \cup {<<newFence, work.phase, worker, currentAuthority>>}
           ]
       /\ heldFence' = IF delivered
            THEN [heldFence EXCEPT ![worker] = newFence]
            ELSE heldFence
    /\ work' = [work EXCEPT !.queueState = LeasedQueue]
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        decision,
        authorization,
        consumption,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RecoverClaimExact(worker, claimId) ==
    /\ worker \in Workers
    /\ claimId \in 1..MaxClaims
    /\ work.queueState = LeasedQueue
    /\ claim.activeWorker = worker
    /\ claim.activeFence = claimId
    /\ claim.activePhase = work.phase
    /\ rawClock >= highWaterMark
    /\ rawClock < claim.leaseUntil
    /\ RecordTrustedTime
    /\ heldFence' = [heldFence EXCEPT ![worker] = claimId]
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

(***************************************************************************
An exact retry of a completed claim returns only an inert PhaseCompleted
receipt.  The single modeled submission ID is implicit; the append-only tuple
contains claim ID/fence, phase, completed_at, non-capability identity, and the
original worker.  No clock/HWM/current-authority check and no lease token are
reconstructed on this historical path.
***************************************************************************)
RecoverCompletedClaim(worker, claimId) ==
    /\ worker \in Workers
    /\ claimId \in 1..MaxClaims
    /\ \E phase \in {EvaluatePhase, IssuePhase, ConsumePhase},
          completedAt \in 0..MaxTime,
          identity \in CompletionIdentities :
        <<claimId, phase, completedAt, identity, worker>> \in claim.completed
    /\ LET completion == CHOOSE item \in claim.completed :
            item[1] = claimId /\ item[5] = worker
       IN claim' = [claim EXCEPT
            !.recoveredCompletionFence = completion[1],
            !.recoveredCompletionPhase = completion[2],
            !.recoveredCompletionIdentity = completion[4],
            !.recoveredCompletionExecutable = FALSE
          ]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        intake,
        work,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

(***************************************************************************
Pre-kernel fail-closed claim history recovers the immutable control decision,
not a PhaseCompleted receipt.  This historical path samples no clock/HWM or
current authority and reconstructs no executable work capability.
***************************************************************************)
RecoverDecisionFinalized(worker, claimId) ==
    /\ worker \in Workers
    /\ claimId \in 1..MaxClaims
    /\ \E finalizedAt \in 0..MaxTime,
          reason \in PreKernelDecisionReasons :
        <<claimId, finalizedAt, worker, reason>> \in claim.decisionFinalized
    /\ LET finalization == CHOOSE item \in claim.decisionFinalized :
            item[1] = claimId /\ item[3] = worker
       IN claim' = [claim EXCEPT
            !.recoveredDecisionFence = finalization[1],
            !.recoveredDecisionReason = finalization[4],
            !.recoveredDecisionExecutable = FALSE
          ]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        intake,
        work,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

(***************************************************************************
Post-decision fail-closed ISSUE/CONSUME history recovers WorkFinalized rather
than PhaseCompleted.  It is likewise historical, currentness-inert, and never
recreates a lease, authorization, consume key, or other execution authority.
***************************************************************************)
RecoverWorkFinalized(worker, claimId) ==
    /\ worker \in Workers
    /\ claimId \in 1..MaxClaims
    /\ \E phase \in {IssuePhase, ConsumePhase},
          finalizedAt \in 0..MaxTime,
          reason \in TerminalWorkFailureReasons :
        <<claimId, phase, finalizedAt, worker, reason>> \in claim.workFinalized
    /\ LET finalization == CHOOSE item \in claim.workFinalized :
            item[1] = claimId /\ item[4] = worker
       IN claim' = [claim EXCEPT
            !.recoveredWorkFence = finalization[1],
            !.recoveredWorkPhase = finalization[2],
            !.recoveredWorkReason = finalization[5],
            !.recoveredWorkExecutable = FALSE
          ]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        intake,
        work,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectClaimRecoveryMismatch(worker, claimId) ==
    /\ worker \in Workers
    /\ claimId \in 1..MaxClaims
    /\ ~(/\ work.queueState = LeasedQueue
          /\ claim.activeWorker = worker
          /\ claim.activeFence = claimId
          /\ claim.activePhase = work.phase)
    /\ ~\E phase \in {EvaluatePhase, IssuePhase, ConsumePhase},
           completedAt \in 0..MaxTime,
           identity \in CompletionIdentities :
        <<claimId, phase, completedAt, identity, worker>> \in claim.completed
    /\ ~\E finalizedAt \in 0..MaxTime,
           reason \in PreKernelDecisionReasons :
        <<claimId, finalizedAt, worker, reason>> \in claim.decisionFinalized
    /\ ~\E phase \in {IssuePhase, ConsumePhase},
           finalizedAt \in 0..MaxTime,
           reason \in TerminalWorkFailureReasons :
        <<claimId, phase, finalizedAt, worker, reason>> \in claim.workFinalized
    /\ UNCHANGED vars

ExactLease(worker) ==
    /\ worker \in Workers
    /\ work.queueState = LeasedQueue
    /\ claim.activeWorker = worker
    /\ claim.activePhase = work.phase
    /\ heldFence[worker] = claim.activeFence
    /\ claim.activeFence > 0

CurrentExactLease(worker) ==
    /\ ExactLease(worker)
    /\ rawClock >= highWaterMark
    /\ rawClock < claim.leaseUntil

RejectExpiredLease(worker) ==
    /\ ExactLease(worker)
    /\ rawClock >= highWaterMark
    /\ rawClock >= claim.leaseUntil
    /\ RecordTrustedTime
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectWorkRollback(worker) ==
    /\ ExactLease(worker)
    /\ rawClock < highWaterMark
    /\ UNCHANGED vars

RejectFrozenMismatch(worker) ==
    /\ ExactLease(worker)
    /\ intake.frozenIntegrity = CorruptFrozenIntegrity
    /\ UNCHANGED vars

WorkFailureApplicable(reason) ==
    \/ /\ reason = AuthorityChangedReason
       /\ currentAuthority = ChangedAuthority
    \/ /\ reason = IngressExpiredReason
       /\ currentAuthority = OriginalAuthority
       /\ rawClock >= IntakeDeadline
    \/ /\ reason = AuthorizationExpiredReason
       /\ currentAuthority = OriginalAuthority
       /\ rawClock < IntakeDeadline
       /\ rawClock >= AuthorizationDeadline
    \/ /\ reason = GrantUnavailableReason
       /\ currentAuthority = OriginalAuthority
       /\ rawClock < IntakeDeadline
       /\ rawClock < AuthorizationDeadline
       /\ ~work.grantAvailable
    \/ /\ reason = DispatchWindowExpiredReason
       /\ work.phase = ConsumePhase
       /\ currentAuthority = OriginalAuthority
       /\ rawClock < IntakeDeadline
       /\ rawClock < AuthorizationDeadline
       /\ work.grantAvailable
       /\ ~work.dispatchWindowAvailable

(***************************************************************************
After an immutable kernel/control decision exists, an ISSUE or CONSUME phase
that becomes impossible is finalized fail-closed without rewriting that
decision.  Priority is authority change, ingress expiry, authorization expiry, grant
loss, then CONSUME dispatch-window loss.  A phase artifact
already durably persisted remains linkable;
this transition applies only before the once-only artifact exists.
***************************************************************************)
FinalizeImpossibleWork(worker, reason) ==
    /\ reason \in TerminalWorkFailureReasons
    /\ decision.present
    /\ decision.linked
    /\ decision.control = ControlAllow
    /\ work.phase \in {IssuePhase, ConsumePhase}
    /\ work.finalizationWrites = 0
    /\ IF work.phase = IssuePhase THEN ~authorization.present ELSE ~consumption.present
    /\ CurrentExactLease(worker)
    /\ WorkFailureApplicable(reason)
    /\ RecordTrustedTime
    /\ work' = [work EXCEPT
        !.phase = DonePhase,
        !.queueState = DoneQueue,
        !.status = FailedClosedStatus,
        !.statusRevision = work.statusRevision + 1,
        !.statusEvents = work.statusEvents
            \cup {<<work.statusRevision + 1, FailedClosedStatus>>},
        !.failureReason = reason,
        !.failurePhase = work.phase,
        !.finalizationWrites = 1
       ]
    /\ claim' = [claim EXCEPT
        !.workFinalized = claim.workFinalized \cup {
            <<claim.activeFence,
              claim.activePhase,
              rawClock,
              claim.activeWorker,
              reason>>
        },
        !.activeFence = NoFence,
        !.activeWorker = NoWorker,
        !.activePhase = NoPhase,
        !.activeAuthorityVector = NoAuthorityVector,
        !.leaseUntil = 0
       ]
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        decision,
        authorization,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

FinalizeAuthorityChanged(worker) ==
    FinalizeImpossibleWork(worker, AuthorityChangedReason)

FinalizeIngressExpired(worker) ==
    FinalizeImpossibleWork(worker, IngressExpiredReason)

FinalizeGrantUnavailable(worker) ==
    FinalizeImpossibleWork(worker, GrantUnavailableReason)

FinalizeAuthorizationExpired(worker) ==
    FinalizeImpossibleWork(worker, AuthorizationExpiredReason)

FinalizeDispatchWindowExpired(worker) ==
    FinalizeImpossibleWork(worker, DispatchWindowExpiredReason)

(***************************************************************************
record_control_evaluation is one abstract database transaction: the signed
evaluation/control decision, PhaseCompleted receipt, revision-2 status event,
and next queue phase appear together.  delivered=FALSE represents a lost
response after that complete commit.  Its exact retry is RecoverCompletedClaim,
which is historical, inert, and does not sample trusted time again.
***************************************************************************)
RecordEvaluation(worker, kernel, grantMode, delivered) ==
    /\ kernel \in {KernelAllow, KernelDeny}
    /\ grantMode \in GrantModes
    /\ delivered \in BOOLEAN
    /\ work.phase = EvaluatePhase
    /\ ~decision.present
    /\ intake.frozenIntegrity = ExactFrozenIntegrity
    /\ currentAuthority = OriginalAuthority
    /\ rawClock < IntakeDeadline
    /\ CurrentExactLease(worker)
    /\ RecordTrustedTime
    /\ decision' = [
        present |-> TRUE,
        kernel |-> kernel,
        control |-> ExpectedControl(kernel, grantMode),
        reason |-> ExpectedReason(kernel, grantMode),
        grant |-> ExpectedGrant(kernel, grantMode),
        nonce |-> DeterministicNonce,
        controlCommitment |-> ExactControlDecisionCommitment,
        commitment |-> ExactDecisionCommitment,
        writes |-> 1,
        linked |-> TRUE
       ]
    /\ LET terminal == ExpectedControl(kernel, grantMode) = ControlDeny
           nextPhase == IF terminal THEN DonePhase ELSE IssuePhase
           nextQueue == IF terminal THEN DoneQueue ELSE ReadyQueue
           nextStatus == ExpectedStatus(ExpectedControl(kernel, grantMode))
       IN
       /\ work' = [work EXCEPT
            !.phase = nextPhase,
            !.queueState = nextQueue,
            !.status = nextStatus,
            !.statusRevision = work.statusRevision + 1,
            !.statusEvents = work.statusEvents
                \cup {<<work.statusRevision + 1, nextStatus>>}
           ]
    /\ claim' = [claim EXCEPT
        !.completed = claim.completed \cup {
            <<claim.activeFence,
              claim.activePhase,
              rawClock,
              NoCompletionIdentity,
              claim.activeWorker>>
        },
        !.activeFence = NoFence,
        !.activeWorker = NoWorker,
        !.activePhase = NoPhase,
        !.activeAuthorityVector = NoAuthorityVector,
        !.leaseUntil = 0
       ]
    /\ knownDecisionFence' = NoFence
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        authorization,
        consumption,
        heldFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

(***************************************************************************
These are pre-kernel fail-closed business decisions under an exact claim.  The
frozen ingress row is revalidated first, then DB time/HWM are sampled.  A
changed current principal binding has deterministic priority over expiry when
both are true.  Neither branch creates a signed kernel evaluation, evaluation
nonce, selected grant, authorization, or consumption.
***************************************************************************)
RecordBoundaryDeny(worker, reason, delivered) ==
    /\ reason \in {AuthorityChangedReason, IngressExpiredReason}
    /\ delivered \in BOOLEAN
    /\ work.phase = EvaluatePhase
    /\ ~decision.present
    /\ intake.frozenIntegrity = ExactFrozenIntegrity
    /\ CurrentExactLease(worker)
    /\ \/ /\ reason = AuthorityChangedReason
           /\ currentAuthority = ChangedAuthority
       \/ /\ reason = IngressExpiredReason
           /\ currentAuthority = OriginalAuthority
           /\ rawClock >= IntakeDeadline
    /\ RecordTrustedTime
    /\ decision' = [
        present |-> TRUE,
        kernel |-> NoKernel,
        control |-> ControlDeny,
        reason |-> reason,
        grant |-> NoGrant,
        nonce |-> NoNonce,
        controlCommitment |-> ExactControlDecisionCommitment,
        commitment |-> NoCommitment,
        writes |-> 1,
        linked |-> TRUE
       ]
    /\ work' = [work EXCEPT
        !.phase = DonePhase,
        !.queueState = DoneQueue,
        !.status = DeniedStatus,
        !.statusRevision = work.statusRevision + 1,
        !.statusEvents = work.statusEvents
            \cup {<<work.statusRevision + 1, DeniedStatus>>}
       ]
    /\ claim' = [claim EXCEPT
        !.decisionFinalized = claim.decisionFinalized \cup {
            <<claim.activeFence,
              rawClock,
              claim.activeWorker,
              reason>>
        },
        !.activeFence = NoFence,
        !.activeWorker = NoWorker,
        !.activePhase = NoPhase,
        !.activeAuthorityVector = NoAuthorityVector,
        !.leaseUntil = 0
       ]
    /\ knownDecisionFence' = NoFence
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        authorization,
        consumption,
        heldFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

(***************************************************************************
Issuance is one atomic transaction: exact authorization record, control link, status
CAS, and READY CONSUME work appear together.  delivered=FALSE returns only
OutcomeUnknown even though that full durable result committed.  Exact recovery
is historical and inert; it never reconstructs the old issuer lease or another
executable capability.
***************************************************************************)
IssueAuthorization(worker, delivered) ==
    /\ delivered \in BOOLEAN
    /\ work.phase = IssuePhase
    /\ decision.linked
    /\ decision.control = ControlAllow
    /\ ~authorization.present
    /\ currentAuthority = OriginalAuthority
    /\ rawClock < IntakeDeadline
    /\ work.grantAvailable
    /\ rawClock < AuthorizationDeadline
    /\ CurrentExactLease(worker)
    /\ RecordTrustedTime
    /\ authorization' = [
        present |-> TRUE,
        commitment |-> ExactAuthorizationCommitment,
        writes |-> 1,
        linked |-> TRUE,
        response |-> IF delivered THEN FreshResponse ELSE OutcomeUnknownResponse,
        recoveredExecutable |-> FALSE
       ]
    /\ work' = [work EXCEPT
        !.phase = ConsumePhase,
        !.queueState = ReadyQueue,
        !.status = AuthorizationIssuedStatus,
        !.statusRevision = work.statusRevision + 1,
        !.statusEvents = work.statusEvents
            \cup {<<work.statusRevision + 1, AuthorizationIssuedStatus>>}
       ]
    /\ claim' = [claim EXCEPT
        !.completed = claim.completed \cup {
            <<claim.activeFence,
              claim.activePhase,
              rawClock,
              NoCompletionIdentity,
              claim.activeWorker>>
        },
        !.activeFence = NoFence,
        !.activeWorker = NoWorker,
        !.activePhase = NoPhase,
        !.activeAuthorityVector = NoAuthorityVector,
        !.leaseUntil = 0
       ]
    /\ knownAuthorizationFence' = NoFence
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        decision,
        consumption,
        heldFence,
        knownDecisionFence,
        knownConsumptionFence,
        restartSeen
       >>

RecoverAuthorizationExact ==
    /\ authorization.present
    /\ authorization.linked
    /\ authorization.commitment = ExactAuthorizationCommitment
    /\ authorization' = [authorization EXCEPT
        !.response = RecoveredResponse,
        !.recoveredExecutable = FALSE
       ]
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        consumption,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectAuthorizationRecoveryMismatch(requestCommitment) ==
    /\ authorization.present
    /\ authorization.commitment = ExactAuthorizationCommitment
    /\ requestCommitment = WrongAuthorizationCommitment
    /\ requestCommitment # authorization.commitment
    /\ UNCHANGED vars

(***************************************************************************
Consumption is likewise one atomic transaction: exact receipt/outbox, control
link, DISPATCH_PENDING status, and DONE queue appear together.  A lost commit
response is OutcomeUnknown, never success.  Exact durable recovery is inert and
does not recreate the consumer lease or a second consumption authority.
***************************************************************************)
ConsumeAuthorization(worker, delivered) ==
    /\ delivered \in BOOLEAN
    /\ work.phase = ConsumePhase
    /\ authorization.linked
    /\ ~consumption.present
    /\ currentAuthority = OriginalAuthority
    /\ rawClock < IntakeDeadline
    /\ work.grantAvailable
    /\ work.dispatchWindowAvailable
    /\ rawClock < AuthorizationDeadline
    /\ CurrentExactLease(worker)
    /\ RecordTrustedTime
    /\ consumption' = [
        present |-> TRUE,
        commitment |-> ExactConsumptionCommitment,
        writes |-> 1,
        linked |-> TRUE,
        response |-> IF delivered THEN FreshResponse ELSE OutcomeUnknownResponse,
        recoveredExecutable |-> FALSE
       ]
    /\ work' = [work EXCEPT
        !.phase = DonePhase,
        !.queueState = DoneQueue,
        !.status = DispatchPendingStatus,
        !.statusRevision = work.statusRevision + 1,
        !.statusEvents = work.statusEvents
            \cup {<<work.statusRevision + 1, DispatchPendingStatus>>}
       ]
    /\ claim' = [claim EXCEPT
        !.completed = claim.completed \cup {
            <<claim.activeFence,
              claim.activePhase,
              rawClock,
              ConsumeCompletionIdentity,
              claim.activeWorker>>
        },
        !.activeFence = NoFence,
        !.activeWorker = NoWorker,
        !.activePhase = NoPhase,
        !.activeAuthorityVector = NoAuthorityVector,
        !.leaseUntil = 0
       ]
    /\ knownConsumptionFence' = NoFence
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        currentVerifier,
        currentAuthority,
        decision,
        authorization,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        restartSeen
       >>

RecoverConsumptionExact ==
    /\ consumption.present
    /\ consumption.linked
    /\ consumption.commitment = ExactConsumptionCommitment
    /\ consumption' = [consumption EXCEPT
        !.response = RecoveredResponse,
        !.recoveredExecutable = FALSE
       ]
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        heldFence,
        knownDecisionFence,
        knownAuthorizationFence,
        knownConsumptionFence,
        restartSeen
       >>

RejectConsumptionRecoveryMismatch(requestCommitment) ==
    /\ consumption.present
    /\ consumption.commitment = ExactConsumptionCommitment
    /\ requestCommitment = WrongConsumptionCommitment
    /\ requestCommitment # consumption.commitment
    /\ UNCHANGED vars

NoWork ==
    /\ work.queueState \in {NoQueue, DoneQueue}
    /\ UNCHANGED vars

(***************************************************************************
A restart destroys only volatile capabilities/evidence delivery.  Durable
intake, HWM, queue, claims, signed decision, authorization, consumption, status events,
and append-only histories remain.  A current active claim must be recovered;
an expired one may be taken over under a new global fence.
***************************************************************************)
Restart ==
    /\ ~restartSeen
    /\ heldFence' = [worker \in Workers |-> NoFence]
    /\ knownDecisionFence' = NoFence
    /\ knownAuthorizationFence' = NoFence
    /\ knownConsumptionFence' = NoFence
    /\ restartSeen' = TRUE
    /\ intake' = [intake EXCEPT !.response = NoIntakeResponse]
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        currentVerifier,
        currentAuthority,
        work,
        claim,
        decision,
        authorization,
        consumption
       >>

Stutter == UNCHANGED vars

Next ==
    \/ \E sample \in 0..MaxTime : SetRawClock(sample)
    \/ RotateVerifier
    \/ RemoveVerifier
    \/ ChangeAuthority
    \/ RevokeSelectedGrant
    \/ CloseDispatchWindow
    \/ InjectFrozenCorruption
    \/ \E delivered \in BOOLEAN : AcceptFresh(delivered)
    \/ \E wire \in RecoveryWires : RecoverSubmission(wire)
    \/ RejectBadSignature
    \/ RejectPayloadConflict
    \/ RejectIntakeTemporal
    \/ RejectIntakeRollback
    \/ \E worker \in Workers, delivered \in BOOLEAN :
        ClaimNext(worker, delivered)
    \/ \E worker \in Workers, claimId \in 1..MaxClaims :
        RecoverClaimExact(worker, claimId)
    \/ \E worker \in Workers, claimId \in 1..MaxClaims :
        RecoverCompletedClaim(worker, claimId)
    \/ \E worker \in Workers, claimId \in 1..MaxClaims :
        RecoverDecisionFinalized(worker, claimId)
    \/ \E worker \in Workers, claimId \in 1..MaxClaims :
        RecoverWorkFinalized(worker, claimId)
    \/ \E worker \in Workers, claimId \in 1..MaxClaims :
        RejectClaimRecoveryMismatch(worker, claimId)
    \/ \E worker \in Workers : RejectExpiredLease(worker)
    \/ \E worker \in Workers : RejectWorkRollback(worker)
    \/ \E worker \in Workers : RejectFrozenMismatch(worker)
    \/ \E worker \in Workers : FinalizeAuthorityChanged(worker)
    \/ \E worker \in Workers : FinalizeIngressExpired(worker)
    \/ \E worker \in Workers : FinalizeGrantUnavailable(worker)
    \/ \E worker \in Workers : FinalizeAuthorizationExpired(worker)
    \/ \E worker \in Workers : FinalizeDispatchWindowExpired(worker)
    \/ \E worker \in Workers,
          kernel \in {KernelAllow, KernelDeny},
          grantMode \in GrantModes,
          delivered \in BOOLEAN :
        RecordEvaluation(worker, kernel, grantMode, delivered)
    \/ \E worker \in Workers,
          reason \in {AuthorityChangedReason, IngressExpiredReason},
          delivered \in BOOLEAN :
        RecordBoundaryDeny(worker, reason, delivered)
    \/ \E worker \in Workers, delivered \in BOOLEAN :
        IssueAuthorization(worker, delivered)
    \/ RecoverAuthorizationExact
    \/ RejectAuthorizationRecoveryMismatch(WrongAuthorizationCommitment)
    \/ \E worker \in Workers, delivered \in BOOLEAN :
        ConsumeAuthorization(worker, delivered)
    \/ RecoverConsumptionExact
    \/ RejectConsumptionRecoveryMismatch(WrongConsumptionCommitment)
    \/ NoWork
    \/ Restart
    \/ Stutter

Spec == Init /\ [][Next]_vars

IntakeType ==
    [
        present : BOOLEAN,
        nonceOwner : {NoPayload, ExactPayload},
        payload : {NoPayload, ExactPayload},
        firstWire : {NoWire, OriginalWire},
        frozenVerifier : Verifiers,
        frozenIntegrity : FrozenIntegrityStates,
        frozenFirstIntegrity : {ExactFrozenIntegrity},
        writes : 0..1,
        response : IntakeResponses,
        recoveredExecutable : BOOLEAN
    ]

WorkType ==
    [
        phase : Phases,
        queueState : QueueStates,
        status : Statuses,
        statusRevision : 0..4,
        statusEvents : SUBSET ((1..4) \X Statuses),
        grantAvailable : BOOLEAN,
        dispatchWindowAvailable : BOOLEAN,
        failureReason : WorkFailureReasons,
        failurePhase : Phases,
        finalizationWrites : 0..1
    ]

ClaimType ==
    [
        globalFence : 0..MaxClaims,
        activeFence : 0..MaxClaims,
        activeWorker : Workers \cup {NoWorker},
        activePhase : Phases,
        activeAuthorityVector : AuthorityVectors,
        leaseUntil : 0..(MaxTime + LeaseLength),
        history : SUBSET (
            (1..MaxClaims) \X Phases \X Workers \X Authorities
        ),
        completed : SUBSET (
            (1..MaxClaims)
                \X Phases
                \X (0..MaxTime)
                \X CompletionIdentities
                \X Workers
        ),
        decisionFinalized : SUBSET (
            (1..MaxClaims)
                \X (0..MaxTime)
                \X Workers
                \X PreKernelDecisionReasons
        ),
        workFinalized : SUBSET (
            (1..MaxClaims)
                \X {IssuePhase, ConsumePhase}
                \X (0..MaxTime)
                \X Workers
                \X TerminalWorkFailureReasons
        ),
        recoveredCompletionFence : 0..MaxClaims,
        recoveredCompletionPhase : Phases,
        recoveredCompletionIdentity : CompletionIdentities,
        recoveredCompletionExecutable : BOOLEAN,
        recoveredDecisionFence : 0..MaxClaims,
        recoveredDecisionReason : DecisionReasons,
        recoveredDecisionExecutable : BOOLEAN,
        recoveredWorkFence : 0..MaxClaims,
        recoveredWorkPhase : Phases,
        recoveredWorkReason : WorkFailureReasons,
        recoveredWorkExecutable : BOOLEAN
    ]

DecisionType ==
    [
        present : BOOLEAN,
        kernel : KernelOutcomes,
        control : ControlOutcomes,
        reason : DecisionReasons,
        grant : SelectedGrants,
        nonce : {NoNonce, DeterministicNonce},
        controlCommitment : {NoCommitment, ExactControlDecisionCommitment},
        commitment : {NoCommitment, ExactDecisionCommitment},
        writes : 0..1,
        linked : BOOLEAN
    ]

AuthorizationType ==
    [
        present : BOOLEAN,
        commitment : {NoCommitment, ExactAuthorizationCommitment},
        writes : 0..1,
        linked : BOOLEAN,
        response : {
            NoIntakeResponse,
            FreshResponse,
            OutcomeUnknownResponse,
            RecoveredResponse
        },
        recoveredExecutable : BOOLEAN
    ]

ConsumptionType ==
    [
        present : BOOLEAN,
        commitment : {NoCommitment, ExactConsumptionCommitment},
        writes : 0..1,
        linked : BOOLEAN,
        response : {
            NoIntakeResponse,
            FreshResponse,
            OutcomeUnknownResponse,
            RecoveredResponse
        },
        recoveredExecutable : BOOLEAN
    ]

TypeOK ==
    /\ rawClock \in 0..MaxTime
    /\ highWaterMark \in 0..MaxTime
    /\ highWaterHistory \subseteq 0..MaxTime
    /\ authenticatedSamples \subseteq 0..MaxTime
    /\ currentVerifier \in Verifiers
    /\ currentAuthority \in Authorities
    /\ intake \in IntakeType
    /\ work \in WorkType
    /\ claim \in ClaimType
    /\ decision \in DecisionType
    /\ authorization \in AuthorizationType
    /\ consumption \in ConsumptionType
    /\ heldFence \in [Workers -> 0..MaxClaims]
    /\ knownDecisionFence \in 0..MaxClaims
    /\ knownAuthorizationFence \in 0..MaxClaims
    /\ knownConsumptionFence \in 0..MaxClaims
    /\ restartSeen \in BOOLEAN

AtomicIntakeNonceStatusAndReadyWork ==
    intake.present <=>
        /\ intake.writes = 1
        /\ intake.nonceOwner = ExactPayload
        /\ intake.payload = ExactPayload
        /\ intake.firstWire = OriginalWire
        /\ intake.frozenVerifier = OriginalVerifier
        /\ intake.frozenFirstIntegrity = ExactFrozenIntegrity
        /\ work.phase # NoPhase
        /\ <<1, AcceptedStatus>> \in work.statusEvents

NoPartialIntakeArtifacts ==
    ~intake.present =>
        /\ intake.writes = 0
        /\ intake.nonceOwner = NoPayload
        /\ intake.payload = NoPayload
        /\ intake.firstWire = NoWire
        /\ work.phase = NoPhase
        /\ work.queueState = NoQueue
        /\ work.status = NoStatus
        /\ work.statusRevision = 0
        /\ work.statusEvents = {}

RecoveredSubmissionIsHistoricalAndInert ==
    intake.response = RecoveredResponse =>
        /\ intake.present
        /\ intake.payload = ExactPayload
        /\ intake.frozenVerifier = OriginalVerifier
        /\ intake.frozenIntegrity = ExactFrozenIntegrity
        /\ ~intake.recoveredExecutable

OutcomeUnknownAlreadyCommittedAtomically ==
    intake.response = OutcomeUnknownResponse =>
        /\ intake.present
        /\ intake.writes = 1
        /\ work.phase = EvaluatePhase
        /\ work.queueState = ReadyQueue
        /\ work.status = AcceptedStatus

FirstWireAuditIsImmutable ==
    intake.present => intake.firstWire = OriginalWire

HighWaterMarkMonotone ==
    \A seen \in highWaterHistory : seen <= highWaterMark

HighWaterMarkCoversAuthenticatedSamples ==
    \A sample \in authenticatedSamples : sample <= highWaterMark

ClaimHistoryIsAppendOnlyFreshAndGloballyFenced ==
    /\ Cardinality(claim.history) = claim.globalFence
    /\ \A record \in claim.history :
        /\ record[1] \in 1..claim.globalFence
        /\ record[2] \in {EvaluatePhase, IssuePhase, ConsumePhase}
        /\ record[3] \in Workers
        /\ record[3] = WorkerForPhase(record[2])
        /\ record[4] \in Authorities
    /\ \A fence \in 1..claim.globalFence :
        \E phase \in {EvaluatePhase, IssuePhase, ConsumePhase},
           worker \in Workers :
            \E authority \in Authorities :
                <<fence, phase, worker, authority>> \in claim.history

CompletedClaimsHaveUniqueInertReceipts ==
    /\ Cardinality(claim.completed) <= claim.globalFence
    /\ \A first, second \in claim.completed :
        first[1] = second[1] => first = second
    /\ \A completion \in claim.completed :
        /\ \E authority \in Authorities :
            <<completion[1],
              completion[2],
              completion[5],
              authority>> \in claim.history
        /\ completion[1] # claim.activeFence
        /\ CASE completion[2] = EvaluatePhase ->
                completion[4] = NoCompletionIdentity
           [] completion[2] = IssuePhase ->
                completion[4] = NoCompletionIdentity
           [] completion[2] = ConsumePhase ->
                completion[4] = ConsumeCompletionIdentity
    /\ ~claim.recoveredCompletionExecutable
    /\ claim.recoveredCompletionFence = NoFence =>
        /\ claim.recoveredCompletionPhase = NoPhase
        /\ claim.recoveredCompletionIdentity = NoCompletionIdentity
    /\ claim.recoveredCompletionFence > 0 =>
        \E completedAt \in 0..MaxTime,
           worker \in Workers :
            <<claim.recoveredCompletionFence,
              claim.recoveredCompletionPhase,
              completedAt,
              claim.recoveredCompletionIdentity,
              worker>> \in claim.completed

TerminalClaimHistoriesAreDisjointUniqueAndInert ==
    /\ Cardinality(claim.decisionFinalized) <= 1
    /\ Cardinality(claim.workFinalized) <= 1
    /\ \A finalized \in claim.decisionFinalized :
        /\ finalized[3] = EvaluatorWorker
        /\ finalized[4] \in PreKernelDecisionReasons
        /\ finalized[4] = decision.reason
        /\ \E authority \in Authorities :
            <<finalized[1],
              EvaluatePhase,
              finalized[3],
              authority>> \in claim.history
        /\ finalized[1] # claim.activeFence
    /\ \A finalized \in claim.workFinalized :
        /\ finalized[2] \in {IssuePhase, ConsumePhase}
        /\ finalized[4] = WorkerForPhase(finalized[2])
        /\ finalized[5] \in TerminalWorkFailureReasons
        /\ finalized[2] = work.failurePhase
        /\ finalized[5] = work.failureReason
        /\ \E authority \in Authorities :
            <<finalized[1],
              finalized[2],
              finalized[4],
              authority>> \in claim.history
        /\ finalized[1] # claim.activeFence
    /\ \A completed \in claim.completed,
           finalized \in claim.decisionFinalized :
        completed[1] # finalized[1]
    /\ \A completed \in claim.completed,
           finalized \in claim.workFinalized :
        completed[1] # finalized[1]
    /\ \A decisionFinalization \in claim.decisionFinalized,
           workFinalization \in claim.workFinalized :
        decisionFinalization[1] # workFinalization[1]
    /\ ~claim.recoveredDecisionExecutable
    /\ ~claim.recoveredWorkExecutable
    /\ claim.recoveredDecisionFence = NoFence =>
        claim.recoveredDecisionReason = NoReason
    /\ claim.recoveredDecisionFence > 0 =>
        \E finalizedAt \in 0..MaxTime,
           worker \in Workers :
            <<claim.recoveredDecisionFence,
              finalizedAt,
              worker,
              claim.recoveredDecisionReason>> \in claim.decisionFinalized
    /\ claim.recoveredWorkFence = NoFence =>
        /\ claim.recoveredWorkPhase = NoPhase
        /\ claim.recoveredWorkReason = NoWorkFailure
    /\ claim.recoveredWorkFence > 0 =>
        \E finalizedAt \in 0..MaxTime,
           worker \in Workers :
            <<claim.recoveredWorkFence,
              claim.recoveredWorkPhase,
              finalizedAt,
              worker,
              claim.recoveredWorkReason>> \in claim.workFinalized

ActiveLeaseHasExactAppendOnlyClaim ==
    (work.queueState = LeasedQueue) <=>
        /\ claim.activeFence > 0
        /\ claim.activeWorker \in Workers
        /\ claim.activeWorker = WorkerForPhase(work.phase)
        /\ claim.activePhase = work.phase
        /\ claim.activeAuthorityVector \in Authorities
        /\ <<claim.activeFence,
             claim.activePhase,
             claim.activeWorker,
             claim.activeAuthorityVector>>
            \in claim.history

NoActiveLeaseOutsideLeasedQueue ==
    work.queueState # LeasedQueue =>
        /\ claim.activeFence = NoFence
        /\ claim.activeWorker = NoWorker
        /\ claim.activePhase = NoPhase
        /\ claim.activeAuthorityVector = NoAuthorityVector
        /\ claim.leaseUntil = 0

OldFenceCannotAuthorizeTakeover ==
    \A worker \in Workers :
        heldFence[worker] # claim.activeFence =>
            \/ work.queueState # LeasedQueue
            \/ ~ExactLease(worker)

DecisionMatrixIsServerDerived ==
    decision.present =>
        /\ decision.writes = 1
        /\ decision.controlCommitment = ExactControlDecisionCommitment
        /\ CASE decision.reason = AuthorityChangedReason ->
                /\ decision.kernel = NoKernel
                /\ decision.control = ControlDeny
                /\ decision.grant = NoGrant
                /\ decision.nonce = NoNonce
                /\ decision.commitment = NoCommitment
           [] decision.reason = IngressExpiredReason ->
                /\ decision.kernel = NoKernel
                /\ decision.control = ControlDeny
                /\ decision.grant = NoGrant
                /\ decision.nonce = NoNonce
                /\ decision.commitment = NoCommitment
           [] decision.kernel = KernelDeny ->
                /\ decision.control = ControlDeny
                /\ decision.reason = KernelDenyReason
                /\ decision.grant = NoGrant
                /\ decision.nonce = DeterministicNonce
                /\ decision.commitment = ExactDecisionCommitment
           [] decision.reason = GrantUnavailableReason ->
                /\ decision.control = ControlDeny
                /\ decision.grant = NoGrant
                /\ decision.kernel = KernelAllow
                /\ decision.nonce = DeterministicNonce
                /\ decision.commitment = ExactDecisionCommitment
           [] decision.reason = ControlAllowReason ->
                /\ decision.control = ControlAllow
                /\ decision.grant = ServerGrant
                /\ decision.kernel = KernelAllow
                /\ decision.nonce = DeterministicNonce
                /\ decision.commitment = ExactDecisionCommitment

NoDecisionBeforeEvaluationClaim ==
    decision.present =>
        /\ intake.present
        /\ intake.frozenIntegrity = ExactFrozenIntegrity
        /\ claim.globalFence > 0

BoundaryDenyIsPreKernelTerminalAndPrioritized ==
    decision.reason \in {AuthorityChangedReason, IngressExpiredReason} =>
        /\ decision.kernel = NoKernel
        /\ decision.control = ControlDeny
        /\ decision.grant = NoGrant
        /\ decision.nonce = NoNonce
        /\ decision.commitment = NoCommitment
        /\ ~authorization.present
        /\ ~consumption.present
        /\ decision.linked
        /\ work.phase = DonePhase
        /\ work.queueState = DoneQueue
        /\ work.status = DeniedStatus
        /\ claim.completed = {}
        /\ claim.workFinalized = {}
        /\ Cardinality(claim.decisionFinalized) = 1
        /\ (decision.reason = IngressExpiredReason =>
            currentAuthority = OriginalAuthority)

CorruptFrozenIngressCreatesNoDecisionOrEffect ==
    intake.frozenIntegrity = CorruptFrozenIntegrity =>
        /\ ~decision.present
        /\ ~authorization.present
        /\ ~consumption.present

WorkFinalizationDoesNotRewriteDecisionOrCreateEffect ==
    /\ (work.finalizationWrites = 0 <=>
        work.failureReason = NoWorkFailure)
    /\ (work.finalizationWrites = 0 <=>
        work.failurePhase = NoPhase)
    /\ ~work.dispatchWindowAvailable =>
        /\ decision.linked
        /\ decision.control = ControlAllow
        /\ authorization.linked
        /\ work.phase \in {ConsumePhase, DonePhase}
    /\ work.finalizationWrites = 1 =>
        /\ work.failureReason \in TerminalWorkFailureReasons
        /\ decision.present
        /\ decision.linked
        /\ decision.control = ControlAllow
        /\ work.failurePhase \in {IssuePhase, ConsumePhase}
        /\ work.phase = DonePhase
        /\ work.queueState = DoneQueue
        /\ work.status = FailedClosedStatus
        /\ ~consumption.present
        /\ (work.failurePhase = IssuePhase => ~authorization.present)
        /\ (work.failurePhase = ConsumePhase =>
            /\ authorization.linked
            /\ ~consumption.present)
        /\ (work.failureReason = AuthorizationExpiredReason
            /\ work.failurePhase = IssuePhase => ~authorization.present)
        /\ (work.failureReason = AuthorizationExpiredReason
            /\ work.failurePhase = ConsumePhase => authorization.linked)
        /\ (work.failureReason = DispatchWindowExpiredReason =>
            /\ work.failurePhase = ConsumePhase
            /\ authorization.linked
            /\ ~consumption.present)

EvaluationClaimsCarryCurrentAuthorityVector ==
    work.queueState = LeasedQueue /\ claim.activePhase = EvaluatePhase =>
        /\ claim.activeWorker = EvaluatorWorker
        /\ claim.activeAuthorityVector \in Authorities

PhaseLinksAreOrdered ==
    /\ authorization.present =>
        /\ decision.present
        /\ decision.linked
        /\ decision.control = ControlAllow
        /\ authorization.linked
    /\ consumption.present =>
        /\ authorization.present
        /\ authorization.linked
        /\ consumption.linked
    /\ consumption.linked =>
        /\ work.phase = DonePhase
        /\ work.queueState = DoneQueue

EachPhaseArtifactIsOnceOnlyAndExact ==
    /\ decision.present <=> decision.writes = 1
    /\ authorization.present <=> authorization.writes = 1
    /\ consumption.present <=> consumption.writes = 1
    /\ decision.present =>
        decision.controlCommitment = ExactControlDecisionCommitment
    /\ decision.kernel \in {KernelAllow, KernelDeny} =>
        decision.commitment = ExactDecisionCommitment
    /\ authorization.present => authorization.commitment = ExactAuthorizationCommitment
    /\ consumption.present =>
        consumption.commitment = ExactConsumptionCommitment

AtomicEvaluationCommit ==
    /\ decision.kernel \in {KernelAllow, KernelDeny} =>
        /\ decision.linked
        /\ claim.decisionFinalized = {}
        /\ \E completion \in claim.completed :
            /\ completion[2] = EvaluatePhase
            /\ completion[4] = NoCompletionIdentity
            /\ completion[5] = EvaluatorWorker
        /\ <<2, ExpectedStatus(decision.control)>> \in work.statusEvents
    /\ knownDecisionFence = NoFence

AtomicIssueAndConsumptionCommits ==
    /\ authorization.present =>
        /\ authorization.linked
        /\ <<3, AuthorizationIssuedStatus>> \in work.statusEvents
        /\ ~authorization.recoveredExecutable
        /\ \E completion \in claim.completed :
            /\ completion[2] = IssuePhase
            /\ completion[4] = NoCompletionIdentity
            /\ completion[5] = IssuerWorker
    /\ consumption.present =>
        /\ consumption.linked
        /\ <<4, DispatchPendingStatus>> \in work.statusEvents
        /\ ~consumption.recoveredExecutable
        /\ \E completion \in claim.completed :
            /\ completion[2] = ConsumePhase
            /\ completion[4] = ConsumeCompletionIdentity
            /\ completion[5] = ConsumerWorker
    /\ authorization.response \in {OutcomeUnknownResponse, RecoveredResponse} =>
        /\ authorization.present
        /\ authorization.linked
        /\ ~authorization.recoveredExecutable
    /\ consumption.response \in {OutcomeUnknownResponse, RecoveredResponse} =>
        /\ consumption.present
        /\ consumption.linked
        /\ ~consumption.recoveredExecutable
    /\ knownAuthorizationFence = NoFence
    /\ knownConsumptionFence = NoFence

QueuePhaseFollowsDurableLinks ==
    /\ ~decision.linked => work.phase \in {NoPhase, EvaluatePhase}
    /\ decision.linked
       /\ decision.control = ControlAllow
       /\ ~authorization.linked
       /\ work.finalizationWrites = 0 =>
        work.phase = IssuePhase
    /\ authorization.linked
       /\ ~consumption.linked
       /\ work.finalizationWrites = 0 => work.phase = ConsumePhase
    /\ decision.linked /\ decision.control = ControlDeny =>
        /\ work.phase = DonePhase
        /\ work.queueState = DoneQueue
    /\ consumption.linked =>
        /\ work.phase = DonePhase
        /\ work.queueState = DoneQueue
    /\ work.finalizationWrites = 1 =>
        /\ work.phase = DonePhase
        /\ work.queueState = DoneQueue

StatusProjectionMatchesLinkedHistory ==
    /\ intake.present =>
        /\ work.statusRevision = Cardinality(work.statusEvents)
        /\ <<work.statusRevision, work.status>> \in work.statusEvents
    /\ intake.present /\ ~decision.linked =>
        /\ work.status = AcceptedStatus
        /\ work.statusRevision = 1
    /\ decision.linked /\ decision.control = ControlDeny =>
        /\ work.status = DeniedStatus
        /\ work.statusRevision = 2
    /\ decision.linked
       /\ decision.control = ControlAllow
       /\ ~authorization.linked
       /\ work.finalizationWrites = 0 =>
        /\ work.status = AuthorizedStatus
        /\ work.statusRevision = 2
    /\ authorization.linked
       /\ ~consumption.linked
       /\ work.finalizationWrites = 0 =>
        /\ work.status = AuthorizationIssuedStatus
        /\ work.statusRevision = 3
    /\ consumption.linked =>
        /\ work.status = DispatchPendingStatus
        /\ work.statusRevision = 4
    /\ work.finalizationWrites = 1 =>
        /\ work.status = FailedClosedStatus
        /\ work.statusRevision = IF authorization.linked THEN 4 ELSE 3

(***************************************************************************
The runtime projection has an explicit revision-2 AUTHORIZED state.  Once
that event exists, revision 3 is either the atomic AUTHORIZATION_ISSUED commit or an
ISSUE-phase FAILED_CLOSED finalization.  A revision-4 successor first passed
through AUTHORIZATION_ISSUED and is then either DISPATCH_PENDING or a CONSUME-phase
FAILED_CLOSED finalization.  No path can silently retain ACCEPTED after ALLOW.
***************************************************************************)
AuthorizedProjectionAdvancesOnlyThroughRuntimeEdges ==
    <<2, AuthorizedStatus>> \in work.statusEvents =>
        /\ decision.present
        /\ decision.linked
        /\ decision.control = ControlAllow
        /\ <<2, AcceptedStatus>> \notin work.statusEvents
        /\ <<2, DeniedStatus>> \notin work.statusEvents
        /\ CASE work.statusRevision = 2 ->
                /\ work.status = AuthorizedStatus
                /\ work.phase = IssuePhase
                /\ ~authorization.linked
                /\ work.finalizationWrites = 0
           [] work.statusRevision = 3 ->
                \/ /\ work.status = AuthorizationIssuedStatus
                   /\ <<3, AuthorizationIssuedStatus>> \in work.statusEvents
                   /\ authorization.linked
                   /\ work.phase = ConsumePhase
                   /\ work.finalizationWrites = 0
                \/ /\ work.status = FailedClosedStatus
                   /\ <<3, FailedClosedStatus>> \in work.statusEvents
                   /\ ~authorization.present
                   /\ work.failurePhase = IssuePhase
                   /\ work.finalizationWrites = 1
           [] work.statusRevision = 4 ->
                /\ <<3, AuthorizationIssuedStatus>> \in work.statusEvents
                /\ authorization.linked
                /\ CASE work.status = DispatchPendingStatus ->
                        /\ <<4, DispatchPendingStatus>> \in work.statusEvents
                        /\ consumption.linked
                   [] work.status = FailedClosedStatus ->
                        /\ <<4, FailedClosedStatus>> \in work.statusEvents
                        /\ ~consumption.present
                        /\ work.failurePhase = ConsumePhase
                        /\ work.finalizationWrites = 1

RestartRetainsAllDurableSafetyState ==
    restartSeen =>
        /\ heldFence \in [Workers -> 0..MaxClaims]
        /\ intake.writes \in 0..1
        /\ decision.writes \in 0..1
        /\ authorization.writes \in 0..1
        /\ consumption.writes \in 0..1

=============================================================================
