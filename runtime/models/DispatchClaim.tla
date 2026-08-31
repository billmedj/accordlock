---------------------------- MODULE DispatchClaim ----------------------------
EXTENDS Naturals

CONSTANTS MaxTime, DispatchDeadline, LeaseLength, MaxRejects

Workers == {"worker-a", "worker-b"}

VARIABLES
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    claimOwner,
    claimLeaseUntil,
    claimSuccesses,
    attemptState,
    attemptOwner,
    attemptAuthorities,
    dispatchBoundaryObserved,
    claimSuccessesAtDispatchBoundary,
    attemptAuthoritiesAtDispatchBoundary,
    leaseBoundaryObserved,
    attemptAuthoritiesAtLeaseBoundary,
    rejectedAttempts,
    lastRequestOutcome,
    clockSampleAtLastRequest,
    highWaterMarkBeforeLastRequest,
    claimSuccessesBeforeLastRequest,
    attemptAuthoritiesBeforeLastRequest

vars == <<
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    claimOwner,
    claimLeaseUntil,
    claimSuccesses,
    attemptState,
    attemptOwner,
    attemptAuthorities,
    dispatchBoundaryObserved,
    claimSuccessesAtDispatchBoundary,
    attemptAuthoritiesAtDispatchBoundary,
    leaseBoundaryObserved,
    attemptAuthoritiesAtLeaseBoundary,
    rejectedAttempts,
    lastRequestOutcome,
    clockSampleAtLastRequest,
    highWaterMarkBeforeLastRequest,
    claimSuccessesBeforeLastRequest,
    attemptAuthoritiesBeforeLastRequest
>>

Min(a, b) == IF a <= b THEN a ELSE b

Init ==
    /\ rawClock = 0
    /\ highWaterMark = 0
    /\ highWaterHistory = {0}
    /\ authenticatedSamples = {}
    /\ claimOwner = "NONE"
    /\ claimLeaseUntil = 0
    /\ claimSuccesses = 0
    /\ attemptState = "NONE"
    /\ attemptOwner = "NONE"
    /\ attemptAuthorities = 0
    /\ dispatchBoundaryObserved = FALSE
    /\ claimSuccessesAtDispatchBoundary = 0
    /\ attemptAuthoritiesAtDispatchBoundary = 0
    /\ leaseBoundaryObserved = FALSE
    /\ attemptAuthoritiesAtLeaseBoundary = 0
    /\ rejectedAttempts = 0
    /\ lastRequestOutcome = "NONE"
    /\ clockSampleAtLastRequest = 0
    /\ highWaterMarkBeforeLastRequest = 0
    /\ claimSuccessesBeforeLastRequest = 0
    /\ attemptAuthoritiesBeforeLastRequest = 0

(*
Only an exactly routed, authenticated request may record a clock sample.  A
sample below the persistent high-water mark is rejected as rollback, rather
than clamped and accepted.  A current sample is recorded for both successful
requests and temporal rejections.  Identity, route, and token rejections do not
change the high-water mark.
*)
RecordAuthenticatedObservation ==
    /\ rawClock >= highWaterMark
    /\ highWaterMark' = rawClock
    /\ highWaterHistory' = highWaterHistory \cup {rawClock}
    /\ authenticatedSamples' = authenticatedSamples \cup {rawClock}
    /\ dispatchBoundaryObserved' =
        (dispatchBoundaryObserved \/ (rawClock >= DispatchDeadline))
    /\ claimSuccessesAtDispatchBoundary' =
        IF ~dispatchBoundaryObserved /\ rawClock >= DispatchDeadline
        THEN claimSuccesses
        ELSE claimSuccessesAtDispatchBoundary
    /\ attemptAuthoritiesAtDispatchBoundary' =
        IF ~dispatchBoundaryObserved /\ rawClock >= DispatchDeadline
        THEN attemptAuthorities
        ELSE attemptAuthoritiesAtDispatchBoundary
    /\ leaseBoundaryObserved' =
        (leaseBoundaryObserved
        \/ (claimOwner # "NONE" /\ rawClock >= claimLeaseUntil))
    /\ attemptAuthoritiesAtLeaseBoundary' =
        IF ~leaseBoundaryObserved
           /\ claimOwner # "NONE"
           /\ rawClock >= claimLeaseUntil
        THEN attemptAuthorities
        ELSE attemptAuthoritiesAtLeaseBoundary

RecordRequestOutcome(outcome) ==
    /\ lastRequestOutcome' = outcome
    /\ clockSampleAtLastRequest' = rawClock
    /\ highWaterMarkBeforeLastRequest' = highWaterMark
    /\ claimSuccessesBeforeLastRequest' = claimSuccesses
    /\ attemptAuthoritiesBeforeLastRequest' = attemptAuthorities

SetRawClock(t) ==
    /\ t \in 0..MaxTime
    /\ rawClock' = t
    /\ UNCHANGED <<
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities,
        dispatchBoundaryObserved,
        claimSuccessesAtDispatchBoundary,
        attemptAuthoritiesAtDispatchBoundary,
        leaseBoundaryObserved,
        attemptAuthoritiesAtLeaseBoundary,
        rejectedAttempts,
        lastRequestOutcome,
        clockSampleAtLastRequest,
        highWaterMarkBeforeLastRequest,
        claimSuccessesBeforeLastRequest,
        attemptAuthoritiesBeforeLastRequest
        >>

ClaimSuccess(worker) ==
    /\ worker \in Workers
    /\ claimOwner = "NONE"
    /\ rawClock >= highWaterMark
    /\ rawClock < DispatchDeadline
    /\ RecordAuthenticatedObservation
    /\ RecordRequestOutcome("CLAIM_SUCCESS")
    /\ claimOwner' = worker
    /\ claimLeaseUntil' = Min(rawClock + LeaseLength, DispatchDeadline)
    /\ claimSuccesses' = claimSuccesses + 1
    /\ UNCHANGED <<
        rawClock,
        attemptState,
        attemptOwner,
        attemptAuthorities,
        rejectedAttempts
        >>

RejectClaimTemporal(worker) ==
    /\ worker \in Workers
    /\ claimOwner = "NONE"
    /\ rejectedAttempts < MaxRejects
    /\ rawClock >= highWaterMark
    /\ rawClock >= DispatchDeadline
    /\ RecordAuthenticatedObservation
    /\ RecordRequestOutcome("TEMPORAL_REJECT")
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        rawClock,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities
        >>

RejectClaimRollback(worker) ==
    /\ worker \in Workers
    /\ claimOwner = "NONE"
    /\ rejectedAttempts < MaxRejects
    /\ rawClock < highWaterMark
    /\ RecordRequestOutcome("ROLLBACK_REJECT")
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities,
        dispatchBoundaryObserved,
        claimSuccessesAtDispatchBoundary,
        attemptAuthoritiesAtDispatchBoundary,
        leaseBoundaryObserved,
        attemptAuthoritiesAtLeaseBoundary
        >>

RejectClaimConflict(worker) ==
    /\ worker \in Workers
    /\ claimOwner # "NONE"
    /\ rejectedAttempts < MaxRejects
    /\ RecordRequestOutcome("IDENTITY_OR_ROUTE_REJECT")
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities,
        dispatchBoundaryObserved,
        claimSuccessesAtDispatchBoundary,
        attemptAuthoritiesAtDispatchBoundary,
        leaseBoundaryObserved,
        attemptAuthoritiesAtLeaseBoundary
        >>

AttemptSuccess(worker) ==
    /\ worker \in Workers
    /\ claimOwner = worker
    /\ attemptState = "NONE"
    /\ rawClock >= highWaterMark
    /\ rawClock < DispatchDeadline
    /\ rawClock < claimLeaseUntil
    /\ RecordAuthenticatedObservation
    /\ RecordRequestOutcome("ATTEMPT_SUCCESS")
    /\ attemptState' = "IN_FLIGHT"
    /\ attemptOwner' = worker
    /\ attemptAuthorities' = attemptAuthorities + 1
    /\ UNCHANGED <<
        rawClock,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        rejectedAttempts
        >>

RejectAttemptTemporal(worker) ==
    /\ worker \in Workers
    /\ claimOwner = worker
    /\ attemptState = "NONE"
    /\ rejectedAttempts < MaxRejects
    /\ rawClock >= highWaterMark
    /\ (rawClock >= DispatchDeadline \/ rawClock >= claimLeaseUntil)
    /\ RecordAuthenticatedObservation
    /\ RecordRequestOutcome("TEMPORAL_REJECT")
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        rawClock,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities
        >>

RejectAttemptRollback(worker) ==
    /\ worker \in Workers
    /\ claimOwner = worker
    /\ attemptState = "NONE"
    /\ rejectedAttempts < MaxRejects
    /\ rawClock < highWaterMark
    /\ RecordRequestOutcome("ROLLBACK_REJECT")
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities,
        dispatchBoundaryObserved,
        claimSuccessesAtDispatchBoundary,
        attemptAuthoritiesAtDispatchBoundary,
        leaseBoundaryObserved,
        attemptAuthoritiesAtLeaseBoundary
        >>

RejectAttemptIdentityOrRoute(worker) ==
    /\ worker \in Workers
    /\ (claimOwner # worker \/ attemptState # "NONE")
    /\ rejectedAttempts < MaxRejects
    /\ RecordRequestOutcome("IDENTITY_OR_ROUTE_REJECT")
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities,
        dispatchBoundaryObserved,
        claimSuccessesAtDispatchBoundary,
        attemptAuthoritiesAtDispatchBoundary,
        leaseBoundaryObserved,
        attemptAuthoritiesAtLeaseBoundary
        >>

RejectUnknownRequest ==
    /\ rejectedAttempts < MaxRejects
    /\ RecordRequestOutcome("IDENTITY_OR_ROUTE_REJECT")
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimOwner,
        claimLeaseUntil,
        claimSuccesses,
        attemptState,
        attemptOwner,
        attemptAuthorities,
        dispatchBoundaryObserved,
        claimSuccessesAtDispatchBoundary,
        attemptAuthoritiesAtDispatchBoundary,
        leaseBoundaryObserved,
        attemptAuthoritiesAtLeaseBoundary
        >>

Stutter == UNCHANGED vars

Next ==
    \/ \E t \in 0..MaxTime : SetRawClock(t)
    \/ \E worker \in Workers : ClaimSuccess(worker)
    \/ \E worker \in Workers : RejectClaimTemporal(worker)
    \/ \E worker \in Workers : RejectClaimRollback(worker)
    \/ \E worker \in Workers : RejectClaimConflict(worker)
    \/ \E worker \in Workers : AttemptSuccess(worker)
    \/ \E worker \in Workers : RejectAttemptTemporal(worker)
    \/ \E worker \in Workers : RejectAttemptRollback(worker)
    \/ \E worker \in Workers : RejectAttemptIdentityOrRoute(worker)
    \/ RejectUnknownRequest
    \/ Stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ rawClock \in 0..MaxTime
    /\ highWaterMark \in 0..MaxTime
    /\ highWaterHistory \subseteq 0..MaxTime
    /\ authenticatedSamples \subseteq 0..MaxTime
    /\ claimOwner \in Workers \cup {"NONE"}
    /\ claimLeaseUntil \in 0..DispatchDeadline
    /\ claimSuccesses \in 0..1
    /\ attemptState \in {"NONE", "IN_FLIGHT"}
    /\ attemptOwner \in Workers \cup {"NONE"}
    /\ attemptAuthorities \in 0..1
    /\ dispatchBoundaryObserved \in BOOLEAN
    /\ claimSuccessesAtDispatchBoundary \in 0..1
    /\ attemptAuthoritiesAtDispatchBoundary \in 0..1
    /\ leaseBoundaryObserved \in BOOLEAN
    /\ attemptAuthoritiesAtLeaseBoundary \in 0..1
    /\ rejectedAttempts \in 0..MaxRejects
    /\ lastRequestOutcome \in {
        "NONE",
        "CLAIM_SUCCESS",
        "ATTEMPT_SUCCESS",
        "TEMPORAL_REJECT",
        "ROLLBACK_REJECT",
        "IDENTITY_OR_ROUTE_REJECT"
        }
    /\ highWaterMarkBeforeLastRequest \in 0..MaxTime
    /\ clockSampleAtLastRequest \in 0..MaxTime
    /\ claimSuccessesBeforeLastRequest \in 0..1
    /\ attemptAuthoritiesBeforeLastRequest \in 0..1

AtMostOneClaimSuccess == claimSuccesses <= 1

AtMostOneAttemptAuthority == attemptAuthorities <= 1

NoAttemptBeforeClaim ==
    attemptState = "IN_FLIGHT" =>
        /\ claimSuccesses = 1
        /\ claimOwner = attemptOwner

HighWaterMarkMonotone ==
    \A seen \in highWaterHistory : seen <= highWaterMark

HighWaterMarkCoversAuthenticatedSamples ==
    \A sample \in authenticatedSamples : sample <= highWaterMark

TemporalRejectPersistsAuthenticatedSample ==
    lastRequestOutcome = "TEMPORAL_REJECT" =>
        /\ clockSampleAtLastRequest \in authenticatedSamples
        /\ clockSampleAtLastRequest <= highWaterMark

IdentityOrRouteRejectCannotPoisonHighWaterMark ==
    lastRequestOutcome = "IDENTITY_OR_ROUTE_REJECT" =>
        highWaterMark = highWaterMarkBeforeLastRequest

RollbackIsRejectedWithoutAuthority ==
    lastRequestOutcome = "ROLLBACK_REJECT" =>
        /\ clockSampleAtLastRequest < highWaterMarkBeforeLastRequest
        /\ highWaterMark = highWaterMarkBeforeLastRequest
        /\ claimSuccesses = claimSuccessesBeforeLastRequest
        /\ attemptAuthorities = attemptAuthoritiesBeforeLastRequest

RejectedRequestCreatesNoAuthority ==
    lastRequestOutcome \in {
        "TEMPORAL_REJECT",
        "ROLLBACK_REJECT",
        "IDENTITY_OR_ROUTE_REJECT"
        } =>
        /\ claimSuccesses = claimSuccessesBeforeLastRequest
        /\ attemptAuthorities = attemptAuthoritiesBeforeLastRequest

NoClaimResurrectionAfterDispatchBoundary ==
    dispatchBoundaryObserved =>
        claimSuccesses = claimSuccessesAtDispatchBoundary

NoAttemptResurrectionAfterDispatchBoundary ==
    dispatchBoundaryObserved =>
        attemptAuthorities = attemptAuthoritiesAtDispatchBoundary

NoAttemptResurrectionAfterLeaseBoundary ==
    leaseBoundaryObserved =>
        attemptAuthorities = attemptAuthoritiesAtLeaseBoundary

=============================================================================
