------------------------ MODULE PhysicalReservation ------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS MaxTime, MaxFailures, MaxRejects

Transactions == {"tx-a", "tx-b", "tx-c"}
Resources == {"resource-x", "resource-y"}
NoOwner == "NO_OWNER"

Target(tx) ==
    IF tx \in {"tx-a", "tx-b"}
    THEN "resource-x"
    ELSE "resource-y"

VARIABLES
    now,
    claimState,
    claimFence,
    leaseUntil,
    reservationOwner,
    firstOwner,
    nextFence,
    workerLive,
    workerFailures,
    rejectedClaims

vars == <<
    now,
    claimState,
    claimFence,
    leaseUntil,
    reservationOwner,
    firstOwner,
    nextFence,
    workerLive,
    workerFailures,
    rejectedClaims
>>

Init ==
    /\ now = 0
    /\ claimState = [tx \in Transactions |-> "NONE"]
    /\ claimFence = [tx \in Transactions |-> 0]
    /\ leaseUntil = [tx \in Transactions |-> 0]
    /\ reservationOwner = [resource \in Resources |-> NoOwner]
    /\ firstOwner = [resource \in Resources |-> NoOwner]
    /\ nextFence = 0
    /\ workerLive = [tx \in Transactions |-> FALSE]
    /\ workerFailures = 0
    /\ rejectedClaims = 0

Reserve(tx) ==
    /\ tx \in Transactions
    /\ claimState[tx] = "NONE"
    /\ reservationOwner[Target(tx)] = NoOwner
    /\ firstOwner[Target(tx)] = NoOwner
    /\ now < MaxTime
    /\ claimState' = [claimState EXCEPT ![tx] = "CLAIMED"]
    /\ claimFence' = [claimFence EXCEPT ![tx] = nextFence + 1]
    /\ leaseUntil' = [leaseUntil EXCEPT ![tx] = now + 1]
    /\ reservationOwner' =
        [reservationOwner EXCEPT ![Target(tx)] = tx]
    /\ firstOwner' = [firstOwner EXCEPT ![Target(tx)] = tx]
    /\ nextFence' = nextFence + 1
    /\ workerLive' = [workerLive EXCEPT ![tx] = TRUE]
    /\ UNCHANGED <<now, workerFailures, rejectedClaims>>

StartAttempt(tx) ==
    /\ tx \in Transactions
    /\ claimState[tx] = "CLAIMED"
    /\ workerLive[tx]
    /\ now < leaseUntil[tx]
    /\ claimState' = [claimState EXCEPT ![tx] = "ATTEMPT_IN_FLIGHT"]
    /\ UNCHANGED <<
        now,
        claimFence,
        leaseUntil,
        reservationOwner,
        firstOwner,
        nextFence,
        workerLive,
        workerFailures,
        rejectedClaims
        >>

LoseWorker(tx) ==
    /\ tx \in Transactions
    /\ claimState[tx] # "NONE"
    /\ workerLive[tx]
    /\ workerFailures < MaxFailures
    /\ workerLive' = [workerLive EXCEPT ![tx] = FALSE]
    /\ workerFailures' = workerFailures + 1
    /\ UNCHANGED <<
        now,
        claimState,
        claimFence,
        leaseUntil,
        reservationOwner,
        firstOwner,
        nextFence,
        rejectedClaims
        >>

RejectUnavailableClaim(tx) ==
    /\ tx \in Transactions
    /\ rejectedClaims < MaxRejects
    /\ \/ claimState[tx] # "NONE"
       \/ reservationOwner[Target(tx)] # NoOwner
    /\ rejectedClaims' = rejectedClaims + 1
    /\ UNCHANGED <<
        now,
        claimState,
        claimFence,
        leaseUntil,
        reservationOwner,
        firstOwner,
        nextFence,
        workerLive,
        workerFailures
        >>

AdvanceClock ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<
        claimState,
        claimFence,
        leaseUntil,
        reservationOwner,
        firstOwner,
        nextFence,
        workerLive,
        workerFailures,
        rejectedClaims
        >>

Stutter == UNCHANGED vars

Next ==
    \/ \E tx \in Transactions : Reserve(tx)
    \/ \E tx \in Transactions : StartAttempt(tx)
    \/ \E tx \in Transactions : LoseWorker(tx)
    \/ \E tx \in Transactions : RejectUnavailableClaim(tx)
    \/ AdvanceClock
    \/ Stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 0..MaxTime
    /\ claimState \in [Transactions -> {"NONE", "CLAIMED", "ATTEMPT_IN_FLIGHT"}]
    /\ claimFence \in [Transactions -> 0..Cardinality(Transactions)]
    /\ leaseUntil \in [Transactions -> 0..MaxTime]
    /\ reservationOwner \in [Resources -> Transactions \cup {NoOwner}]
    /\ firstOwner \in [Resources -> Transactions \cup {NoOwner}]
    /\ nextFence \in 0..Cardinality(Transactions)
    /\ workerLive \in [Transactions -> BOOLEAN]
    /\ workerFailures \in 0..MaxFailures
    /\ rejectedClaims \in 0..MaxRejects

ClaimHasExactReservation ==
    \A tx \in Transactions :
        claimState[tx] # "NONE" => reservationOwner[Target(tx)] = tx

ReservationHasClaim ==
    \A resource \in Resources :
        reservationOwner[resource] # NoOwner =>
            /\ claimState[reservationOwner[resource]] # "NONE"
            /\ Target(reservationOwner[resource]) = resource

PhysicalReservationExclusive ==
    \A tx1, tx2 \in Transactions :
        /\ tx1 # tx2
        /\ Target(tx1) = Target(tx2)
        => \/ claimState[tx1] = "NONE"
           \/ claimState[tx2] = "NONE"

FenceIsPositiveAndExclusive ==
    /\ \A tx \in Transactions :
        claimState[tx] # "NONE" => claimFence[tx] > 0
    /\ \A tx1, tx2 \in Transactions :
        /\ tx1 # tx2
        /\ claimState[tx1] # "NONE"
        /\ claimState[tx2] # "NONE"
        => claimFence[tx1] # claimFence[tx2]

NoReleaseOrTakeover ==
    \A resource \in Resources :
        firstOwner[resource] = NoOwner
        \/ reservationOwner[resource] = firstOwner[resource]

WorkerLossRetainsReservation ==
    \A tx \in Transactions :
        /\ claimState[tx] # "NONE"
        /\ ~workerLive[tx]
        => reservationOwner[Target(tx)] = tx

ExpiryRetainsReservation ==
    \A tx \in Transactions :
        /\ claimState[tx] # "NONE"
        /\ now >= leaseUntil[tx]
        => reservationOwner[Target(tx)] = tx

=============================================================================
