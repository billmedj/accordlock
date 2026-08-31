-------------------------- MODULE AuthorizationLifecycle --------------------------
EXTENDS Naturals

CONSTANTS MaxEpoch, MaxTime, MaxRejects

VARIABLES
    authorityEpoch,
    now,
    authorizationState,
    authorizationEpoch,
    issuedAt,
    consumeBefore,
    consumeCount,
    receiptPresent,
    outboxPresent,
    consumedEpoch,
    rejectedAttempts

vars == <<
    authorityEpoch,
    now,
    authorizationState,
    authorizationEpoch,
    issuedAt,
    consumeBefore,
    consumeCount,
    receiptPresent,
    outboxPresent,
    consumedEpoch,
    rejectedAttempts
>>

Init ==
    /\ authorityEpoch = 0
    /\ now = 0
    /\ authorizationState = "NONE"
    /\ authorizationEpoch = MaxEpoch + 1
    /\ issuedAt = MaxTime + 1
    /\ consumeBefore = MaxTime + 1
    /\ consumeCount = 0
    /\ receiptPresent = FALSE
    /\ outboxPresent = FALSE
    /\ consumedEpoch = MaxEpoch + 1
    /\ rejectedAttempts = 0

Issue ==
    /\ authorizationState = "NONE"
    /\ now < MaxTime
    /\ authorizationState' = "ISSUED"
    /\ authorizationEpoch' = authorityEpoch
    /\ issuedAt' = now
    /\ consumeBefore' = IF now + 2 <= MaxTime THEN now + 2 ELSE MaxTime
    /\ UNCHANGED <<
        authorityEpoch,
        now,
        consumeCount,
        receiptPresent,
        outboxPresent,
        consumedEpoch,
        rejectedAttempts
        >>

RotateAuthority ==
    /\ authorityEpoch < MaxEpoch
    /\ authorityEpoch' = authorityEpoch + 1
    /\ UNCHANGED <<
        now,
        authorizationState,
        authorizationEpoch,
        issuedAt,
        consumeBefore,
        consumeCount,
        receiptPresent,
        outboxPresent,
        consumedEpoch,
        rejectedAttempts
        >>

AdvanceClock ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<
        authorityEpoch,
        authorizationState,
        authorizationEpoch,
        issuedAt,
        consumeBefore,
        consumeCount,
        receiptPresent,
        outboxPresent,
        consumedEpoch,
        rejectedAttempts
        >>

Consume ==
    /\ authorizationState = "ISSUED"
    /\ authorityEpoch = authorizationEpoch
    /\ now < consumeBefore
    /\ authorizationState' = "CONSUMED"
    /\ consumeCount' = consumeCount + 1
    /\ receiptPresent' = TRUE
    /\ outboxPresent' = TRUE
    /\ consumedEpoch' = authorityEpoch
    /\ UNCHANGED <<
        authorityEpoch,
        now,
        authorizationEpoch,
        issuedAt,
        consumeBefore,
        rejectedAttempts
        >>

RejectInvalidConsumption ==
    /\ authorizationState = "ISSUED"
    /\ \/ authorityEpoch # authorizationEpoch
       \/ now >= consumeBefore
    /\ rejectedAttempts < MaxRejects
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        authorityEpoch,
        now,
        authorizationState,
        authorizationEpoch,
        issuedAt,
        consumeBefore,
        consumeCount,
        receiptPresent,
        outboxPresent,
        consumedEpoch
        >>

RejectReplay ==
    /\ authorizationState = "CONSUMED"
    /\ rejectedAttempts < MaxRejects
    /\ rejectedAttempts' = rejectedAttempts + 1
    /\ UNCHANGED <<
        authorityEpoch,
        now,
        authorizationState,
        authorizationEpoch,
        issuedAt,
        consumeBefore,
        consumeCount,
        receiptPresent,
        outboxPresent,
        consumedEpoch
        >>

Stutter == UNCHANGED vars

Next ==
    \/ Issue
    \/ RotateAuthority
    \/ AdvanceClock
    \/ Consume
    \/ RejectInvalidConsumption
    \/ RejectReplay
    \/ Stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ authorityEpoch \in 0..MaxEpoch
    /\ now \in 0..MaxTime
    /\ authorizationState \in {"NONE", "ISSUED", "CONSUMED"}
    /\ authorizationEpoch \in 0..(MaxEpoch + 1)
    /\ issuedAt \in 0..(MaxTime + 1)
    /\ consumeBefore \in 0..(MaxTime + 1)
    /\ consumeCount \in 0..1
    /\ receiptPresent \in BOOLEAN
    /\ outboxPresent \in BOOLEAN
    /\ consumedEpoch \in 0..(MaxEpoch + 1)
    /\ rejectedAttempts \in 0..MaxRejects

AtMostOnce == consumeCount <= 1

IssuanceWindowWasNonempty ==
    authorizationState # "NONE" => issuedAt < consumeBefore

ReceiptAndOutboxAreAtomic ==
    /\ receiptPresent = outboxPresent
    /\ receiptPresent = (authorizationState = "CONSUMED")

ConsumptionUsedStampedEpoch ==
    authorizationState = "CONSUMED" => consumedEpoch = authorizationEpoch

NoEffectBeforeConsumption ==
    authorizationState # "CONSUMED" =>
        /\ consumeCount = 0
        /\ ~receiptPresent
        /\ ~outboxPresent

=============================================================================
