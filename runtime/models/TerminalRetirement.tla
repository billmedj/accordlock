-------------------------- MODULE TerminalRetirement --------------------------
EXTENDS Naturals, FiniteSets

(***************************************************************************
This is a bounded safety model of the v12 terminal-retirement boundary.  Hash
commitments, canonical encodings, signatures, SQL transactions, and trusted
clock reads are represented by collision-free symbolic values and atomic
actions.  The model deliberately has no NO_EFFECT success path.
***************************************************************************)

CONSTANTS MaxTime, MaxRejects, MaxRecoveries, MaxRestarts

TxA == "tx-a"
TxB == "tx-b"
TxLegacy == "tx-legacy"
Transactions == {TxA, TxB, TxLegacy}

ResourceX == "resource-x"
ResourceY == "resource-y"
Resources == {ResourceX, ResourceY}
NoOwner == "NO_OWNER"

ActivationX == "activation-x"
ActivationY == "activation-y"
Activations == {ActivationX, ActivationY}

NoMaterial == "NO_MATERIAL"
MaterialX == "material-v11-x"
MaterialY == "material-v11-y"
WrongCommitmentMaterial == "wrong-full-commitment"
WrongSchemaMaterial == "wrong-schema-material"
UnrootedMaterial == "unrooted-material"
Materials == {
    MaterialX,
    MaterialY,
    WrongCommitmentMaterial,
    WrongSchemaMaterial,
    UnrootedMaterial
}

NoRegistryCommitment == "NO_REGISTRY_COMMITMENT"
RegistryCommitmentX == "registry-commitment-x"
RegistryCommitmentY == "registry-commitment-y"
OtherRegistryCommitment == "other-registry-commitment"

NoObservation == "NO_DELETION_OBSERVATION"
ObservationA == "delete-observation-a"
ObservationB == "delete-observation-b"
ObservationLegacy == "delete-observation-legacy"
DeletionObservations == {ObservationA, ObservationB, ObservationLegacy}

NoTerminalId == "NO_TERMINAL_ID"
TerminalIds == {"terminal-1", "terminal-2"}
NoTerminalEvidence == "NO_TERMINAL_EVIDENCE"
ExactPurposeSeparatedPair == "EXACT_EFFECT_AND_RETIREMENT"

NoTx == "NO_TX"
NoRequestId == "NO_REQUEST_ID"
ExactRequest == "EXACT_REQUEST"
NoRequestVariant == "NO_REQUEST_VARIANT"

BadRouting == "BAD_ROUTING"
RegistryMismatch == "REGISTRY_MISMATCH"
NoncanonicalEnvelope == "NONCANONICAL_ENVELOPE"
BadSignature == "BAD_SIGNATURE"
DurableContextMismatch == "DURABLE_CONTEXT_MISMATCH"
WrongEffectPurpose == "WRONG_EFFECT_PURPOSE"
WrongRetirementPurpose == "WRONG_RETIREMENT_PURPOSE"
NoEffect == "NO_EFFECT"
DeleteAckOnly == "DELETE_ACK_ONLY"
GetOnly == "GET_ONLY"
MissingDeleteObservation == "MISSING_DELETE_OBSERVATION"
SchemaDriftRequest == "SCHEMA_DRIFT"
TamperedRequest == "TAMPERED_DURABLE_STATE"
RecoveryIdMismatch == "RECOVERY_ID_MISMATCH"
RecoveryEnvelopeMismatch == "RECOVERY_ENVELOPE_MISMATCH"
RecoveryKeyMismatch == "RECOVERY_KEY_MISMATCH"

UnauthenticatedVariants == {
    BadRouting,
    RegistryMismatch,
    NoncanonicalEnvelope,
    BadSignature,
    DurableContextMismatch,
    WrongEffectPurpose,
    WrongRetirementPurpose,
    NoEffect,
    DeleteAckOnly,
    GetOnly,
    MissingDeleteObservation,
    SchemaDriftRequest,
    TamperedRequest
}
RecoveryMismatchVariants == {
    RecoveryIdMismatch,
    RecoveryEnvelopeMismatch,
    RecoveryKeyMismatch
}
RequestVariants ==
    UnauthenticatedVariants \cup RecoveryMismatchVariants
        \cup {NoRequestVariant, ExactRequest}

NoOutcome == "NONE"
TerminalSuccess == "TERMINAL_SUCCESS"
CommitAmbiguous == "COMMIT_AMBIGUOUS"
RecoveredExact == "RECOVERED_EXACT"
AuthenticatedFutureReject == "AUTHENTICATED_FUTURE_REJECT"
AuthenticatedRollbackReject == "AUTHENTICATED_ROLLBACK_REJECT"
UnauthenticatedReject == "UNAUTHENTICATED_REJECT"
RecoveryMismatchReject == "RECOVERY_MISMATCH_REJECT"
RestartOutcome == "RESTART"
RequestOutcomes == {
    NoOutcome,
    TerminalSuccess,
    CommitAmbiguous,
    RecoveredExact,
    AuthenticatedFutureReject,
    AuthenticatedRollbackReject,
    UnauthenticatedReject,
    RecoveryMismatchReject,
    RestartOutcome
}

ExactIntegrity == "EXACT"
TamperedIntegrity == "TAMPERED"
SchemaDriftIntegrity == "SCHEMA_DRIFT"
IntegrityStates == {ExactIntegrity, TamperedIntegrity, SchemaDriftIntegrity}

Target(tx) == IF tx \in {TxA, TxB} THEN ResourceX ELSE ResourceY

ActivationFor(tx) ==
    IF tx \in {TxA, TxB} THEN ActivationX ELSE ActivationY

ExpectedRegistryCommitment(activation) ==
    IF activation = ActivationX
    THEN RegistryCommitmentX
    ELSE RegistryCommitmentY

ExpectedMaterial(activation) ==
    IF activation = ActivationX THEN MaterialX ELSE MaterialY

MaterialCommitment(material) ==
    CASE material = MaterialX -> RegistryCommitmentX
      [] material = MaterialY -> RegistryCommitmentY
      [] OTHER -> OtherRegistryCommitment

MaterialSchema(material) == IF material = WrongSchemaMaterial THEN 2 ELSE 1

MaterialIsV11Rooted(material) == material # UnrootedMaterial

RegistryMaterialEligible(activation, material) ==
    /\ material = ExpectedMaterial(activation)
    /\ MaterialCommitment(material) = ExpectedRegistryCommitment(activation)
    /\ MaterialSchema(material) = 1
    /\ MaterialIsV11Rooted(material)

IsV12Delete(tx) == tx \in {TxA, TxB}

ExactDeletionObservation(tx) ==
    CASE tx = TxA -> ObservationA
      [] tx = TxB -> ObservationB
      [] OTHER -> ObservationLegacy

EffectObservedAt(tx) == IF tx = TxB THEN 2 ELSE 2

WitnessObservedAt(tx, deletionObservedAt) ==
    IF EffectObservedAt(tx) >= deletionObservedAt[tx]
    THEN EffectObservedAt(tx)
    ELSE deletionObservedAt[tx]

ActiveClaim(state) == state \in {"CLAIMED", "ATTEMPT_IN_FLIGHT"}

VARIABLES
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    claimState,
    claimFence,
    terminalFence,
    activeReservation,
    reservationHistory,
    registryMaterial,
    registryWrites,
    registryRecoveries,
    deletionObservation,
    deletionFirstObservation,
    deletionObservedAt,
    deletionWrites,
    durableIntegrity,
    corruptionCount,
    terminalHistory,
    terminalId,
    terminalEvidence,
    terminalWrites,
    terminalIdOwner,
    lostCommitPending,
    recoveryResponses,
    reclaims,
    restarts,
    requestRejects,
    terminalMutationEpoch,
    lastOutcome,
    lastRequestTx,
    lastRequestId,
    lastRequestVariant,
    highWaterBeforeLastRequest,
    mutationEpochBeforeLastRequest

vars == <<
    rawClock,
    highWaterMark,
    highWaterHistory,
    authenticatedSamples,
    claimState,
    claimFence,
    terminalFence,
    activeReservation,
    reservationHistory,
    registryMaterial,
    registryWrites,
    registryRecoveries,
    deletionObservation,
    deletionFirstObservation,
    deletionObservedAt,
    deletionWrites,
    durableIntegrity,
    corruptionCount,
    terminalHistory,
    terminalId,
    terminalEvidence,
    terminalWrites,
    terminalIdOwner,
    lostCommitPending,
    recoveryResponses,
    reclaims,
    restarts,
    requestRejects,
    terminalMutationEpoch,
    lastOutcome,
    lastRequestTx,
    lastRequestId,
    lastRequestVariant,
    highWaterBeforeLastRequest,
    mutationEpochBeforeLastRequest
>>

Init ==
    /\ rawClock = 0
    /\ highWaterMark = 0
    /\ highWaterHistory = {0}
    /\ authenticatedSamples = {}
    /\ claimState = [
        tx \in Transactions |->
            IF tx \in {TxA, TxLegacy} THEN "ATTEMPT_IN_FLIGHT" ELSE "NONE"
        ]
    /\ claimFence = [
        tx \in Transactions |->
            CASE tx = TxA -> 1 [] tx = TxLegacy -> 2 [] OTHER -> 0
        ]
    /\ terminalFence = [tx \in Transactions |-> 0]
    /\ activeReservation = [
        resource \in Resources |->
            IF resource = ResourceX THEN TxA ELSE TxLegacy
        ]
    /\ reservationHistory = {<<TxA, ResourceX>>, <<TxLegacy, ResourceY>>}
    /\ registryMaterial = [activation \in Activations |-> NoMaterial]
    /\ registryWrites = [activation \in Activations |-> 0]
    /\ registryRecoveries = [activation \in Activations |-> 0]
    /\ deletionObservation = [tx \in Transactions |-> NoObservation]
    /\ deletionFirstObservation = [tx \in Transactions |-> NoObservation]
    /\ deletionObservedAt = [tx \in Transactions |-> 0]
    /\ deletionWrites = [tx \in Transactions |-> 0]
    /\ durableIntegrity = [tx \in Transactions |-> ExactIntegrity]
    /\ corruptionCount = 0
    /\ terminalHistory = {}
    /\ terminalId = [tx \in Transactions |-> NoTerminalId]
    /\ terminalEvidence = [tx \in Transactions |-> NoTerminalEvidence]
    /\ terminalWrites = [tx \in Transactions |-> 0]
    /\ terminalIdOwner = [id \in TerminalIds |-> NoOwner]
    /\ lostCommitPending = [tx \in Transactions |-> FALSE]
    /\ recoveryResponses = 0
    /\ reclaims = 0
    /\ restarts = 0
    /\ requestRejects = 0
    /\ terminalMutationEpoch = 0
    /\ lastOutcome = NoOutcome
    /\ lastRequestTx = NoTx
    /\ lastRequestId = NoRequestId
    /\ lastRequestVariant = NoRequestVariant
    /\ highWaterBeforeLastRequest = 0
    /\ mutationEpochBeforeLastRequest = 0

ClearLastRequest ==
    /\ lastOutcome' = NoOutcome
    /\ lastRequestTx' = NoTx
    /\ lastRequestId' = NoRequestId
    /\ lastRequestVariant' = NoRequestVariant
    /\ highWaterBeforeLastRequest' = highWaterMark
    /\ mutationEpochBeforeLastRequest' = terminalMutationEpoch

RecordRequest(outcome, tx, requestId, variant) ==
    /\ lastOutcome' = outcome
    /\ lastRequestTx' = tx
    /\ lastRequestId' = requestId
    /\ lastRequestVariant' = variant
    /\ highWaterBeforeLastRequest' = highWaterMark
    /\ mutationEpochBeforeLastRequest' = terminalMutationEpoch

SetRawClock(sample) ==
    /\ sample \in 0..MaxTime
    /\ sample # rawClock
    /\ rawClock' = sample
    /\ ClearLastRequest
    /\ UNCHANGED <<
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

RegisterExactRegistry(activation, material) ==
    /\ activation \in Activations
    /\ material \in Materials
    /\ registryMaterial[activation] = NoMaterial
    /\ RegistryMaterialEligible(activation, material)
    /\ registryMaterial' = [registryMaterial EXCEPT ![activation] = material]
    /\ registryWrites' = [registryWrites EXCEPT ![activation] = 1]
    /\ ClearLastRequest
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

RecoverExactRegistry(activation) ==
    /\ activation \in Activations
    /\ registryMaterial[activation] = ExpectedMaterial(activation)
    /\ registryRecoveries[activation] < MaxRecoveries
    /\ registryRecoveries' =
        [registryRecoveries EXCEPT ![activation] = @ + 1]
    /\ ClearLastRequest
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

RejectRegistryMaterial(activation, material) ==
    /\ activation \in Activations
    /\ material \in Materials
    /\ \/ ~RegistryMaterialEligible(activation, material)
       \/ /\ registryMaterial[activation] # NoMaterial
          /\ registryMaterial[activation] # material
    /\ ClearLastRequest
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

CommitFinalDeleteObservation(tx) ==
    /\ tx \in Transactions
    /\ claimState[tx] = "ATTEMPT_IN_FLIGHT"
    /\ IsV12Delete(tx)
    /\ deletionObservation[tx] = NoObservation
    /\ rawClock > 0
    /\ rawClock >= highWaterMark
    /\ deletionObservation' =
        [deletionObservation EXCEPT ![tx] = ExactDeletionObservation(tx)]
    /\ deletionFirstObservation' =
        [deletionFirstObservation EXCEPT ![tx] = ExactDeletionObservation(tx)]
    /\ deletionObservedAt' = [deletionObservedAt EXCEPT ![tx] = rawClock]
    /\ deletionWrites' = [deletionWrites EXCEPT ![tx] = 1]
    /\ highWaterMark' = rawClock
    /\ highWaterHistory' = highWaterHistory \cup {rawClock}
    /\ authenticatedSamples' = authenticatedSamples \cup {rawClock}
    /\ ClearLastRequest
    /\ UNCHANGED <<
        rawClock,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

InjectDurableCorruption(tx, corruption) ==
    /\ tx \in Transactions
    /\ corruption \in {TamperedIntegrity, SchemaDriftIntegrity}
    /\ tx \notin terminalHistory
    /\ durableIntegrity[tx] = ExactIntegrity
    /\ corruptionCount = 0
    /\ durableIntegrity' = [durableIntegrity EXCEPT ![tx] = corruption]
    /\ corruptionCount' = 1
    /\ ClearLastRequest
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

DurableContextReady(tx) ==
    /\ tx \in Transactions
    /\ claimState[tx] = "ATTEMPT_IN_FLIGHT"
    /\ activeReservation[Target(tx)] = tx
    /\ claimFence[tx] > 0
    /\ durableIntegrity[tx] = ExactIntegrity
    /\ registryMaterial[ActivationFor(tx)] = ExpectedMaterial(ActivationFor(tx))
    /\ MaterialCommitment(registryMaterial[ActivationFor(tx)])
        = ExpectedRegistryCommitment(ActivationFor(tx))
    /\ deletionObservation[tx] = ExactDeletionObservation(tx)
    /\ deletionWrites[tx] = 1
    /\ IsV12Delete(tx)

AuthenticatedEvidenceReady(tx) ==
    /\ DurableContextReady(tx)
    /\ terminalEvidence[tx] = NoTerminalEvidence

FinalizeReturned(tx, requestId) ==
    /\ tx \in Transactions
    /\ requestId \in TerminalIds
    /\ terminalIdOwner[requestId] = NoOwner
    /\ AuthenticatedEvidenceReady(tx)
    /\ rawClock >= highWaterMark
    /\ WitnessObservedAt(tx, deletionObservedAt) <= rawClock
    /\ claimState' = [claimState EXCEPT ![tx] = "TERMINAL"]
    /\ terminalFence' = [terminalFence EXCEPT ![tx] = claimFence[tx]]
    /\ activeReservation' = [activeReservation EXCEPT ![Target(tx)] = NoOwner]
    /\ terminalHistory' = terminalHistory \cup {tx}
    /\ terminalId' = [terminalId EXCEPT ![tx] = requestId]
    /\ terminalEvidence' =
        [terminalEvidence EXCEPT ![tx] = ExactPurposeSeparatedPair]
    /\ terminalWrites' = [terminalWrites EXCEPT ![tx] = 1]
    /\ terminalIdOwner' = [terminalIdOwner EXCEPT ![requestId] = tx]
    /\ lostCommitPending' = [lostCommitPending EXCEPT ![tx] = FALSE]
    /\ highWaterMark' = rawClock
    /\ highWaterHistory' = highWaterHistory \cup {rawClock}
    /\ authenticatedSamples' = authenticatedSamples \cup {rawClock}
    /\ terminalMutationEpoch' = terminalMutationEpoch + 1
    /\ RecordRequest(TerminalSuccess, tx, requestId, ExactRequest)
    /\ UNCHANGED <<
        rawClock,
        claimFence,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects
        >>

FinalizeLostResponse(tx, requestId) ==
    /\ tx \in Transactions
    /\ requestId \in TerminalIds
    /\ terminalIdOwner[requestId] = NoOwner
    /\ AuthenticatedEvidenceReady(tx)
    /\ rawClock >= highWaterMark
    /\ WitnessObservedAt(tx, deletionObservedAt) <= rawClock
    /\ claimState' = [claimState EXCEPT ![tx] = "TERMINAL"]
    /\ terminalFence' = [terminalFence EXCEPT ![tx] = claimFence[tx]]
    /\ activeReservation' = [activeReservation EXCEPT ![Target(tx)] = NoOwner]
    /\ terminalHistory' = terminalHistory \cup {tx}
    /\ terminalId' = [terminalId EXCEPT ![tx] = requestId]
    /\ terminalEvidence' =
        [terminalEvidence EXCEPT ![tx] = ExactPurposeSeparatedPair]
    /\ terminalWrites' = [terminalWrites EXCEPT ![tx] = 1]
    /\ terminalIdOwner' = [terminalIdOwner EXCEPT ![requestId] = tx]
    /\ lostCommitPending' = [lostCommitPending EXCEPT ![tx] = TRUE]
    /\ highWaterMark' = rawClock
    /\ highWaterHistory' = highWaterHistory \cup {rawClock}
    /\ authenticatedSamples' = authenticatedSamples \cup {rawClock}
    /\ terminalMutationEpoch' = terminalMutationEpoch + 1
    /\ RecordRequest(CommitAmbiguous, tx, requestId, ExactRequest)
    /\ UNCHANGED <<
        rawClock,
        claimFence,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects
        >>

RejectAuthenticatedFuture(tx, requestId) ==
    /\ tx \in Transactions
    /\ requestId \in TerminalIds
    /\ AuthenticatedEvidenceReady(tx)
    /\ rawClock >= highWaterMark
    /\ WitnessObservedAt(tx, deletionObservedAt) > rawClock
    /\ requestRejects < MaxRejects
    /\ highWaterMark' = rawClock
    /\ highWaterHistory' = highWaterHistory \cup {rawClock}
    /\ authenticatedSamples' = authenticatedSamples \cup {rawClock}
    /\ requestRejects' = requestRejects + 1
    /\ RecordRequest(AuthenticatedFutureReject, tx, requestId, ExactRequest)
    /\ UNCHANGED <<
        rawClock,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        terminalMutationEpoch
        >>

RejectAuthenticatedRollback(tx, requestId) ==
    /\ tx \in Transactions
    /\ requestId \in TerminalIds
    /\ AuthenticatedEvidenceReady(tx)
    /\ rawClock < highWaterMark
    /\ requestRejects < MaxRejects
    /\ requestRejects' = requestRejects + 1
    /\ RecordRequest(AuthenticatedRollbackReject, tx, requestId, ExactRequest)
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        terminalMutationEpoch
        >>

ReasonApplicable(tx, variant) ==
    CASE variant = RegistryMismatch ->
            registryMaterial[ActivationFor(tx)] # ExpectedMaterial(ActivationFor(tx))
      [] variant \in {DeleteAckOnly, GetOnly, MissingDeleteObservation} ->
            deletionObservation[tx] = NoObservation
      [] variant = SchemaDriftRequest ->
            durableIntegrity[tx] = SchemaDriftIntegrity
      [] variant = TamperedRequest ->
            durableIntegrity[tx] = TamperedIntegrity
      [] OTHER -> TRUE

RejectUnauthenticated(tx, requestId, variant) ==
    /\ tx \in Transactions
    /\ requestId \in TerminalIds
    /\ variant \in UnauthenticatedVariants
    /\ ReasonApplicable(tx, variant)
    /\ requestRejects < MaxRejects
    /\ requestRejects' = requestRejects + 1
    /\ RecordRequest(UnauthenticatedReject, tx, requestId, variant)
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        terminalMutationEpoch
        >>

RecoverExactTerminal(tx) ==
    /\ tx \in Transactions
    /\ tx \in terminalHistory
    /\ lostCommitPending[tx]
    /\ recoveryResponses < MaxRecoveries
    /\ recoveryResponses' = recoveryResponses + 1
    /\ lostCommitPending' = [lostCommitPending EXCEPT ![tx] = FALSE]
    /\ RecordRequest(RecoveredExact, tx, terminalId[tx], ExactRequest)
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

RejectMismatchedRecovery(tx, requestId, variant) ==
    /\ tx \in Transactions
    /\ tx \in terminalHistory
    /\ requestId \in TerminalIds
    /\ variant \in RecoveryMismatchVariants
    /\ \/ requestId # terminalId[tx]
       \/ variant \in {RecoveryEnvelopeMismatch, RecoveryKeyMismatch}
    /\ requestRejects < MaxRejects
    /\ requestRejects' = requestRejects + 1
    /\ RecordRequest(RecoveryMismatchReject, tx, requestId, variant)
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        terminalMutationEpoch
        >>

ReclaimReleasedResource ==
    /\ claimState[TxB] = "NONE"
    /\ TxA \in terminalHistory
    /\ activeReservation[ResourceX] = NoOwner
    /\ reclaims = 0
    /\ claimState' = [claimState EXCEPT ![TxB] = "CLAIMED"]
    /\ claimFence' = [claimFence EXCEPT ![TxB] = 3]
    /\ activeReservation' = [activeReservation EXCEPT ![ResourceX] = TxB]
    /\ reservationHistory' = reservationHistory \cup {<<TxB, ResourceX>>}
    /\ reclaims' = 1
    /\ terminalMutationEpoch' = terminalMutationEpoch + 1
    /\ ClearLastRequest
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        terminalFence,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        restarts,
        requestRejects
        >>

StartReclaimedAttempt ==
    /\ claimState[TxB] = "CLAIMED"
    /\ activeReservation[ResourceX] = TxB
    /\ claimState' = [claimState EXCEPT ![TxB] = "ATTEMPT_IN_FLIGHT"]
    /\ ClearLastRequest
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        restarts,
        requestRejects,
        terminalMutationEpoch
        >>

Restart ==
    /\ restarts < MaxRestarts
    /\ restarts' = restarts + 1
    /\ lastOutcome' = RestartOutcome
    /\ lastRequestTx' = NoTx
    /\ lastRequestId' = NoRequestId
    /\ lastRequestVariant' = NoRequestVariant
    /\ highWaterBeforeLastRequest' = highWaterMark
    /\ mutationEpochBeforeLastRequest' = terminalMutationEpoch
    /\ UNCHANGED <<
        rawClock,
        highWaterMark,
        highWaterHistory,
        authenticatedSamples,
        claimState,
        claimFence,
        terminalFence,
        activeReservation,
        reservationHistory,
        registryMaterial,
        registryWrites,
        registryRecoveries,
        deletionObservation,
        deletionFirstObservation,
        deletionObservedAt,
        deletionWrites,
        durableIntegrity,
        corruptionCount,
        terminalHistory,
        terminalId,
        terminalEvidence,
        terminalWrites,
        terminalIdOwner,
        lostCommitPending,
        recoveryResponses,
        reclaims,
        requestRejects,
        terminalMutationEpoch
        >>

Stutter == UNCHANGED vars

Next ==
    \/ \E sample \in 0..MaxTime : SetRawClock(sample)
    \/ \E material \in Materials :
        RegisterExactRegistry(ActivationX, material)
    \/ RecoverExactRegistry(ActivationX)
    \/ \E material \in Materials :
        RejectRegistryMaterial(ActivationX, material)
    \/ \E tx \in Transactions : CommitFinalDeleteObservation(tx)
    \/ \E tx \in Transactions,
          corruption \in {TamperedIntegrity, SchemaDriftIntegrity} :
        InjectDurableCorruption(tx, corruption)
    \/ \E tx \in Transactions, requestId \in TerminalIds :
        FinalizeReturned(tx, requestId)
    \/ \E tx \in Transactions, requestId \in TerminalIds :
        FinalizeLostResponse(tx, requestId)
    \/ \E tx \in Transactions, requestId \in TerminalIds :
        RejectAuthenticatedFuture(tx, requestId)
    \/ \E tx \in Transactions, requestId \in TerminalIds :
        RejectAuthenticatedRollback(tx, requestId)
    \/ \E tx \in Transactions,
          requestId \in TerminalIds,
          variant \in UnauthenticatedVariants :
        RejectUnauthenticated(tx, requestId, variant)
    \/ \E tx \in Transactions : RecoverExactTerminal(tx)
    \/ \E tx \in Transactions,
          requestId \in TerminalIds,
          variant \in RecoveryMismatchVariants :
        RejectMismatchedRecovery(tx, requestId, variant)
    \/ ReclaimReleasedResource
    \/ StartReclaimedAttempt
    \/ Restart
    \/ Stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ rawClock \in 0..MaxTime
    /\ highWaterMark \in 0..MaxTime
    /\ highWaterHistory \subseteq 0..MaxTime
    /\ authenticatedSamples \subseteq 0..MaxTime
    /\ claimState \in [Transactions -> {"NONE", "CLAIMED", "ATTEMPT_IN_FLIGHT", "TERMINAL"}]
    /\ claimFence \in [Transactions -> 0..Cardinality(Transactions)]
    /\ terminalFence \in [Transactions -> 0..Cardinality(Transactions)]
    /\ activeReservation \in [Resources -> Transactions \cup {NoOwner}]
    /\ reservationHistory \subseteq (Transactions \X Resources)
    /\ registryMaterial \in [Activations -> Materials \cup {NoMaterial}]
    /\ registryWrites \in [Activations -> 0..1]
    /\ registryRecoveries \in [Activations -> 0..MaxRecoveries]
    /\ deletionObservation \in
        [Transactions -> DeletionObservations \cup {NoObservation}]
    /\ deletionFirstObservation \in
        [Transactions -> DeletionObservations \cup {NoObservation}]
    /\ deletionObservedAt \in [Transactions -> 0..MaxTime]
    /\ deletionWrites \in [Transactions -> 0..1]
    /\ durableIntegrity \in [Transactions -> IntegrityStates]
    /\ corruptionCount \in 0..1
    /\ terminalHistory \subseteq Transactions
    /\ terminalId \in [Transactions -> TerminalIds \cup {NoTerminalId}]
    /\ terminalEvidence \in
        [Transactions -> {NoTerminalEvidence, ExactPurposeSeparatedPair}]
    /\ terminalWrites \in [Transactions -> 0..1]
    /\ terminalIdOwner \in [TerminalIds -> Transactions \cup {NoOwner}]
    /\ lostCommitPending \in [Transactions -> BOOLEAN]
    /\ recoveryResponses \in 0..MaxRecoveries
    /\ reclaims \in 0..1
    /\ restarts \in 0..MaxRestarts
    /\ requestRejects \in 0..MaxRejects
    /\ terminalMutationEpoch \in 0..Cardinality(Transactions)
    /\ lastOutcome \in RequestOutcomes
    /\ lastRequestTx \in Transactions \cup {NoTx}
    /\ lastRequestId \in TerminalIds \cup {NoRequestId}
    /\ lastRequestVariant \in RequestVariants
    /\ highWaterBeforeLastRequest \in 0..MaxTime
    /\ mutationEpochBeforeLastRequest \in 0..Cardinality(Transactions)

RegistryMaterialIsExactlyV11Committed ==
    \A activation \in Activations :
        registryMaterial[activation] # NoMaterial =>
            /\ registryMaterial[activation] = ExpectedMaterial(activation)
            /\ MaterialCommitment(registryMaterial[activation])
                = ExpectedRegistryCommitment(activation)
            /\ MaterialSchema(registryMaterial[activation]) = 1
            /\ MaterialIsV11Rooted(registryMaterial[activation])
            /\ registryWrites[activation] = 1

RegistryIsAppendOnly ==
    \A activation \in Activations :
        registryWrites[activation] = 0
            <=> registryMaterial[activation] = NoMaterial

DeletionObservationIsAppendOnlyAndExact ==
    \A tx \in Transactions :
        /\ deletionWrites[tx] = 0
            <=> deletionObservation[tx] = NoObservation
        /\ deletionWrites[tx] = 1 =>
            /\ deletionObservation[tx] = ExactDeletionObservation(tx)
            /\ deletionFirstObservation[tx] = deletionObservation[tx]
            /\ deletionObservedAt[tx] > 0

NoLegacyDeletionBackfill ==
    /\ deletionObservation[TxLegacy] = NoObservation
    /\ deletionFirstObservation[TxLegacy] = NoObservation
    /\ deletionWrites[TxLegacy] = 0

ActiveReservationMatchesActiveClaim ==
    /\ \A tx \in Transactions :
        ActiveClaim(claimState[tx]) => activeReservation[Target(tx)] = tx
    /\ \A resource \in Resources :
        activeReservation[resource] # NoOwner =>
            /\ ActiveClaim(claimState[activeReservation[resource]])
            /\ Target(activeReservation[resource]) = resource

NoConcurrentPhysicalOverlap ==
    \A tx1, tx2 \in Transactions :
        /\ tx1 # tx2
        /\ Target(tx1) = Target(tx2)
        => \/ ~ActiveClaim(claimState[tx1])
           \/ ~ActiveClaim(claimState[tx2])

TerminalTransitionAtomicallyReleases ==
    \A tx \in Transactions :
        tx \in terminalHistory <=>
            /\ claimState[tx] = "TERMINAL"
            /\ activeReservation[Target(tx)] # tx
            /\ terminalWrites[tx] = 1

TerminalHistoryAndFenceAreRetained ==
    \A tx \in terminalHistory :
        /\ <<tx, Target(tx)>> \in reservationHistory
        /\ terminalFence[tx] = claimFence[tx]
        /\ terminalFence[tx] > 0
        /\ terminalId[tx] \in TerminalIds
        /\ terminalIdOwner[terminalId[tx]] = tx

PriorOwnersAreTerminalBeforeReclaim ==
    \A resource \in Resources, prior \in Transactions :
        /\ <<prior, resource>> \in reservationHistory
        /\ activeReservation[resource] # NoOwner
        /\ activeReservation[resource] # prior
        => prior \in terminalHistory

TerminalRequiresDurableExactLineage ==
    \A tx \in terminalHistory :
        /\ durableIntegrity[tx] = ExactIntegrity
        /\ IsV12Delete(tx)
        /\ deletionObservation[tx] = ExactDeletionObservation(tx)
        /\ deletionWrites[tx] = 1
        /\ registryMaterial[ActivationFor(tx)] = ExpectedMaterial(ActivationFor(tx))
        /\ MaterialCommitment(registryMaterial[ActivationFor(tx)])
            = ExpectedRegistryCommitment(ActivationFor(tx))

TerminalRequiresPurposeSeparatedSignatures ==
    \A tx \in Transactions :
        tx \in terminalHistory
            <=> terminalEvidence[tx] = ExactPurposeSeparatedPair

TamperAndSchemaDriftFailClosed ==
    \A tx \in Transactions :
        durableIntegrity[tx] # ExactIntegrity => tx \notin terminalHistory

TerminalIdsAreUnique ==
    \A id \in TerminalIds :
        terminalIdOwner[id] # NoOwner =>
            /\ terminalId[terminalIdOwner[id]] = id
            /\ terminalIdOwner[id] \in terminalHistory

TerminalWriteIsOnceOnly ==
    \A tx \in Transactions :
        terminalWrites[tx] = 1 <=> tx \in terminalHistory

LostCommitAlreadyContainsAtomicResult ==
    \A tx \in Transactions :
        lostCommitPending[tx] =>
            /\ tx \in terminalHistory
            /\ claimState[tx] = "TERMINAL"
            /\ activeReservation[Target(tx)] # tx
            /\ terminalWrites[tx] = 1

ExactRecoveryOnly ==
    lastOutcome = RecoveredExact =>
        /\ lastRequestTx \in terminalHistory
        /\ lastRequestVariant = ExactRequest
        /\ lastRequestId = terminalId[lastRequestTx]
        /\ terminalWrites[lastRequestTx] = 1
        /\ terminalMutationEpoch = mutationEpochBeforeLastRequest

HighWaterMarkMonotone ==
    \A seen \in highWaterHistory : seen <= highWaterMark

HighWaterMarkCoversAuthenticatedSamples ==
    \A sample \in authenticatedSamples : sample <= highWaterMark

AuthenticatedTemporalResultPersistsClock ==
    lastOutcome \in {
        TerminalSuccess,
        CommitAmbiguous,
        AuthenticatedFutureReject
        } =>
        /\ highWaterMark >= highWaterBeforeLastRequest
        /\ rawClock \in authenticatedSamples
        /\ rawClock <= highWaterMark

AuthenticatedRollbackIsReadOnly ==
    lastOutcome = AuthenticatedRollbackReject =>
        /\ rawClock < highWaterBeforeLastRequest
        /\ highWaterMark = highWaterBeforeLastRequest
        /\ terminalMutationEpoch = mutationEpochBeforeLastRequest

UnauthenticatedAndMismatchRejectsAreHwmInert ==
    lastOutcome \in {UnauthenticatedReject, RecoveryMismatchReject} =>
        /\ highWaterMark = highWaterBeforeLastRequest
        /\ terminalMutationEpoch = mutationEpochBeforeLastRequest

NoEffectOrPartialDeletionCanRetire ==
    lastOutcome = UnauthenticatedReject
        /\ lastRequestVariant \in {NoEffect, DeleteAckOnly, GetOnly, MissingDeleteObservation}
        => terminalMutationEpoch = mutationEpochBeforeLastRequest

RestartRetainsDurableSafetyState ==
    lastOutcome = RestartOutcome =>
        /\ highWaterMark = highWaterBeforeLastRequest
        /\ terminalMutationEpoch = mutationEpochBeforeLastRequest

=============================================================================
