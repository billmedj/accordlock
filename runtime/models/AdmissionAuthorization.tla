---------------------- MODULE AdmissionAuthorization ----------------------
EXTENDS Naturals, FiniteSets

CONSTANTS MaxTime, DispatchDeadline, MaxAttempts

Uids == {"uid-a", "uid-b"}
Transactions == {"tx-a", "tx-b"}
Claims == {"claim-a", "claim-b"}
Fences == {1, 2}
Resources == {"resource-x", "resource-y"}
ProviderCommitments == {"provider-a", "provider-b"}
ObjectCommitments == {"object-a", "object-b"}
IdentityCommitments == {"identity-a", "identity-b"}

NoUid == "NO_UID"

ActiveTransaction == "tx-a"
ActiveClaim == "claim-a"
ActiveFence == 1
ActiveResource == "resource-x"
ExpectedProviderCommitment == "provider-a"

Request(uid, tx, claim, fence, resource, provider, oldObject, newObject,
        executor, observer) ==
    [uid |-> uid,
     tx |-> tx,
     claim |-> claim,
     fence |-> fence,
     resource |-> resource,
     provider |-> provider,
     oldObject |-> oldObject,
     newObject |-> newObject,
     executor |-> executor,
     observer |-> observer]

NoRequest == Request(
    "NO_UID", "NO_TX", "NO_CLAIM", 0, "NO_RESOURCE", "NO_PROVIDER",
    "NO_OBJECT", "NO_OBJECT", "NO_IDENTITY", "NO_IDENTITY")

GoodA == Request(
    "uid-a", "tx-a", "claim-a", 1, "resource-x", "provider-a",
    "object-a", "object-a", "identity-a", "identity-a")

GoodB == Request(
    "uid-b", "tx-a", "claim-a", 1, "resource-x", "provider-a",
    "object-a", "object-a", "identity-a", "identity-a")

Requests == {
    GoodA,
    GoodB,
    Request("uid-a", "tx-b", "claim-a", 1, "resource-x", "provider-a",
        "object-a", "object-a", "identity-a", "identity-a"),
    Request("uid-a", "tx-a", "claim-b", 1, "resource-x", "provider-a",
        "object-a", "object-a", "identity-a", "identity-a"),
    Request("uid-a", "tx-a", "claim-a", 2, "resource-x", "provider-a",
        "object-a", "object-a", "identity-a", "identity-a"),
    Request("uid-a", "tx-a", "claim-a", 1, "resource-y", "provider-a",
        "object-a", "object-a", "identity-a", "identity-a"),
    Request("uid-a", "tx-a", "claim-a", 1, "resource-x", "provider-b",
        "object-a", "object-a", "identity-a", "identity-a"),
    Request("uid-a", "tx-a", "claim-a", 1, "resource-x", "provider-a",
        "object-b", "object-a", "identity-a", "identity-a"),
    Request("uid-a", "tx-a", "claim-a", 1, "resource-x", "provider-a",
        "object-a", "object-b", "identity-a", "identity-a"),
    Request("uid-a", "tx-a", "claim-a", 1, "resource-x", "provider-a",
        "object-a", "object-a", "identity-b", "identity-a"),
    Request("uid-a", "tx-a", "claim-a", 1, "resource-x", "provider-a",
        "object-a", "object-a", "identity-a", "identity-b")
}

VARIABLES
    now,
    authorityCurrent,
    grantCurrent,
    authorizationByUid,
    transactionOwner,
    claimOwner,
    fenceOwner,
    providerOwner,
    writeCount,
    attempts,
    recoveryCount,
    rejectedCount,
    allRecoveriesWereCurrent,
    allRecoveriesWereExact,
    allRecoveriesUsedCommittedRows,
    allRejectionsPreservedRows

vars == <<
    now,
    authorityCurrent,
    grantCurrent,
    authorizationByUid,
    transactionOwner,
    claimOwner,
    fenceOwner,
    providerOwner,
    writeCount,
    attempts,
    recoveryCount,
    rejectedCount,
    allRecoveriesWereCurrent,
    allRecoveriesWereExact,
    allRecoveriesUsedCommittedRows,
    allRejectionsPreservedRows
>>

Init ==
    /\ now = 0
    /\ authorityCurrent = TRUE
    /\ grantCurrent = TRUE
    /\ authorizationByUid = [uid \in Uids |-> NoRequest]
    /\ transactionOwner = [tx \in Transactions |-> NoUid]
    /\ claimOwner = [claim \in Claims |-> NoUid]
    /\ fenceOwner = [fence \in Fences |-> NoUid]
    /\ providerOwner = [provider \in ProviderCommitments |-> NoUid]
    /\ writeCount = [uid \in Uids |-> 0]
    /\ attempts = 0
    /\ recoveryCount = 0
    /\ rejectedCount = 0
    /\ allRecoveriesWereCurrent = TRUE
    /\ allRecoveriesWereExact = TRUE
    /\ allRecoveriesUsedCommittedRows = TRUE
    /\ allRejectionsPreservedRows = TRUE

IsCurrent(request) ==
    /\ authorityCurrent
    /\ grantCurrent
    /\ now < DispatchDeadline
    /\ request.tx = ActiveTransaction
    /\ request.claim = ActiveClaim
    /\ request.fence = ActiveFence
    /\ request.resource = ActiveResource
    /\ request.provider = ExpectedProviderCommitment

IndexesUnused(request) ==
    /\ transactionOwner[request.tx] = NoUid
    /\ claimOwner[request.claim] = NoUid
    /\ fenceOwner[request.fence] = NoUid
    /\ providerOwner[request.provider] = NoUid

CanAuthorize(request) ==
    /\ attempts < MaxAttempts
    /\ IsCurrent(request)
    /\ authorizationByUid[request.uid] = NoRequest
    /\ IndexesUnused(request)

CanRecover(request) ==
    /\ attempts < MaxAttempts
    /\ IsCurrent(request)
    /\ authorizationByUid[request.uid] = request
    /\ writeCount[request.uid] = 1

Authorize(request) ==
    /\ request \in Requests
    /\ CanAuthorize(request)
    /\ authorizationByUid' =
        [authorizationByUid EXCEPT ![request.uid] = request]
    /\ transactionOwner' =
        [transactionOwner EXCEPT ![request.tx] = request.uid]
    /\ claimOwner' = [claimOwner EXCEPT ![request.claim] = request.uid]
    /\ fenceOwner' = [fenceOwner EXCEPT ![request.fence] = request.uid]
    /\ providerOwner' =
        [providerOwner EXCEPT ![request.provider] = request.uid]
    /\ writeCount' = [writeCount EXCEPT ![request.uid] = 1]
    /\ attempts' = attempts + 1
    /\ UNCHANGED <<
        now,
        authorityCurrent,
        grantCurrent,
        recoveryCount,
        rejectedCount,
        allRecoveriesWereCurrent,
        allRecoveriesWereExact,
        allRecoveriesUsedCommittedRows,
        allRejectionsPreservedRows
        >>

Recover(request) ==
    /\ request \in Requests
    /\ CanRecover(request)
    /\ attempts' = attempts + 1
    /\ recoveryCount' = recoveryCount + 1
    /\ allRecoveriesWereCurrent' =
        allRecoveriesWereCurrent /\ IsCurrent(request)
    /\ allRecoveriesWereExact' =
        allRecoveriesWereExact
        /\ authorizationByUid[request.uid] = request
    /\ allRecoveriesUsedCommittedRows' =
        allRecoveriesUsedCommittedRows /\ writeCount[request.uid] = 1
    /\ UNCHANGED <<
        now,
        authorityCurrent,
        grantCurrent,
        authorizationByUid,
        transactionOwner,
        claimOwner,
        fenceOwner,
        providerOwner,
        writeCount,
        rejectedCount,
        allRejectionsPreservedRows
        >>

Reject(request) ==
    /\ request \in Requests
    /\ attempts < MaxAttempts
    /\ ~CanAuthorize(request)
    /\ ~CanRecover(request)
    /\ attempts' = attempts + 1
    /\ rejectedCount' = rejectedCount + 1
    /\ allRejectionsPreservedRows' = allRejectionsPreservedRows
    /\ UNCHANGED <<
        now,
        authorityCurrent,
        grantCurrent,
        authorizationByUid,
        transactionOwner,
        claimOwner,
        fenceOwner,
        providerOwner,
        writeCount,
        recoveryCount,
        allRecoveriesWereCurrent,
        allRecoveriesWereExact,
        allRecoveriesUsedCommittedRows
        >>

AdvanceClock ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<
        authorityCurrent,
        grantCurrent,
        authorizationByUid,
        transactionOwner,
        claimOwner,
        fenceOwner,
        providerOwner,
        writeCount,
        attempts,
        recoveryCount,
        rejectedCount,
        allRecoveriesWereCurrent,
        allRecoveriesWereExact,
        allRecoveriesUsedCommittedRows,
        allRejectionsPreservedRows
        >>

RotateAuthority ==
    /\ authorityCurrent
    /\ authorityCurrent' = FALSE
    /\ UNCHANGED <<
        now,
        grantCurrent,
        authorizationByUid,
        transactionOwner,
        claimOwner,
        fenceOwner,
        providerOwner,
        writeCount,
        attempts,
        recoveryCount,
        rejectedCount,
        allRecoveriesWereCurrent,
        allRecoveriesWereExact,
        allRecoveriesUsedCommittedRows,
        allRejectionsPreservedRows
        >>

RevokeGrant ==
    /\ grantCurrent
    /\ grantCurrent' = FALSE
    /\ UNCHANGED <<
        now,
        authorityCurrent,
        authorizationByUid,
        transactionOwner,
        claimOwner,
        fenceOwner,
        providerOwner,
        writeCount,
        attempts,
        recoveryCount,
        rejectedCount,
        allRecoveriesWereCurrent,
        allRecoveriesWereExact,
        allRecoveriesUsedCommittedRows,
        allRejectionsPreservedRows
        >>

Stutter == UNCHANGED vars

Next ==
    \/ \E request \in Requests : Authorize(request)
    \/ \E request \in Requests : Recover(request)
    \/ \E request \in Requests : Reject(request)
    \/ AdvanceClock
    \/ RotateAuthority
    \/ RevokeGrant
    \/ Stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 0..MaxTime
    /\ authorityCurrent \in BOOLEAN
    /\ grantCurrent \in BOOLEAN
    /\ authorizationByUid \in [Uids -> Requests \cup {NoRequest}]
    /\ transactionOwner \in [Transactions -> Uids \cup {NoUid}]
    /\ claimOwner \in [Claims -> Uids \cup {NoUid}]
    /\ fenceOwner \in [Fences -> Uids \cup {NoUid}]
    /\ providerOwner \in [ProviderCommitments -> Uids \cup {NoUid}]
    /\ writeCount \in [Uids -> 0..1]
    /\ attempts \in 0..MaxAttempts
    /\ recoveryCount \in 0..MaxAttempts
    /\ rejectedCount \in 0..MaxAttempts
    /\ allRecoveriesWereCurrent \in BOOLEAN
    /\ allRecoveriesWereExact \in BOOLEAN
    /\ allRecoveriesUsedCommittedRows \in BOOLEAN
    /\ allRejectionsPreservedRows \in BOOLEAN

OneDurableWritePerUid ==
    \A uid \in Uids : writeCount[uid] \in 0..1

WriteAndAuthorizationAgree ==
    \A uid \in Uids :
        (writeCount[uid] = 1) = (authorizationByUid[uid] # NoRequest)

AuthorizationBoundToClaimFenceAndProvider ==
    \A uid \in Uids :
        authorizationByUid[uid] # NoRequest =>
            /\ authorizationByUid[uid].tx = ActiveTransaction
            /\ authorizationByUid[uid].claim = ActiveClaim
            /\ authorizationByUid[uid].fence = ActiveFence
            /\ authorizationByUid[uid].resource = ActiveResource
            /\ authorizationByUid[uid].provider = ExpectedProviderCommitment

IndexesMatchAuthorization ==
    \A uid \in Uids :
        authorizationByUid[uid] # NoRequest =>
            LET request == authorizationByUid[uid] IN
                /\ transactionOwner[request.tx] = uid
                /\ claimOwner[request.claim] = uid
                /\ fenceOwner[request.fence] = uid
                /\ providerOwner[request.provider] = uid

NoAliasAcrossDurableAuthorizations ==
    \A uid1, uid2 \in Uids :
        /\ uid1 # uid2
        /\ authorizationByUid[uid1] # NoRequest
        /\ authorizationByUid[uid2] # NoRequest
        => LET request1 == authorizationByUid[uid1]
               request2 == authorizationByUid[uid2]
           IN /\ request1.tx # request2.tx
              /\ request1.claim # request2.claim
              /\ request1.fence # request2.fence
              /\ request1.provider # request2.provider

RecoveryIsCurrentOnly == allRecoveriesWereCurrent

RecoveryRequiresExactCommittedTuple == allRecoveriesWereExact

RecoveryRequiresDurableAuthorization == allRecoveriesUsedCommittedRows

RejectedAttemptsCreateNoRows == allRejectionsPreservedRows

=============================================================================
