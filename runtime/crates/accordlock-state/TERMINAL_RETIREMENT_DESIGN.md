# Durable terminal retirement protocol (v12)

Status: **implemented by migration `0012_terminal_retirement` and the sealed
`TerminalRetirementState` API**.

This handoff records the security contract of the v12 implementation. It is
not an enablement claim for a `NO_EFFECT` path: v12 deliberately accepts only
an authenticated exact effect together with authenticated retirement of the
exact attempt credential.

## Trust and data flow

The terminal witness registry is not a new trust root. An
`ActivatedWitnessRegistry` may be persisted only when its complete canonical
commitment is already frozen in the exact historical v11 EKS destination
activation selected by `(scope, resource_activation_id,
mediation_activation_id)`. Registry authority and every verifier entry are
stored as immutable material; a commitment alone is insufficient.

The store reconstructs `TerminalAttemptBinding`, `CredentialIdentity`, the
payload TokenReview request commitment, the payload Secret deletion
observation, and `RetirementExpectation` exclusively from durable v8-v12
state. The terminalization caller supplies only:

- the existing `ConsumeKey`;
- a globally unique terminalization ID; and
- the exact canonical signed effect and retirement envelope bytes.

The caller cannot supply an expected route, token digest, admission linkage,
deletion time, policy bound, or verifier key.

The payload TokenReview request commitment is bearer-free and
domain-separated. It commits to the durable attempt route and exact credential
identity, including the token digest, audience, credential ID, and service
account UID. The Secret-deletion observation is likewise domain-separated and
commits to the exact journal entry ID, journal request/result commitments,
provider-evidence commitment, attempt, credential, and trusted final absence
time.

## Final DELETE observation

Migration 0012 adds an append-only
`accordlock_broker_secret_deletion_observations` row. It is written atomically with
the transition of the exact `DELETE_SECRET` journal entry to
`COMMITTED/DELETE_ABSENT` and with the trusted-time high-water update.

`observed_unix_s` is the normative final GET-absence sample. The v9
`last_reconciled_unix_s`, when present, records the preceding pending
GET-present reconciliation; it is only a floor. The final observation must be
at or after both `started_unix_s` and that floor. Existing v9
`DELETE_ABSENT` rows are intentionally not backfilled. Without the v12
observation row, terminal context derivation fails closed.

## Evidence and time rules

The two envelopes are purpose-separated and independently signed:

1. `EXACT_EFFECT` proves the exact durable attempt and complete provider
   effect. There is no `NO_EFFECT` variant.
2. `CREDENTIAL_RETIREMENT` proves deletion of the exact bound Secret and
   either an exact payload TokenReview rejection or satisfaction of the
   conservative bound derived from the immutable credential policy.

Envelope canonicality, registry role, key, issuer, authority version,
signature, scope, cluster, complete attempt tuple, admission linkage, and
retirement expectation are checked before trusted time is sampled. Those
failures are high-water-mark inert.

After the tuple and both signatures authenticate, successful finalization and
temporal rejection advance or retain the scope high-water mark. A signed
observation later than the store clock persists the sampled clock before
returning `TerminalEvidenceFuture`; a later lower sample is rejected as
rollback. Exact recovery and audit re-verify both historical signatures
against the exact persisted registry and use the original `finalized_at` as
the trusted verification time.

## Atomic transition and recovery

In one serializable transaction the store:

1. reloads the authorization, receipt, outbox, claim, credential, admission,
   destination activation, broker journal, final deletion observation,
   registry binding, and complete registry material;
2. checks the claim is the exact active `ATTEMPT_IN_FLIGHT` owner;
3. verifies both signed envelopes against state-derived expectations;
4. inserts one append-only terminal record;
5. changes the exact claim to `TERMINAL` and attaches the terminalization ID;
6. advances the trusted-time high-water mark; and
7. commits.

The active physical-resource exclusion is a partial unique index covering
only `CLAIMED` and `ATTEMPT_IN_FLIGHT`. Therefore the old reservation is not
released before the terminal row and claim transition commit. The terminal
claim, globally unique fence, audit history, signed envelopes, and deletion
observation remain retained. A later claim for the same physical resource can
be acquired only after commit and receives a new fence.

Terminalization IDs, claim IDs, and fences are globally unique in terminal
history. Evidence IDs and envelope commitments are globally unique within
their cryptographic witness role (`EXACT_EFFECT` or
`CREDENTIAL_RETIREMENT`); the two purpose-separated namespaces may reuse the
same raw UUID or digest without ambiguity. Reuse within the same role on
another claim is rejected. An exact retry succeeds only when
the terminal pointer, complete stored tuple, record commitment, both exact
envelope byte strings, derived context, evidence identifiers, and both
historical signatures all agree. Database/commit ambiguity is retried through
that exact recovery path; otherwise the API returns
`TerminalRetirementOutcomeUnknown`.

Registry registration uses the same pattern. Concurrent processes may race to
insert the same material or binding, but a retry returns recovered success only
after reloading and comparing the complete material and exact v11-rooted
binding. Conflicting material or a conflicting activation binding is rejected.

## Historical-registry limitation

The v12 registry is historical and append-only. Verification uses the signed
`observed_at` inside each verifier entry's immutable validity window and
cutoff. A rotation or revocation performed after activation does not
retroactively replace that historical material.

V12 does **not** define a separate emergency kill switch, nor a transparency
timestamp that prevents a subsequently compromised signing key from
backdating evidence inside its accepted window. Safety therefore depends on:

- strict separation between the exact-effect and credential-retirement roles;
- strong independent key custody;
- short verifier validity windows and acceptance cutoffs; and
- the v11 root-mediated commitment to the complete registry material.

Changing those historical verification behavior requires a separate protocol
version. Cleanup code must not silently consult a mutable current registry or
retroactively rewrite terminal history.

## Fail-closed exclusions

None of the following can terminalize a claim:

- an HTTP success response;
- a DELETE acknowledgement;
- a Secret GET/404 without the exact atomic v12 journal observation;
- admission `ALLOW` by itself;
- lease or dispatch-deadline expiry;
- process death or retry count;
- a caller-provided timestamp, expiry, token digest, hash, or verifier key;
- ambiguous/no-effect evidence; or
- a legacy committed DELETE row that lacks the append-only v12 observation.

The memory and PostgreSQL implementations follow the same state machine. The
companion `models/TerminalRetirement.tla` model covers rooted registry
material, authenticated evidence pairing, HWM ordering, atomic release,
reclaim, exact recovery, restart, tamper, and schema fail-closed invariants.
