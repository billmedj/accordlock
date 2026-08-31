# Pre-G1 wire-v2 migration — historical snapshot

> This record predates the AccordLock public-release cleanup. Product and
> identifier names were normalized later; use the current schemas and
> conformance vectors as the authoritative pre-1.0 protocol description.

**Date:** 2026-08-16  
**Status:** mandatory local reset procedure; not a public compatibility promise

## Why this break exists

The first local evidence format kept the request identifier only in the outer
`TrustedEvidenceSet`. Each evidence assertion was signed, but its signed bytes
did not contain that request identifier. An intact assertion could therefore
be relabelled into another outer request container unless the connector-to-
kernel channel independently preserved the association.

The corrected pre-G1 profile makes the association cryptographic:

- `EvidenceAssertion` schema 2 contains `request_id` and has a 10-element
  canonical CBOR representation;
- Review, Build, Artifact and Target evidence use purpose-separated
  `accordlock:v2:evidence:*` COSE domains;
- the evidence-set root uses `accordlock:v2:evidence-root`;
- connector checkpoints are version 2;
- the kernel requires
  `assertion.request_id == evidence_set.request_id == proposal.request_id`;
- `EvaluationAttestation` also uses schema/domain 2, and authorization issuance refuses
  every legacy-v1 evaluation.

`ExecutionAuthorization` was already schema/domain 2 and is not renumbered by this change.
That does not make an old authorization harmless: an authorization produced before the reset
can remain executable until its signed expiry if its bound authority is still
active.

## Compatibility decision

There is deliberately no dual-stack parser and no silent migration. This is a
pre-G1 development workspace with no supported customer data. Accepting both
profiles would preserve the ambiguity that the correction removes.

The required policy is:

1. stop every issuer, connector, evaluator, dispatcher, executor and webhook;
2. preserve an audit copy if any local run has evidentiary value;
3. make every pre-v2 authorization non-current by advancing/rotating the relevant
   authority configuration, or replace the disposable local database with a
   freshly migrated empty database;
4. remove all legacy evidence assertions, evidence sets, connector
   checkpoints, signed evaluations, unconsumed authorizations, receipts, outbox work,
   dispatch claims and admission authorizations from the active development
   lineage;
5. regenerate conformance fixtures and synthetic sessions under the v2
   domains; and
6. run the complete locked reproduction gate before starting any service.

This document does not authorize deleting a database that contains material
the author wishes to preserve. Database selection, backup and destructive reset
remain explicit operator actions.

## Restart gates

Do not resume the candidate unless all of the following are true:

- no active service accepts a schema-1 evidence assertion or evaluation;
- no current connector checkpoint predates profile 2;
- the active authority cannot validate a still-live pre-reset authorization;
- the exact migration ledger and constraints pass `validate_schema`;
- substitution of a valid assertion between two request identifiers is denied;
- legacy v1 evidence and evaluation COSE domains are rejected; and
- workspace tests, conformance corpus, dependency checks and TLA models pass
  from the same frozen source snapshot.

## What this establishes

After the reset, the signed evidence object preserves its request association,
and the kernel and issuer enforce the corrected profile. This is not evidence
of a production migration system, external interoperability, a real connector,
key rotation, customer-data recovery, or independent review.
