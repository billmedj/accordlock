# AccordLock durable control workers

This crate is the narrow composition layer for the v13 durable control queue.
It binds each worker instance to exactly one role at construction and composes
only the production capabilities returned by `ControlPlaneState`:

- `EvaluatorWorker` consumes `ControlEvaluationWork`, constructs a
  `KernelContext`, signs exactly one evaluation, and records it before the
  queue can advance;
- `IssuerWorker` consumes `ControlIssuanceWork` through
  `AuthorizationIssuer::issue_or_recover`, then drops the returned signed authorization and
  consume key because their exact tuple is already durable; and
- `ConsumerWorker` consumes `ControlConsumptionWork` through the atomic state
  boundary that also writes the receipt, outbox, control link, and `DONE`
  transition.

There is no HTTP endpoint, caller-selected role, caller-selected claim ID,
grant selector, capability reconstruction, or unbounded polling loop. A
supervisor first calls `begin_attempt`, retains the returned opaque identity,
then passes it to one bounded `run_once` call. Reusing that same attempt after a
worker-task failure recovers the exact claim. If the claim or phase commit is
ambiguous, the returned opaque, non-serializable recovery token may be passed
only to the same worker's `recover_once`; the worker checks its exact role and
identity before asking state to recover that claim. No public getter exposes
the underlying claim ID.

This is not autonomous process restart. `ClaimAttempt` and `ClaimRecovery` are
intentionally neither clonable nor serializable, so a complete supervisor
process crash loses an unjournaled claim identity and cannot recover it
immediately. State may allow a newly fenced takeover only after the lease and
only where its phase rules authorization one; an external or otherwise unknown effect
must never be treated as absent. A durable local claim journal or a separately
proved deterministic claim-ID derivation is required before claiming immediate
cross-process recovery.

`ControlStep` keeps inert history, terminal finalization, claim ambiguity, and
post-capability commit ambiguity separate. It never promotes any of them to a
successful phase advance. Ordinary errors also fail closed: the lease is not
reconstructed or released and can only be recovered or expire under the state
adapter's fencing rules.

The crate intentionally does not decide how evidence is collected, where keys
are isolated, how worker identities map to database credentials, or how a
supervisor schedules bounded calls. Those are deployment composition duties.
In particular, the current state API treats a role as a trusted selector, not
an authenticated database identity; production deployment still needs
separate least-privilege principals for evaluator, issuer, and consumer loops.

Readiness: **READY TO INTEGRATE; PRODUCTION HOLD**. The Rust capability path and
memory crash/recovery contract are executable, but production readiness remains
blocked until PostgreSQL authenticates the evaluator, issuer, and consumer as
distinct session/database roles and authorization tests prove that each role
cannot call another phase's mutations. Key isolation and a bounded supervisor
also remain deployment premises rather than claims of this crate.
