# `accordlock-cli`

This crate is a local demonstration and conformance CLI. It is not a
production authorization service.

## Live Kubernetes state modes

`accordlock live prepare` has two explicit state modes:

- `--state-backend in-memory` is the default deterministic demonstration path.
  Its receipt and pending outbox entry disappear with the process.
- `--state-backend postgres` writes the authority, grant, issued authorization,
  single-use consumption, receipt, and pending outbox entry to PostgreSQL. The
  successful consumption call receives only the tenant/environment scope,
  transaction identifier, and authorization `authorization_id`. The state adapter reloads active
  authority, trusted database time, grant state, and deadline inputs. The live
  path uses `consume_or_recover`, so a lost PostgreSQL commit response is
  accepted only by reloading and cross-validating the exact receipt, outbox,
  issued authorization, and original identifier tuple.

The PostgreSQL connection string is read from a named environment variable. It
is not accepted as a command-line value or copied into session JSON. The
default variable is `ACCORDLOCK_LIVE_POSTGRES_URL`:

```powershell
$env:ACCORDLOCK_LIVE_POSTGRES_URL = 'postgresql://postgres@127.0.0.1:55432/accordlock_test_v2'
.\target\debug\accordlock.exe live prepare `
  --deployment .\.local\live-k8s\before.json `
  --new-image docker.io/library/nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236 `
  --state-backend postgres `
  --migrate-postgres `
  --session-out .\.local\live-k8s\session.json
```

`--migrate-postgres` is opt-in. Without it, the required schema must already
exist. A different variable name can be selected with `--postgres-url-env`.
Do not point the local harness or its integration tests at a production or
shared database.

Each preparation run derives a fresh local environment name from its random
request identifier. This isolates the single-grant test profile and makes the
same disposable database reusable across reproducibility runs. It is test
namespacing, not tenant provisioning or an authenticated control-plane API.

The session records `state_backend`, `durable_consumption`, a durable
`state_instance_id`, separate composite references for the consumption receipt
and execution outbox, and the outbox status. `POSTGRESQL` means that those local
records committed in the identified logical state lineage. It does not mean
that an external effect was dispatched or observed.

`accordlock live validate` refuses to validate a `POSTGRESQL` session as a purely
self-contained JSON claim. It reloads the exact receipt and pending outbox
entry from the configured database and reports `state_records_reverified=true`.
It also requires the configured database's durable state-lineage identifier to
equal the identifier exported in session schema version 4.
When a non-default variable name was used for preparation, pass the same
`--postgres-url-env NAME` to validation. An `IN_MEMORY` report necessarily sets
`state_records_reverified=false`.

Every local evaluation context is constructed with a canonical, bounded,
sorted attester registry whose computed root must equal the active registry
authority root. The local authority's kernel-configuration root commits the
exact evaluator key identifier and public key; issuance refuses any other
evaluation verifier. Authorization verification uses the strict contextual profile
with the recorded time, expected executor audience, and supplied authority
vector. Session revalidation repeats that historical check at the durable
consumption receipt's recorded time and authority. It does not provide a fresh
current-authority or revocation oracle at a later dispatch time; production
dispatch still requires that separate current-state recheck.

The synthetic and live harnesses also auto-create an activated ingress registry
from public hard-coded seeds, replace the local principal-registry root with its
computed root, sign their own ingress envelope, and use fixed fixture nonces.
Each invocation creates a fresh process-local replay guard. This is deterministic
test bootstrap, not a production registry, nonce service, key lifecycle, or
authenticated ingress integration. The seeds and fixed nonces must never be
reused as a deployment profile.

`accordlock live validate-effect` requires an eventual Deployment plus exhaustive
ReplicaSet and Pod list snapshots for the Deployment selector. It validates the
exact Deployment-to-ReplicaSet-to-Pod ownership chain. Its report schema is
version 2 and exports `rollout_ownership_valid`. Separate Kubernetes list reads
are not an atomic snapshot; an inconsistent controller transition fails closed.

## Security boundary

Both modes still use synthetic attestations and public deterministic test
keys. The PostgreSQL path adds durable single-use consumption and a pending
outbox record. Consumption, receipt, and outbox creation are one transaction,
but the preceding local authority, grant, and issued-authorization registration calls
are not one atomic transaction with evidence evaluation. The path does not
implement authenticated production ingress, key custody, a fenced dispatcher,
durable request-intent or session-file recovery across a process crash,
provider effect receipts, EKS evidence adapters, or independent validation. An
`ConsumptionOutcomeUnknown` response requires retrying the unchanged
identifier tuple; it is not evidence that dispatch occurred. This CLI never
dispatches the prepared effect. The separate local `kind` PowerShell runner
currently calls `kubectl` directly and is not wired through the durable
dispatch claim or `AuthorizedProviderAttempt`. It is therefore not a
complete-mediation exhibit.

The optional integration test uses a disposable database:

```powershell
$env:ACCORDLOCK_TEST_POSTGRES_URL = 'postgresql://.../disposable_test_database'
cargo test -p accordlock-cli live_k8s::tests::postgres_live_session_persists_receipt_and_outbox -- --ignored --exact
```

The binary-level environment/configuration path is covered separately:

```powershell
cargo test -p accordlock-cli --test live_postgres_cli cli_postgres_prepare_and_validate_reverify_durable_state -- --ignored --exact
```
