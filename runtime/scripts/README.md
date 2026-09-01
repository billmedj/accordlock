# Reproducibility runners

The top-level runners are fail-closed. A stage receives `PASS` only after its
process exits successfully. Missing tools, checksum drift, validation errors,
compiler source warnings, test failures, and model-checker errors terminate the
run. The CLI determinism probe alone authorizations rustc's `linker_messages` lint
because MSVC reports successful import-library creation on stderr; the separate
workspace Clippy stage still applies `-D warnings` to every target.

The default PostgreSQL mode is `local`. It starts or reuses the project-local
PostgreSQL 17.11 cluster on `127.0.0.1:55432`, runs the complete explicit local
`NoTls` PostgreSQL suite, and stops only an instance that it started. The
documented Windows 17.4 profile remains accepted for local compatibility;
other server versions fail closed until explicitly calibrated. The
separate SCRAM-PLUS/TLS integration requires its own TLS endpoint and is not
part of this local runner. External mode
requires `ACCORDLOCK_TEST_POSTGRES_URL`; it means that the runner does not manage
the database process, not that the current `NoTls` adapter accepts a remote
host. The state adapter still requires an explicit loopback address or local
Unix socket. The historical v5/v10/v11 rebuild cases in the main state suite and
the v13-to-v14 upgrade suite rebuild `public`; both therefore require the URL's
database name to be exactly `accordlock_test_v2` and reject any other database
before connecting. Local mode supplies its separate reset confirmation only
around each of those two destructive test binaries. External mode requires the
operator to set the same explicit `ACCORDLOCK_TEST_POSTGRES_V14_RESET` confirmation
as well as a dedicated disposable loopback database named `accordlock_test_v2`;
another ambient URL can neither redirect nor authorize either schema reset.
`not-requested` is available for diagnostics, but it prints `INCOMPLETE` and
exits with code 2. It is never reported as a green full run.

TLC is mandatory for a full run. Fetching its pinned jar is a separate,
explicit network operation:

```powershell
python scripts/fetch_tla2tools.py --output .local/tools/tla2tools.jar
./scripts/run-all.ps1
```

```sh
python3 scripts/fetch_tla2tools.py --output .local/tools/tla2tools.jar
sh scripts/run-all.sh
```

Those commands use the default exhaustive validation mode: they execute the
seven legacy canonical TLA configurations, the Max3
`DurableDispatchAcquisition.cfg` configuration, and the intentionally heavy
257-head PostgreSQL scanner test. A deliberately smaller smoke mode is
available for hosted CI and explicit local diagnostics:

```powershell
./scripts/run-all.ps1 -TlaMode smoke
$env:ACCORDLOCK_TLA_MODE = 'smoke'
./scripts/run-all.ps1
```

```sh
ACCORDLOCK_TLA_MODE=smoke sh scripts/run-all.sh
```

The smoke subrunners execute the first seven canonical configurations and
`DurableDispatchAcquisition.tla` with
`models/DurableDispatchAcquisitionSmoke.cfg`. That configuration performs a
complete reachable-state search at `MaxAcquisitions = 1` while retaining the
canonical invariant list, exact alpha-canonicalization, and `SafetyView`. It
exercises single-acquisition broker, review, attempt, restart, and recovery
paths, but cannot exercise takeover, supersession, or later-item ordering.
`models/DurableDispatchAcquisitionBoundedMax2.cfg` preserves the much larger
two-acquisition tier for an intentional deep run. Every checked-in smoke
invocation uses TLC's automatic worker selection. Output is labelled
`run_all_smoke` and explicitly states that it is neither a Max2 nor canonical
Max3 result.
The same smoke selection skips exactly one PostgreSQL test:
`postgres_v14_scan_skips_more_than_transient_retry_cap_and_reaches_valid_tail`.
That test constructs 257 fully authenticated durable workflows to prove the
scanner crosses its 256-item transient retry bound. All other PostgreSQL
adversarial, upgrade, guard, and CLI state-path tests still run in smoke mode.
The default exhaustive command retains the 257-head test unchanged; the runner
prints this boundary explicitly in both modes.
`ACCORDLOCK_TLA_MODE` accepts only `exhaustive` and `smoke`; omitting it always
selects the canonical exhaustive run, including the 257-head PostgreSQL test.
The historical variable name is retained for compatibility even though the
mode now also selects this one bounded database test. The PowerShell
`-TlaMode` parameter takes precedence over the environment.

The RustSec advisory check is also mandatory. The runner requires the exact
`cargo-audit 0.22.2` binary and a dedicated checkout of the official advisory
database. Install and fetch them explicitly before the runner's no-fetch
advisory stage:

```powershell
cargo install cargo-audit --version 0.22.2 --locked --root .local/tools/cargo-audit
git clone https://github.com/RustSec/advisory-db.git .local/rustsec-advisory-db
git -C .local/rustsec-advisory-db fetch --prune origin main
$rustSecCommit = (Get-Content scripts/rustsec-advisory-db.commit -Raw).Trim()
git -C .local/rustsec-advisory-db checkout --detach $rustSecCommit
```

```sh
cargo install cargo-audit --version 0.22.2 --locked --root .local/tools/cargo-audit
git clone https://github.com/RustSec/advisory-db.git .local/rustsec-advisory-db
git -C .local/rustsec-advisory-db fetch --prune origin main
rustsec_commit=$(tr -d '\r\n' < scripts/rustsec-advisory-db.commit)
git -C .local/rustsec-advisory-db checkout --detach "$rustsec_commit"
```

The advisory stage verifies the configured RustSec remote, requires `HEAD` to
equal the commit recorded in `scripts/rustsec-advisory-db.commit` and to be an
ancestor of the locally fetched `origin/main`, rejects a dirty checkout and a
commit more than 14 days old, and then audits offline. Updating that pin is an
explicit reviewed source change, not an automatic runner mutation. The stage
parses the JSON result and rejects advisory ignores, target or severity
filters, incomplete informational-warning classes, an unexpectedly small
database, vulnerabilities, and warnings. The checks establish exact use of and
local consistency with the configured fetched ref. They do not independently
authenticate that a local Git object
originated at GitHub or prove that the upstream database is complete. The
runner deliberately passes `--no-yanked` because yanked status requires a
working crates.io index and is a
separate supply-chain check. No yanked-crate claim is made by this stage. The
full build is not claimed to be network-independent unless the Rust dependency
cache has separately been populated and the Cargo commands are run offline.

The runners verify:

1. pinned Rust and other tool versions, plus the current RustSec advisory set;
2. crates.io-only locked external sources, repository-contained workspace
   manifests and Cargo target source paths, SHA-256 lock checksums, and
   non-empty Cargo license metadata for every external Rust package. It does
   not parse SPDX or make a legal license-compatibility determination;
3. exact SHA-256 coverage of every Git-visible source file at both the start
   and end of the run. The manifest deliberately excludes itself and ignored
   build/runtime output; regenerate it explicitly with
   `python scripts/source_manifest.py --write` on Windows or
   `python3 scripts/source_manifest.py --write` on POSIX after an intentional
   source change. After compilation, the runner also inspects rustc dep-info and
   rejects any existing repository source actually read by rustc but absent
   from the manifest. Generated inputs under `target` are counted separately;
4. duplicate-free JSON, corpus indexing, reason-code synchronization, and the
   provisional CDDL/Rust array contract;
5. payload corpus-oracle validation and its negative tests;
6. static negative tests for the fail-closed Kubernetes admission deployment
   candidate (the intentionally unmaterialized base itself remains refused);
7. payload and adversarial tests for the offline EKS activation-evidence
   claim validator. Its candidate result establishes internal claim/binding
   consistency only; it is not collector authentication, cryptographic
   provenance, operator approval, or permission to activate production;
8. formatting, all-target compilation, Clippy with warnings denied, and Rust
   tests;
9. two byte-identical executions of the synthetic CLI demo;
10. bounded TLC exploration of authorization epoch/replay safety, durable
   dispatch-claim rollback/rejection behavior, physical-resource exclusion,
   one-shot admission authorization, broker reconciliation, exact terminal
   retirement with atomic reservation release, the durable v13 control queue,
   and v14 server-selected dispatch acquisition, historical recovery discovery,
   no-send closure, and safe reservation release;
11. the explicit PostgreSQL state suite, the separate v13 durable-control
    adversarial suite, the v14 guard and true-upgrade suites, and the CLI
    library and binary durable-state paths. Smoke mode excludes only the
    257-head scanner proof; exhaustive mode includes it.

The default TLC subrunners execute the seven legacy canonical checked-in model
configurations followed by the canonical Max3
`DurableDispatchAcquisition.cfg` configuration. A missing pinned jar or any
failed configuration fails the stage; none may be silently skipped. The hosted
`reproducibility-smoke` workflow runs on pushes and pull requests with the
explicit Max1 full-search smoke mode and a two-hour fail-closed timeout. It does
not claim a Max2, canonical Max3, or 257-head PostgreSQL result. The separate
`reproducibility-exhaustive` workflow runs the unmodified default command on a
labelled self-hosted Linux TLC runner only when manually dispatched during the
technical preview; it has no push, schedule, or pull-request trigger. Both
workflows use the dedicated `accordlock_test_v2` service database and scope the
destructive reset confirmation to the single `run-all` step.

The corpus and CLI stages remain synthetic. Passing them is not Gate G0, a
customer workflow reconstruction, a benchmark, production assurance, or
independent validation.

The beginning/end checks detect persistent workspace drift. They do not make a
mutable checkout hostile-process-safe: an actor able to swap a source before
compilation and restore it before the final check can still evade this local
runner. That stronger threat model requires building an immutable committed
checkout or a content-addressed read-only copy. Rustc dep-info records compiler
inputs, not every file that an arbitrary build script or executed test might
read at runtime.
