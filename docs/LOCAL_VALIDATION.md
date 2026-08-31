# Local Validation Record

**Date:** 2026-08-31  
**Environment:** Windows 11, Rust 1.97.1, Python 3.13.1, Java 20.0.1  
**Purpose:** record what was reproduced after the public monorepo was assembled

**Recorded revision:** `a371189415d154ffb1c8d42707cbf0e44f78a50e`

**Recorded component trees:** runtime `3a02ebe252285cacf180ca9c46976477ec71cfa7`; desktop `9f83e43814e4f513846b6423d3de55c211ddc3b0`

This is a workstation validation record, not a release certificate. A public tag must reproduce the required gates from a clean checkout in CI and retain the resulting logs.

## Passed

| Surface | Command or entry point | Result |
| --- | --- | --- |
| Runtime formatting | `cargo fmt --all -- --check` in `runtime/` | Passed |
| Runtime workspace | `cargo test --workspace --locked` in `runtime/` | Passed with no failures; tests explicitly requiring a disposable PostgreSQL service and helper-only subprocess tests remained ignored |
| Native offline chain | `accordlock offline --compact` | Passed; report declared `production_ready: false` |
| Adversarial demonstration | `python demos/run_demo.py` against freshly built native CLI and runtime binaries | 5 of 5 cases passed |
| Demonstration tests | Python standard-library unit and real-binary integration suite | 8 of 8 passed; no skipped integration test |
| Assurance manifest | `python assurance/verify.py --root runtime --json` | 10 claims, 221 references, 0 findings |
| Assurance linter tests | Python standard-library test suite | 9 of 9 passed |
| Lean | `runtime/formal/verify.ps1` | 81 theorems built; no `sorry` or declared `axiom` placeholder |
| TLA+ | `runtime/scripts/run-tla-smoke.ps1` with the pinned v1.7.4 jar | 8 complete bounded searches, 0 invariant violations |

The TLA+ runner verified the jar before execution:

```text
SHA-256 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
TLC 2.19 from TLA+ tools v1.7.4
```

### Bounded model-checking results

| Model | Configuration | Generated states | Distinct states | Complete depth |
| --- | --- | ---: | ---: | ---: |
| AuthorizationLifecycle | canonical | 886 | 306 | 10 |
| DispatchClaim | canonical | 37,121 | 4,218 | 9 |
| PhysicalReservation | canonical | 20,346 | 3,400 | 12 |
| AdmissionAuthorization | canonical | 5,457 | 640 | 9 |
| BrokerJournal | canonical | 1,520,004 | 250,052 | 27 |
| TerminalRetirement | canonical | 4,371,625 | 279,978 | 16 |
| DurableControlQueue | canonical | 20,165,021 | 839,417 | 21 |
| DurableDispatchAcquisition | Max1 smoke configuration | 3,149,250 | 307,768 | 22 |
| **Total** |  | **29,269,710** | **1,685,779** |  |

The final acquisition run is a complete Max1 search. It is not the canonical exhaustive Max3 result and does not cover Max2 multi-acquisition behavior.

## Not executed in this record

| Gate | Reason | Required next evidence |
| --- | --- | --- |
| PostgreSQL integration profiles | no disposable PostgreSQL service was configured | run the guarded suites against a dedicated local database and retain migration, concurrency, TLS, backup, and restore results |
| Desktop TypeScript and packaging suite | local Node.js 22.14.0 and pnpm 10.7.0 are below the build script's pinned Node.js 24.10 and pnpm 10.30 minimums | reproduce in pinned CI and on a clean packaging workstation |
| Disposable kind composition | Docker engine was not available | complete the repository's account-free kind exhibit and retain the report |
| Live GitHub, AWS, ECR, EKS, and messaging-provider acceptance | no test accounts or reachable gateway were used | run scoped disposable environments and retain redacted signed receipts |
| Signed installer lifecycle | no public signing identity or clean test machine was used | sign, install, update, roll back, uninstall, and verify on clean Windows and macOS systems |
| Independent review | not commissioned | review the release candidate after the deployment profile is frozen |

## Interpretation

This record establishes that the imported runtime source, provider-free transaction path, public claim map, abstract Lean model, and bounded TLA+ configurations reproduced locally after assembly. It does not establish live-provider identity, complete mediation, operating-system isolation, production key custody, production availability, or semantic correctness of arbitrary natural-language tasks.
