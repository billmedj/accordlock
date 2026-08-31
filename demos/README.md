# AccordLock provider-free adversarial demonstrations

This package runs security demonstrations against AccordLock's real native entrypoints without a model provider, account, cluster, or internet request.

It demonstrates five concrete properties:

1. Prompt-injection text inside a model plan checkpoint remains non-authoritative; a request for `.env` is denied by the native protected-path broker.
2. An unlisted HTTPS domain is denied locally before transport.
3. A file mutation requires one exact action approval; an identical retry is reconciled and cannot repeat the side effect.
4. A consumed authorization is rejected on replay by AccordLock's native offline scenario.
5. Authority drift is rejected by the native stale-state scenario.

The output is a machine-readable JSON report and a short Markdown report. It is an enforcement demonstration, not a claim that prompt injection is solved at the model layer.

## Run from a clean clone

From the repository root, one standard-library launcher builds the two locked
native entrypoints, verifies the native offline proof, runs all five cases, and
deletes temporary reports:

```powershell
python scripts/run_demo.py --display markdown
```

Use `--offline` after Rust dependencies are cached. Add
`--output-directory <path>` only when you want to retain the full JSON and
Markdown reports; existing report files are never overwritten.

Windows source builds require Visual Studio Build Tools with the
**Desktop development with C++** workload in addition to the pinned Rust
toolchain.

## Run against existing binaries

Python 3.11 or newer is sufficient. The package has no runtime dependency outside the standard library.

```powershell
$env:PYTHONPATH = "src"
python run_demo.py `
  --cli-binary C:\path\to\accordlock.exe `
  --runtime-binary C:\path\to\accordlock-agent-runtime.exe `
  --output-directory artifacts
```

The runtime listens only on a random literal IPv4 loopback port. The demo creates an ephemeral runtime token, SQLite ledger, and workspace under `.demo-runs`, then removes them. The network test configures only `allowed.example` and proposes `blocked.example`, which is rejected before the HTTPS adapter performs transport.

## AccordBench adapter

```powershell
$env:PYTHONPATH = "src"
python accordbench_adapter.py `
  --cli-binary C:\path\to\accordlock.exe `
  fixtures\accordbench-cases.jsonl
```

The adapter contract is documented in [docs/ACCORD_BENCH_ADAPTER.md](docs/ACCORD_BENCH_ADAPTER.md). It runs native AccordLock decisions and refuses oracle-shaped input fields.

## Tests

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Set `ACCORDLOCK_CLI_BIN` and `ACCORDLOCK_RUNTIME_BIN` to include the optional real-binary integration test. The hermetic tests do not need either binary.

## Non-claims

- No model is called, so this does not measure model susceptibility or task quality.
- No external network request, provider, cloud, Kubernetes, EKS, or notification service is exercised.
- The offline replay/stale scenarios use deterministic public fixtures and process-local state.
- The runtime demonstration uses ephemeral SQLite state and a temporary workspace.
- A passing report is not a formal proof, security audit, performance benchmark, or production-readiness certification.
