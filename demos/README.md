# Provider-free demos

These five cases run against the native CLI and runtime without a model,
external account, or external request:

1. Injected instructions in a model plan cannot authorize a read of `.env`.
2. The HTTPS broker rejects an unlisted domain before transport.
3. A file write needs approval bound to that action. An identical retry is
   reconciled without repeating the write.
4. The offline scenario rejects a consumed execution grant.
5. The stale-state scenario rejects changed authority.

## Run from a clean clone

Requires Python 3.11+ and the pinned Rust toolchain. Windows builds also need
Visual Studio Build Tools with the Desktop development with C++ workload.

From the repository root, build both binaries and run the cases:

```powershell
python scripts/run_demo.py --display markdown
```

Success includes `PASS provider_free_demo cases=5 provider=NONE network=NOT_ATTEMPTED`.
Use `--offline` once Rust dependencies are cached; otherwise the build may
download dependencies.

Reports are temporary by default. Add `--output-directory <path>` to keep
`adversarial-demo.json` and `adversarial-demo.md`. The launcher refuses to
overwrite existing reports.

## Run against existing binaries

From `demos/`, with Python 3.11+ and no third-party Python packages:

```powershell
$env:PYTHONPATH = "src"
python run_demo.py `
  --cli-binary C:\path\to\accordlock.exe `
  --runtime-binary C:\path\to\accordlock-agent-runtime.exe `
  --output-directory artifacts
```

The runtime listens only on a random IPv4 loopback port. The demo removes its
temporary token, SQLite ledger, and workspace under `.demo-runs` when finished.

## AccordBench adapter

From `demos/`:

```powershell
$env:PYTHONPATH = "src"
python accordbench_adapter.py `
  --cli-binary C:\path\to\accordlock.exe `
  fixtures\accordbench-cases.jsonl
```

The adapter runs native decisions and rejects fields that supply expected
answers. See the [adapter contract](docs/ACCORD_BENCH_ADAPTER.md).

## Tests

From `demos/`:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Set `ACCORDLOCK_CLI_BIN` and `ACCORDLOCK_RUNTIME_BIN` to include the native
integration test. Other tests need neither binary.

These local fixtures test broker enforcement and replay handling. They do not
measure model behavior, external-service compatibility, or production safety.
The offline replay and stale-state cases use process-local state.
