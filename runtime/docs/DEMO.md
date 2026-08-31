# Offline demo

The AccordLock offline demo is the fastest honest proof that the local security
chain works. It uses the production Rust components with deterministic,
synthetic test material. The demo logic requires no account, network,
container runtime, database, Kubernetes cluster, or credential. On a fresh
machine, Cargo may still download the pinned toolchain and dependencies before
the binary starts.

From the repository root:

```sh
cargo run --locked -q -p accordlock-cli -- offline --compact
```

The command exits successfully only if every expected decision and refusal is
observed. It prints one JSON object so that humans, CI jobs, and release checks
can inspect the same result.

After the Rust dependencies are cached, add `--offline` to Cargo to enforce a
fully disconnected build:

```sh
cargo run --offline --locked -q -p accordlock-cli -- offline --compact
```

## What it proves locally

| Phase | Expected result |
|---|---|
| Signed request ingress | Accepted with the deterministic test authority |
| Typed evidence and policy evaluation | Legitimate deployment accepted |
| Adversarial authority, lineage, and delta cases | Refused |
| Authorization issuance and signature verification | Accepted |
| Transactional in-memory consumption | First use accepted |
| Replay of the same authorization | Refused as `ALREADY_CONSUMED` |
| Kubernetes patch and projection validation | Accepted for the exact bounded image change |

The report also states `production_ready: false`, `benchmark: false`, no
network access, and no external mutation. A release must treat those fields as
security-relevant output, not boilerplate.

## What it does not prove

The demo does not establish real AWS or Kubernetes identity, exclusive
credentials, live cluster RBAC, webhook caller authentication, the exact EKS
API audience, PostgreSQL behavior under distributed failure, complete mediation
of cluster writes, operational latency, or independent security assurance.
Those gates remain visible in the JSON report and in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

For fixture-by-fixture regression reports, use:

```sh
cargo run --locked -q -p accordlock-cli -- demo --scenario all
```

For the disposable account-free Kubernetes exhibit, continue with
[INSTALLATION.md](INSTALLATION.md). Neither path is authorization to deploy
AccordLock against a production resource.
