# Installing and evaluating AccordLock

AccordLock is an unreleased engineering alpha. There is no supported production installer
or hosted service yet. Use one of the bounded evaluation paths below.

## 1. Offline end-to-end decision proof

Use this path first. It demonstrates the local decision and authorization chain
without Docker, Kubernetes, PostgreSQL, or cloud credentials. The demo logic
does not access the network; a fresh Cargo installation may download the pinned
toolchain and dependencies before the binary starts.

Requirements:

- Git;
- the Rust toolchain pinned by `rust-toolchain.toml`.

From the repository root:

```sh
cargo run --locked -q -p accordlock-cli -- offline --compact
```

The command must exit successfully and emit one deterministic JSON report. The
report is intentionally self-limiting: it declares `production_ready: false`,
identifies its synthetic test material, lists the phases actually exercised,
and lists the live gates not exercised. It performs no cloud action or external
mutation. See [DEMO.md](DEMO.md) for the exact coverage boundary.

Once the dependencies are cached, require a fully disconnected Cargo run with:

```sh
cargo run --offline --locked -q -p accordlock-cli -- offline --compact
```

For individual positive and adversarial fixtures, run:

```sh
cargo run --locked -q -p accordlock-cli -- demo --scenario all
```

## 2. Repository verification

The fastest portable checks are:

```sh
cargo fmt --all -- --check
cargo check --workspace --locked --all-targets
cargo test --workspace --locked
python3 -m unittest discover -s tests -v
```

The complete fail-closed suite additionally requires PostgreSQL 17.11, Java,
the pinned TLA+ tool, and the pinned RustSec advisory database. The documented
Windows 17.4 reproduction profile remains accepted for local compatibility;
all other server versions fail closed until explicitly calibrated. Follow
[`scripts/README.md`](../scripts/README.md); do not omit failed or unavailable
stages while reporting a complete pass.

## 3. Disposable Kubernetes exhibit

Use this path to exercise the narrow image-update flow on an account-free local
cluster.

Requirements:

- Windows PowerShell;
- a reachable Linux-container Docker daemon using cgroup v2;
- `kind`;
- `kubectl`;
- the pinned Rust toolchain.

Run:

```powershell
& .\infra\local\k8s\run-live.ps1
```

Read [`infra/local/k8s/README.md`](../infra/local/k8s/README.md) first. The
runner retains detailed diagnostics and fails closed on an unknown or
mismatched existing cluster. It uses public deterministic keys and is not EKS,
production, or complete-mediation evidence.

## 4. Admission webhook container candidate

The repository includes a hardened container definition and a deliberately
unmaterialized Kubernetes base:

- [`containers/webhook/`](../containers/webhook/)
- [`infra/kubernetes/admission/`](../infra/kubernetes/admission/)

Both container base images must be supplied by immutable digest. The Kubernetes
base intentionally contains invalid placeholders and must fail validation until
an environment-specific private overlay supplies real, non-committed
configuration and secret references.

This path is for engineering evaluation. Do not apply the base to a production
cluster. There is intentionally no turnkey production deployment command.

## Uninstall and cleanup

The deterministic demo writes only build output under ignored local paths. The
PostgreSQL and Kubernetes helpers document their exact local state and cleanup
boundaries. Never delete a data directory or cluster by a computed or ambiguous
name; verify the explicit target first.

## Production deployment

Production deployment is not supported by this engineering alpha. The gates for
an authenticated GitHub–ECR–EKS beta and a production candidate are listed in
[ROADMAP.md](ROADMAP.md). Current security blockers are listed in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
