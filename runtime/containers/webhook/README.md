# AccordLock admission webhook image candidate

This container definition packages only `accordlock-webhookd`. It has no mutable
base-image default and therefore fails before the build unless both image
arguments are supplied as immutable digest references:

```text
docker build \
  --build-arg ACCORDLOCK_RUST_BUILDER_IMAGE=<builder-name>@sha256:<digest> \
  --build-arg ACCORDLOCK_RUNTIME_IMAGE=<runtime-name>@sha256:<digest> \
  --file containers/webhook/Dockerfile \
  --tag <local-output-name> \
  .
```

The builder image must contain Rust 1.97.1 and the native build tools required
by the locked dependency graph. The runtime image must be compatible with the
resulting Linux binary and run UID/GID `65532`. Freeze and record both exact
digests in the release evidence; do not replace them with tags in a published
command. The build stage validates both argument strings before copying source
or invoking Cargo and refuses a missing digest, non-lowercase/non-hex digest,
wrong digest length, or a tag on the final repository component. The container
engine still resolves each `FROM` before that check, so release automation must
also validate the arguments before invoking the engine; the in-build check is
defence in depth, not a registry-fetch policy.

`cargo build --frozen` proves only that Cargo used the committed lockfile. A
container build is not hermetic merely because its base images and Rust
dependencies are locked: the builder toolchain, registry delivery, build
scripts, native linker, operating-system packages, and BuildKit remain inputs.

No credential, PostgreSQL URL, TLS private key, CA bundle, tenant, cluster, or
executor identity is a build argument. Those values belong to the deployment
secret/configuration boundary. The root `.dockerignore` also excludes `.env*`,
private-key and certificate extensions at every directory depth (while keeping
the non-secret root `.env.example`), conventional `secret(s)` directories, and
mounted-style `password` files, so `COPY . .` cannot add those ignored secrets
to a builder layer or cache. The current repository does not yet claim a
published image, SBOM, signature, provenance attestation, vulnerability scan,
or live Kubernetes deployment.
