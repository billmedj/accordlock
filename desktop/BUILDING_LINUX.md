# AccordLock Linux source validation

AccordLock Desktop is currently a **source alpha**. This repository does not publish or endorse a Linux installer, package, container image, or upstream Goose binary as an AccordLock distribution.

## Supported boundary

Linux engineering evaluation must use the reviewed source tree and the single hardened CLI profile:

```text
cargo build --locked --release -p goose-cli --bin goose --no-default-features --features accordlock-distribution,rustls-tls,system-keyring
```

The desktop must be paired with the exact sibling AccordLock native runtime described in [the distribution boundary](ui/desktop/ACCORDLOCK_DISTRIBUTION.md). Building only the Electron shell or substituting an upstream Goose executable does not produce AccordLock.

System dependencies, desktop staging, and local developer commands may change while reproducibility work is in progress. Do not redistribute local ZIP, DEB, RPM, Flatpak, or container outputs, connect them to production credentials, or describe them as signed releases.

## Publication gate

Linux packaging remains blocked until the desktop/native-runtime pair has reproducible builds, provenance, an approved signing and update channel, rollback procedures, and release-owner review. The inherited bundle and package-publication workflows intentionally fail closed.

AccordLock is derived from [Goose](https://github.com/aaif-goose/goose) and preserves the upstream Apache-2.0 license and attribution.
