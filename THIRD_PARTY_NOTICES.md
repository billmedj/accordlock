# Third-party notices

This file records the principal source-level attributions for the AccordLock
monorepo. Individual source files, nested license files, lockfiles, and packaged
dependency metadata remain authoritative for their respective components.

## Goose

[`desktop/`](desktop/) is a modified distribution derived from
[Goose](https://github.com/aaif-goose/goose). Goose is developed by its upstream
contributors and is licensed under the Apache License 2.0. AccordLock-specific
changes are not authored, endorsed, or certified by the upstream Goose project.

- Upstream source: <https://github.com/aaif-goose/goose>
- Preserved component license: [`desktop/LICENSE`](desktop/LICENSE)
- Component notice: [`desktop/NOTICE`](desktop/NOTICE)
- Imported-source record: [`SOURCE_PROVENANCE.json`](SOURCE_PROVENANCE.json)

## Contributor Covenant

[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) adapts Contributor Covenant version
2.1, originally authored by Coraline Ada Ehmke and stewarded by the
Organization for Ethical Source. The adapted upstream material is licensed
under the [Creative Commons Attribution 4.0 International
License](https://creativecommons.org/licenses/by/4.0/). The file identifies the
changes made for AccordLock.

## Package dependencies

The Rust and JavaScript dependency graphs are pinned in component lockfiles:

- [`runtime/Cargo.lock`](runtime/Cargo.lock)
- [`desktop/Cargo.lock`](desktop/Cargo.lock)
- [`desktop/ui/pnpm-lock.yaml`](desktop/ui/pnpm-lock.yaml)

Some source packages retain their own license or notice files inside the
component tree. Binary distributors must preserve all applicable notices and
generate a dependency license inventory and software bill of materials for the
exact release artifact. This source-level notice is not a substitute for that
artifact-specific review.

## Embedded desktop assets

The desktop component embeds pinned browser distributions for visualization
and source data for optional local Whisper transcription. Exact versions,
upstream artifacts, SHA-256 digests, modification relationships, attributions,
and complete required license texts are recorded in
[`desktop/THIRD_PARTY_NOTICES.md`](desktop/THIRD_PARTY_NOTICES.md). That file,
the desktop `LICENSE`, and the desktop `NOTICE` are included in packaged
applications by `desktop/ui/desktop/forge.config.ts`.

## Evaluation tools

TLA+ tools, Lean, Rust, Node.js, Python, Docker, Kubernetes, and `kind` are not
relicensed by this repository. The pinned TLA+ jar is downloaded only through
the hash-verifying fetch script and is not committed. Each tool remains subject
to its own license.
