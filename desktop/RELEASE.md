<!-- Modified by AccordLock contributors; see UPSTREAM.md. -->
# AccordLock release process

AccordLock has no supported production release yet. A source snapshot,
development installer, or passing local test suite is not a production
security boundary.

The release boundary spans this monorepo's desktop distribution and independent
runtime. Validate both component trees from the monorepo root.

## Source engineering alpha

The first public technical preview is a source-only GitHub prerelease. It may
contain no binary assets. Before tagging it, the exact monorepo commit must pass
the source publication, runtime, desktop, formal-model, and reproducibility
workflows. Its notes must link the exact commit and green workflow runs, state
that live cloud/provider acceptance and independent review remain pending, and
direct readers to the known limitations.

The source tag does not satisfy the binary or production gates below. It exists
so reviewers can inspect, reproduce, and discuss the complete engineering
alpha without mistaking an unsigned development package for a supported build.

## Binary and production gates

Binary release packaging remains disabled until its manifest adapter, signing,
inventory, clean-machine, live-provider, and independent-review gates pass.

## Release gates

A binary or production release candidate may be published only when all of
these gates pass:

1. **Pinned source** — the root `SOURCE_PROVENANCE.json` records the imported
   desktop and runtime commits, source trees, assembled trees, exclusions, and
   post-import adjustments.
2. **Repository validation** — publication hygiene, license attribution,
   schemas, policy contracts, and source-lock checks pass.
3. **Automated tests** — the core Rust suites and desktop unit, type, format,
   localization, and packaging checks pass from a clean checkout.
4. **Reproducible package** — the binary release orchestrator consumes a
   release-ready manifest derived from the recorded monorepo sources. Embedded
   binaries match their build markers and source commit.
5. **Signed artifacts** — the Windows installer and protected sidecars have
   valid release signatures. Development signatures are not accepted.
6. **Software inventory** — the pinned Syft version produces valid CycloneDX
   inventories for the packaged desktop and both source components.
7. **Manual acceptance** — every item in `RELEASE_CHECKLIST.md` passes on a
   supported clean Windows system and on an upgrade from the previous release.
8. **Security review** — no unresolved release-blocking vulnerability or
   unsupported production claim remains.

## Build

Do not invoke `-Release` for the source-only technical preview. A later binary
release must run from the monorepo root, validate source provenance, derive the
packager's release-ready manifest, and invoke the fail-closed packager with a
code-signing certificate and pinned SBOM tool.

The completed output must contain:

- the Windows installer;
- the unpacked application and portable archive;
- `accordlock-artifact-manifest.json`;
- `SHA256SUMS`;
- CycloneDX inventories for the desktop, distribution source, and core source.

Verify every checksum, build marker, source commit, signature, and inventory
before attaching artifacts to a release. Keep development packages clearly
marked and never publish them as supported releases.

## Publish

Create an immutable version tag only after the gates for that release class
pass. Release notes must state the release class, supported operating systems,
supported deployment profiles, known limitations, upgrade behavior, and
security-relevant changes. Do not imply that a read-only deployment preflight
can change a cluster.

If any gate fails after packaging, discard the candidate, fix the source, and
build a new version. Do not replace artifacts under an existing tag.
