# AccordLock release process

AccordLock has no supported public release yet. A source snapshot, development
installer, or passing local test suite is not a production release.

The release boundary spans the AccordLock wrapper, this desktop distribution,
and the AccordLock core runtime. Use the wrapper repository to validate and
package those exact sources together.

## Release gates

A release candidate may be published only when all of these gates pass:

1. **Pinned source** — `UPSTREAM.lock.json` names clean, public commits for the
   wrapper, desktop distribution, and core runtime.
2. **Repository validation** — publication hygiene, license attribution,
   schemas, policy contracts, and source-lock checks pass.
3. **Automated tests** — the core Rust suites and desktop unit, type, format,
   localization, and packaging checks pass from a clean checkout.
4. **Reproducible package** — the wrapper builds the installer from the pinned
   sources. Embedded binaries match their build markers and source commits.
5. **Signed artifacts** — the Windows installer and protected sidecars have
   valid release signatures. Development signatures are not accepted.
6. **Software inventory** — the pinned Syft version produces valid CycloneDX
   inventories for the packaged desktop and both source components.
7. **Manual acceptance** — every item in `RELEASE_CHECKLIST.md` passes on a
   supported clean Windows system and on an upgrade from the previous release.
8. **Security review** — no unresolved release-blocking vulnerability or
   unsupported production claim remains.

## Build

Run the release from the wrapper repository, not from this nested source tree.
The wrapper validates the source lock and invokes this distribution's
fail-closed packager with the code-signing certificate and pinned SBOM tool.

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

Create an immutable version tag only after the release gates pass. Release
notes must state the supported operating systems, supported deployment
profiles, known limitations, upgrade behavior, and security-relevant changes.
Do not imply that a read-only deployment preflight can change a cluster.

If any gate fails after packaging, discard the candidate, fix the source, and
build a new version. Do not replace artifacts under an existing tag.
