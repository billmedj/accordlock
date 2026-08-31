<!-- Modified by AccordLock contributors; see UPSTREAM.md. -->

# AccordLock Desktop scripts

These maintainer scripts support development, verification, English message extraction, and packaging. They are not an end-user installation path.

## Native component verification

`verify-accordlock-backend.js` checks all protected native components staged in `src/bin` before packaging:

- the protected Goose backend and `accordlock-build.json`;
- `accordlock-agent-runtime[.exe]` and `accordlock-runtime-build.json`.
- `accordlock-preflight-runner[.exe]` and `accordlock-preflight-runner-build.json`.

Each strict marker binds its component to a SHA-256 digest, protocol version, and source state. Release verification requires clean source. An explicitly acknowledged local development build may record dirty source truthfully; it cannot be packaged as a release.

From the repository root:

```powershell
# Unsigned local development; installs no dependencies and creates no package.
$env:ACCORDLOCK_ALLOW_DIRTY_BUILD = "1"
.\scripts\build-windows.ps1 -Development -AllowDirty -RuntimeRepo C:\path\to\accordlock

# Clean release build.
.\scripts\build-windows.ps1 -RuntimeArtifactsDirectory C:\path\to\verified-runtime-artifacts
```

Supplying both runtime sources or neither is an error.

## Platform preparation

`prepare-platform-binaries.js` stages pinned helper binaries for the current platform and removes incompatible cross-platform files. Downloaded helpers are accepted only after their pinned SHA-256 values match.

Packaged extension wrappers do not install runtimes. They resolve an existing system `node`, `npx`, `uvx`, or `jbang` outside the application bundle and fail with a prerequisite error when none is available. The legacy `prepare-windows-npm` scripts are retained only as fail-closed stubs.

## English messages and artwork

- `i18n-check.js` verifies that the extracted English source catalog is current.
- `i18n-compile.js` builds the English runtime catalog and removes stale generated catalogs.
- `generate-accordlock-icons.mjs` generates the icon set from the canonical vector.

Run `corepack pnpm run i18n:check` after copy changes.
