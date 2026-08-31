<!-- Modified by AccordLock contributors; see UPSTREAM.md. -->

# Windows extension helpers

These authored wrappers are copied into `src/bin` for Windows packages.

- `npx.cmd` runs an existing system `npx.cmd`. It never downloads or installs Node.js.
- `jbang.cmd` runs an existing system `jbang.exe` or `jbang.cmd`. It never changes JBang trust settings.

The wrappers skip themselves during `PATH` lookup, forward the original arguments, and return the selected tool's exit code. If a prerequisite is missing, they stop with an AccordLock error and exit code 127.

`prepare-windows-npm.bat` and `prepare-windows-npm.sh` are retired fail-closed stubs. Node.js and JBang must be installed through organization-approved system provisioning before an extension that uses them can start.

`prepare-platform-binaries.js` remains a packaging-only path for Astral `uv` 0.11.11. It accepts the immutable release archive only after every staged executable matches its pinned SHA-256 digest. It is not invoked by a packaged application.
