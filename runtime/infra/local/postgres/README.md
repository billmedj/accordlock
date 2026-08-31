# AccordLock disposable local PostgreSQL 17

These scripts initialize a project-local PostgreSQL cluster under
`.local/postgres`, bound only to `127.0.0.1:55432`. The database is
`accordlock_test_v2`; the user is `postgres`. The versioned name prevents the v2
single-grant/signed-authorization profile from silently coercing an incompatible v1
test database. An existing `accordlock_test` database is left untouched.

The checked-in migrations define fresh public-preview state. They do not support
an in-place upgrade from any earlier private alpha database. Export anything
needed for audit, then initialize a new disposable local cluster for this
revision.

Authentication is `trust` and no password or secret is created. This is
deliberate for a disposable single-user test cluster and is unsafe for a shared
machine, remote listener, CI secret, or production use. The scripts never
delete the data directory. Remove it manually only after verifying the exact
path and accepting the loss of local test data.

Windows with PostgreSQL 17 installed in the standard location:

```powershell
./infra/local/postgres/init.ps1
./infra/local/postgres/start.ps1
$env:ACCORDLOCK_TEST_POSTGRES_URL = 'postgresql://postgres@127.0.0.1:55432/accordlock_test_v2'
cargo test -p accordlock-state --test postgres -- --ignored --test-threads=1
./infra/local/postgres/stop.ps1
```

POSIX with PostgreSQL 17 commands on `PATH`:

```sh
./infra/local/postgres/postgres-local.sh start
ACCORDLOCK_TEST_POSTGRES_URL=postgresql://postgres@127.0.0.1:55432/accordlock_test_v2 \
  cargo test -p accordlock-state --test postgres -- --ignored --test-threads=1
./infra/local/postgres/postgres-local.sh stop
```

`start` is idempotent and creates the test database when absent. A stopped or
uninitialized status is not reported as a passing database stage.

Both platform helpers verify that the dedicated port is served by this
repository's exact project-local data directory before they reuse, report, or
stop a server. They fail closed when the data-directory postmaster and the
server reachable on the dedicated port do not agree.
