#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
local_root=$repository_root/.local/postgres
data_dir=$local_root/data
log_file=$local_root/postgres.log
port=55432
database=accordlock_test_v2
user=postgres
action=${1:-}

case "$data_dir" in
    "$repository_root"/.local/postgres/*) ;;
    *) echo "FAIL postgres_local: unsafe data path: $data_dir" >&2; exit 1 ;;
esac

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "FAIL postgres_local: missing command: $1" >&2
        exit 1
    fi
}

data_server_running() {
    pg_ctl status -D "$data_dir" >/dev/null 2>&1
}

dedicated_port_ready() {
    pg_isready -h 127.0.0.1 -p "$port" -U "$user" -d postgres >/dev/null 2>&1
}

serving_data_dir() {
    psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$port" -U "$user" \
        -d postgres -tA -c 'SHOW data_directory'
}

assert_owned_server() {
    if ! dedicated_port_ready; then
        echo "FAIL postgres_local: dedicated port $port is not ready" >&2
        exit 1
    fi
    observed=$(serving_data_dir)
    if [ -z "$observed" ] || [ ! -d "$observed" ]; then
        echo 'FAIL postgres_local: serving data directory is absent or invalid' >&2
        exit 1
    fi
    expected_canonical=$(CDPATH= cd "$data_dir" && pwd -P)
    observed_canonical=$(CDPATH= cd "$observed" && pwd -P)
    if [ "$observed_canonical" != "$expected_canonical" ]; then
        echo "FAIL postgres_local: port $port serves another data directory" >&2
        exit 1
    fi
}

initialize() {
    require_command initdb
    if [ -f "$data_dir/PG_VERSION" ]; then
        version=$(tr -d '[:space:]' < "$data_dir/PG_VERSION")
        if [ "$version" != 17 ]; then
            echo "FAIL postgres_init: existing version=$version expected=17" >&2
            exit 1
        fi
        echo "PASS postgres_init existing_cluster=$data_dir version=17"
        return
    fi
    if [ -d "$data_dir" ] && [ -n "$(find "$data_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "FAIL postgres_init: non-empty data directory without PG_VERSION" >&2
        exit 1
    fi
    mkdir -p "$data_dir"
    initdb -D "$data_dir" --username=postgres --auth-local=trust --auth-host=trust \
        --encoding=UTF8 --no-locale
    {
        echo
        echo "# AccordLock disposable local test cluster."
        echo "listen_addresses = '127.0.0.1'"
        echo "port = $port"
        echo 'fsync = on'
        echo 'synchronous_commit = on'
        echo 'full_page_writes = on'
    } >> "$data_dir/postgresql.conf"
    echo "PASS postgres_init new_cluster=$data_dir version=17 auth=trust_loopback_only"
}

start_server() {
    initialize
    require_command pg_ctl
    require_command psql
    require_command createdb
    require_command pg_isready
    mkdir -p "$local_root"
    if data_server_running; then
        assert_owned_server
        state=existing_server
    else
        if dedicated_port_ready; then
            echo "FAIL postgres_start: port $port is occupied by another PostgreSQL server" >&2
            exit 1
        fi
        pg_ctl start -D "$data_dir" -l "$log_file" -w -t 30 -o "-p $port -h 127.0.0.1"
        assert_owned_server
        state=started_server
    fi
    exists=$(psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$port" -U "$user" \
        -d postgres -tA -c "SELECT 1 FROM pg_database WHERE datname = '$database'")
    if [ "$exists" != 1 ]; then
        createdb -h 127.0.0.1 -p "$port" -U "$user" "$database"
    fi
    pg_isready -h 127.0.0.1 -p "$port" -U "$user" -d "$database"
    echo "PASS postgres_start state=$state port=$port database=$database"
    echo "ACCORDLOCK_TEST_POSTGRES_URL=postgresql://$user@127.0.0.1:$port/$database"
}

case "$action" in
    init) initialize ;;
    start) start_server ;;
    stop)
        require_command pg_ctl
        require_command psql
        require_command pg_isready
        if [ ! -f "$data_dir/PG_VERSION" ] || ! data_server_running; then
            echo "NOT_RUNNING postgres_stop path=$data_dir"
        else
            assert_owned_server
            pg_ctl stop -D "$data_dir" -m fast -w -t 30
            echo "PASS postgres_stop path=$data_dir"
        fi
        ;;
    status)
        require_command pg_ctl
        require_command psql
        require_command pg_isready
        data_server_running
        assert_owned_server
        echo "PASS postgres_status url=postgresql://$user@127.0.0.1:$port/$database"
        ;;
    *)
        echo 'usage: postgres-local.sh init|start|stop|status' >&2
        exit 2
        ;;
esac
