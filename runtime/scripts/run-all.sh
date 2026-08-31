#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
postgres_mode=${ACCORDLOCK_POSTGRES_MODE:-local}
tla_mode=${ACCORDLOCK_TLA_MODE:-exhaustive}
tla_jar=${TLA2TOOLS_JAR:-$repository_root/.local/tools/tla2tools.jar}
local_postgres_started_by_runner=0
run_incomplete=0

fail() {
    echo "FAIL $1" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "tool_versions missing=$1"
}

run_stage() {
    stage=$1
    shift
    echo "RUN $stage"
    "$@"
    echo "PASS $stage"
}

cleanup() {
    if [ "$local_postgres_started_by_runner" -eq 1 ] && [ "${ACCORDLOCK_KEEP_LOCAL_POSTGRES:-0}" != 1 ]; then
        echo 'RUN postgres_local_stop'
        "$repository_root/infra/local/postgres/postgres-local.sh" status >/dev/null
        "$repository_root/infra/local/postgres/postgres-local.sh" stop
        echo 'PASS postgres_local_stop'
    elif [ "$local_postgres_started_by_runner" -eq 1 ]; then
        echo 'RUNNING postgres_local_stop reason=ACCORDLOCK_KEEP_LOCAL_POSTGRES'
    fi
}
trap cleanup EXIT HUP INT TERM

case "$tla_mode" in
    exhaustive|smoke) ;;
    *) fail "tla_model_check unknown_mode=$tla_mode" ;;
esac

cd "$repository_root"
require_command cargo
require_command rustc
require_command python3
require_command java
require_command git

cargo_audit=${ACCORDLOCK_CARGO_AUDIT:-$repository_root/.local/tools/cargo-audit/bin/cargo-audit}
if [ ! -x "$cargo_audit" ]; then
    cargo_audit=$(command -v cargo-audit 2>/dev/null || true)
fi
if [ -z "$cargo_audit" ] || [ ! -x "$cargo_audit" ]; then
    fail 'tool_versions missing=cargo-audit'
fi

echo 'RUN tool_versions'
pinned_rust=$(python3 -c "import re; print(re.search(r'channel\\s*=\\s*\"([^\"]+)\"', open('rust-toolchain.toml', encoding='utf8').read()).group(1))")
rust_version=$(rustc --version)
case "$rust_version" in
    "rustc $pinned_rust "*) ;;
    *) fail "tool_versions rust_mismatch pinned=$pinned_rust observed=$rust_version" ;;
esac
echo "$rust_version"
cargo --version
cargo_audit_version=$($cargo_audit --version)
if [ "$cargo_audit_version" != 'cargo-audit 0.22.2' ]; then
    fail "tool_versions cargo-audit_mismatch observed=$cargo_audit_version"
fi
echo "$cargo_audit_version"
python3 --version
java -version
git --version
echo 'PASS tool_versions'

rustsec_db=$repository_root/.local/rustsec-advisory-db
run_stage rustsec_advisory_audit_no_yanked python3 scripts/check_rustsec_audit.py \
    --cargo-audit "$cargo_audit" --git git --db "$rustsec_db" \
    --lock "$repository_root/Cargo.lock" --expected-commit-file \
    "$repository_root/scripts/rustsec-advisory-db.commit" --max-age-days 14
run_stage locked_supply_chain_contract python3 scripts/check_supply_chain.py --cargo cargo
run_stage source_manifest_exact python3 scripts/source_manifest.py --git git

run_stage repository_contracts_static_only python3 scripts/validate_repository.py
run_stage synthetic_corpus_oracle_validation python3 conformance/validate.py
run_stage corpus_validator_negative_tests python3 -m unittest discover -s tests -p 'test_*.py'
run_stage admission_deployment_static_tests python3 -m unittest discover \
    -s infra/kubernetes/admission -p 'test_validate.py'
run_stage eks_activation_evidence_gate_tests python3 -m unittest discover \
    -s infra/kubernetes/activation -p 'test_validate.py'
run_stage rustfmt_check cargo fmt --all -- --check
run_stage cargo_check_all_targets cargo check --workspace --locked --all-targets
run_stage clippy_deny_warnings cargo clippy --workspace --locked --all-targets -- -D warnings
run_stage rust_tests_non_ignored cargo test --workspace --locked
run_stage rustc_actual_source_inputs python3 scripts/source_manifest.py \
    --git git --dep-info-root "$repository_root/target"
run_stage cli_synthetic_demo_determinism python3 scripts/check_cli_demo.py --cargo cargo
if [ "$tla_mode" = smoke ]; then
    run_stage tla_model_check_smoke sh "$repository_root/scripts/run-tla-smoke.sh" "$tla_jar"
else
    run_stage tla_model_check "$repository_root/scripts/run-tla.sh" "$tla_jar"
fi

case "$postgres_mode" in
    local)
        if "$repository_root/infra/local/postgres/postgres-local.sh" status >/dev/null 2>&1; then
            postgres_was_running=1
        else
            postgres_was_running=0
        fi
        run_stage postgres_local_start "$repository_root/infra/local/postgres/postgres-local.sh" start
        if [ "$postgres_was_running" -eq 0 ]; then
            local_postgres_started_by_runner=1
        fi
        ACCORDLOCK_TEST_POSTGRES_URL=postgresql://postgres@127.0.0.1:55432/accordlock_test_v2
        export ACCORDLOCK_TEST_POSTGRES_URL
        ;;
    external)
        if [ -z "${ACCORDLOCK_TEST_POSTGRES_URL:-}" ]; then
            fail 'postgres_transactional_test external mode requires ACCORDLOCK_TEST_POSTGRES_URL'
        fi
        if [ "${ACCORDLOCK_TEST_POSTGRES_V14_RESET:-}" != DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2 ]; then
            fail 'postgres_transactional_test external mode requires explicit ACCORDLOCK_TEST_POSTGRES_V14_RESET confirmation'
        fi
        ;;
    not-requested)
        echo 'NOT_REQUESTED postgres_transactional_test mode=not-requested'
        run_incomplete=1
        ;;
    *) fail "postgres_transactional_test unknown_mode=$postgres_mode" ;;
esac

if [ "$postgres_mode" != not-requested ]; then
    if [ "$postgres_mode" = local ]; then
        run_stage postgres_state_adversarial_invariants env \
            ACCORDLOCK_TEST_POSTGRES_V14_RESET=DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2 \
            cargo test -p accordlock-state --test postgres --locked -- \
            --ignored --test-threads=1
    else
        run_stage postgres_state_adversarial_invariants cargo test -p accordlock-state \
            --test postgres --locked -- --ignored --test-threads=1
    fi
    if [ "$tla_mode" = smoke ]; then
        echo 'BOUNDARY postgres_control_v13_smoke omits only the 257-head exhaustive scan; default exhaustive mode retains it'
        run_stage postgres_control_v13_adversarial_invariants cargo test -p accordlock-state \
            --test postgres_control_v13 --locked -- --ignored --test-threads=1 \
            --skip postgres_v14_scan_skips_more_than_transient_retry_cap_and_reaches_valid_tail
    else
        run_stage postgres_control_v13_adversarial_invariants cargo test -p accordlock-state \
            --test postgres_control_v13 --locked -- --ignored --test-threads=1
    fi
    run_stage postgres_v14_guard_invariants cargo test -p accordlock-state \
        --test postgres_v14_guards --locked -- --ignored --test-threads=1
    if [ "$postgres_mode" = local ]; then
        run_stage postgres_v14_upgrade_invariants env \
            ACCORDLOCK_TEST_POSTGRES_V14_RESET=DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2 \
            cargo test -p accordlock-state --test postgres_v14_upgrade --locked -- \
            --ignored --test-threads=1
    else
        run_stage postgres_v14_upgrade_invariants cargo test -p accordlock-state \
            --test postgres_v14_upgrade --locked -- --ignored --test-threads=1
    fi
    run_stage postgres_live_session_state_path cargo test -p accordlock-cli --lib --locked \
        live_k8s::tests::postgres_live_session_persists_receipt_and_outbox -- \
        --ignored --exact --test-threads=1
    run_stage postgres_live_session_cli_path cargo test -p accordlock-cli --test live_postgres_cli \
        --locked cli_postgres_prepare_and_validate_reverify_durable_state -- \
        --ignored --exact --test-threads=1
fi

run_stage source_manifest_exact_final python3 scripts/source_manifest.py --git git

if [ "$run_incomplete" -eq 1 ]; then
    echo 'INCOMPLETE run_all reason=postgres_not_requested'
    exit 2
fi

if [ "$tla_mode" = smoke ]; then
    echo 'PASS run_all_smoke scope=static_contracts_rust_tla_smoke_postgres_bounded_live_cli_rustsec tla_mode=smoke'
    echo 'BOUNDARY run_all_smoke is not a full or exhaustive reproducibility result'
    echo 'BOUNDARY run_all_smoke excludes the 257-head PostgreSQL scan retained by exhaustive mode'
else
    echo 'PASS run_all scope=static_contracts_rust_tla_postgres_live_cli_rustsec tla_mode=exhaustive'
fi
echo 'BOUNDARY conformance scenario manifests were validated but not executed'
echo 'BOUNDARY RustSec advisories were checked; yanked-crate status was not checked'
