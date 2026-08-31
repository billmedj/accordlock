#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
expected_sha256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jar=${1:-${TLA2TOOLS_JAR:-}}

if [ -z "$jar" ] && [ -f "$repository_root/.local/tools/tla2tools.jar" ]; then
    jar=$repository_root/.local/tools/tla2tools.jar
fi
if [ -z "$jar" ]; then
    echo 'FAIL tla_model_check_smoke: TLC jar is required; fetch it explicitly or set TLA2TOOLS_JAR' >&2
    exit 1
fi
if [ ! -f "$jar" ]; then
    echo "FAIL tla_model_check_smoke: jar not found: $jar" >&2
    exit 1
fi
if ! command -v java >/dev/null 2>&1; then
    echo 'FAIL tla_model_check_smoke: java is missing' >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    observed_sha256=$(sha256sum "$jar")
    observed_sha256=${observed_sha256%% *}
elif command -v shasum >/dev/null 2>&1; then
    observed_sha256=$(shasum -a 256 "$jar")
    observed_sha256=${observed_sha256%% *}
else
    echo 'FAIL tla_model_check_smoke: sha256sum or shasum is required' >&2
    exit 1
fi
if [ "$observed_sha256" != "$expected_sha256" ]; then
    echo "FAIL tla_model_check_smoke: expected=$expected_sha256 observed=$observed_sha256" >&2
    exit 1
fi

canonical_models='AuthorizationLifecycle DispatchClaim PhysicalReservation AdmissionAuthorization BrokerJournal TerminalRetirement DurableControlQueue'
model_count=0
for model in $canonical_models; do
    java -XX:+UseParallelGC -jar "$jar" -workers auto -cleanup \
        -config "$repository_root/models/$model.cfg" \
        "$repository_root/models/$model.tla"
    echo "PASS tla_model_smoke model=$model config=canonical sha256=$observed_sha256"
    model_count=$((model_count + 1))
done

java -XX:+UseParallelGC -jar "$jar" -workers auto -cleanup \
    -config "$repository_root/models/DurableDispatchAcquisitionSmoke.cfg" \
    "$repository_root/models/DurableDispatchAcquisition.tla"
echo "PASS tla_model_smoke model=DurableDispatchAcquisition config=smoke_max_acquisitions_1_full_search sha256=$observed_sha256"
model_count=$((model_count + 1))

echo "PASS tla_model_check_smoke models=$model_count canonical_configs=7 smoke_configs=1 sha256=$observed_sha256"
echo 'BOUNDARY tla_model_check_smoke is a complete Max1 search; it is not the canonical exhaustive Max3 result and does not cover Max2 multi-acquisition behavior'
