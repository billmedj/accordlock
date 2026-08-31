#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
expected_sha256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jar=${1:-${TLA2TOOLS_JAR:-}}

if [ -z "$jar" ] && [ -f "$repository_root/.local/tools/tla2tools.jar" ]; then
    jar=$repository_root/.local/tools/tla2tools.jar
fi
if [ -z "$jar" ]; then
    echo 'FAIL tla_model_check: TLC jar is required; fetch it explicitly or set TLA2TOOLS_JAR' >&2
    exit 1
fi
if [ ! -f "$jar" ]; then
    echo "FAIL tla_model_check: jar not found: $jar" >&2
    exit 1
fi
if ! command -v java >/dev/null 2>&1; then
    echo 'FAIL tla_model_check: java is missing' >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    observed_sha256=$(sha256sum "$jar")
    observed_sha256=${observed_sha256%% *}
elif command -v shasum >/dev/null 2>&1; then
    observed_sha256=$(shasum -a 256 "$jar")
    observed_sha256=${observed_sha256%% *}
else
    echo 'FAIL tla_model_check: sha256sum or shasum is required' >&2
    exit 1
fi
if [ "$observed_sha256" != "$expected_sha256" ]; then
    echo "FAIL tla_model_check: expected=$expected_sha256 observed=$observed_sha256" >&2
    exit 1
fi

models='AuthorizationLifecycle DispatchClaim PhysicalReservation AdmissionAuthorization BrokerJournal TerminalRetirement DurableControlQueue DurableDispatchAcquisition'
model_count=0
for model in $models; do
    java -XX:+UseParallelGC -jar "$jar" -workers 1 -cleanup \
        -config "$repository_root/models/$model.cfg" \
        "$repository_root/models/$model.tla"
    echo "PASS tla_model model=$model sha256=$observed_sha256"
    model_count=$((model_count + 1))
done

echo "PASS tla_model_check models=$model_count sha256=$observed_sha256"
