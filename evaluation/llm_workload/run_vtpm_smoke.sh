#!/usr/bin/env bash
# Run one short Protocol 1.2 LLM experiment against already-running CVM
# services. Results are written below evaluation/results/llm/pets2027-vtpm/.

set -euo pipefail

MODE=""
TDX_HOST=""
VLLM_HOST=""
MODEL_KEY="phi3-mini"
INTERLEAVE="no-updates"
RPS="0.15"
EPOCH_SEC="15"
DURATION_SEC="90"
TDX_PORT="8443"
VLLM_PORT="8000"
NUM_PROMPTS=""
CAMPAIGN_ID=""
RUN_ID=""
RESULT_ROOT=""
SSH_USER=""
SSH_KEY=""
CA_CERT=""
NO_VERIFY=0
REQUIRE_AK_CERT=0
GOLDEN_FILE=""
REQUIRE_GOLDEN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --tdx-host) TDX_HOST="$2"; shift 2 ;;
        --vllm-host) VLLM_HOST="$2"; shift 2 ;;
        --model-key) MODEL_KEY="$2"; shift 2 ;;
        --rps) RPS="$2"; shift 2 ;;
        --epoch-sec) EPOCH_SEC="$2"; shift 2 ;;
        --duration-sec) DURATION_SEC="$2"; shift 2 ;;
        --tdx-port) TDX_PORT="$2"; shift 2 ;;
        --vllm-port) VLLM_PORT="$2"; shift 2 ;;
        --num-prompts) NUM_PROMPTS="$2"; shift 2 ;;
        --campaign-id) CAMPAIGN_ID="$2"; shift 2 ;;
        --run-id) RUN_ID="$2"; shift 2 ;;
        --result-root) RESULT_ROOT="$2"; shift 2 ;;
        --ssh-user) SSH_USER="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ca-cert) CA_CERT="$2"; shift 2 ;;
        --no-verify) NO_VERIFY=1; shift ;;
        --require-ak-cert) REQUIRE_AK_CERT=1; shift ;;
        --golden-file) GOLDEN_FILE="$2"; shift 2 ;;
        --require-golden) REQUIRE_GOLDEN=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ "$MODE" == "sgx" || "$MODE" == "python" ]] || {
    echo "--mode must be sgx or python" >&2
    exit 2
}
[[ -n "$TDX_HOST" ]] || { echo "--tdx-host is required" >&2; exit 2; }
VLLM_HOST="${VLLM_HOST:-$TDX_HOST}"
[[ -z "$SSH_USER" && -z "$SSH_KEY" ]] || {
    [[ -n "$SSH_USER" && -n "$SSH_KEY" ]] || {
        echo "--ssh-user and --ssh-key must be supplied together" >&2
        exit 2
    }
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERIFIER_DIR="$REPO_ROOT/research/sgx-tdx-attestation/sgx-verifier"
APP_DIR="$REPO_ROOT/research/sgx-tdx-attestation"
RESULT_ROOT="${RESULT_ROOT:-$REPO_ROOT/evaluation/results/llm/pets2027-vtpm}"
CAMPAIGN_ID="${CAMPAIGN_ID:-smoke-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_ID="${RUN_ID:-${MODEL_KEY}-tdx-vordr-${MODE}-${INTERLEAVE}-T${EPOCH_SEC}-r1}"
RUN_DIR="$RESULT_ROOT/$CAMPAIGN_ID/$MODEL_KEY/tdx-vordr/$MODE/T-${EPOCH_SEC}s/repeat-1"
STAGE_REL="llm-results/$CAMPAIGN_ID/$MODEL_KEY/tdx-vordr/$MODE/T-${EPOCH_SEC}s/repeat-1"
STAGE_HOST="$APP_DIR/runtime-state/$STAGE_REL"
STAGE_ENCLAVE="/app/runtime-state/$STAGE_REL"

if [[ -e "$RUN_DIR" || -e "$STAGE_HOST" ]]; then
    echo "refusing to overwrite an existing run:" >&2
    echo "  $RUN_DIR" >&2
    echo "  $STAGE_HOST" >&2
    exit 2
fi

mkdir -p "$RUN_DIR" "$STAGE_HOST"

python3 - "$TDX_HOST" "$TDX_PORT" "$VLLM_HOST" "$VLLM_PORT" <<'PY'
import socket
import sys

for label, host, port in (
    ("TDX protocol server", sys.argv[1], int(sys.argv[2])),
    ("vLLM server", sys.argv[3], int(sys.argv[4])),
):
    try:
        with socket.create_connection((host, port), timeout=5):
            print(f"[preflight] {label} reachable at {host}:{port}")
    except OSError as exc:
        raise SystemExit(f"[preflight] {label} is not reachable: {exc}")
PY

if [[ -z "$NUM_PROMPTS" ]]; then
    NUM_PROMPTS=$(python3 -c \
        "import math; print(max(3, int(math.ceil(float('$RPS') * float('$DURATION_SEC')))))")
fi

if [[ "$MODE" == "sgx" ]]; then
    [[ -f "$VERIFIER_DIR/verifier.manifest.sgx" && -f "$VERIFIER_DIR/verifier.sig" ]] || {
        echo "SGX verifier is not built; run 'make all' in $VERIFIER_DIR" >&2
        exit 2
    }
    DRIVER_OUT="$STAGE_ENCLAVE"
    CHECKPOINT="$STAGE_ENCLAVE/checkpoint.sealed"
    READY="$STAGE_ENCLAVE/ready.json"
    START_SIGNAL="$STAGE_ENCLAVE/start.json"
    DRIVER=(
        gramine-sgx ./verifier
        /app/sgx-verifier/llm_attestation_driver.py
    )
else
    DRIVER_OUT="$STAGE_HOST"
    CHECKPOINT="$STAGE_HOST/checkpoint.unused"
    READY="$STAGE_HOST/ready.json"
    START_SIGNAL="$STAGE_HOST/start.json"
    DRIVER=(python3 llm_attestation_driver.py)
fi

COMMON_ARGS=(
    --tdx-host "$TDX_HOST"
    --tdx-port "$TDX_PORT"
    --epoch-sec "$EPOCH_SEC"
    --duration-sec "$DURATION_SEC"
    --campaign-id "$CAMPAIGN_ID"
    --run-id "$RUN_ID"
    --output-dir "$DRIVER_OUT"
    --checkpoint-file "$CHECKPOINT"
    --checkpoint-namespace "pets2027-llm|$CAMPAIGN_ID|$RUN_ID"
    --start-signal "$START_SIGNAL"
    --ready-file "$READY"
    --baseline-before-measurement
    --reset-checkpoint
    --reset-cvm-stream
    --fail-fast
    --expected-rtmr3-base auto
)
[[ "$NO_VERIFY" == "1" ]] && COMMON_ARGS+=(--no-verify)
[[ -n "$CA_CERT" ]] && COMMON_ARGS+=(--ca-cert "$CA_CERT")
[[ "$REQUIRE_AK_CERT" == "1" ]] && COMMON_ARGS+=(--require-ak-cert)
[[ -n "$GOLDEN_FILE" ]] && COMMON_ARGS+=(--golden-file "$GOLDEN_FILE")
[[ "$REQUIRE_GOLDEN" == "1" ]] && COMMON_ARGS+=(--require-golden)

echo "[smoke] campaign=$CAMPAIGN_ID run=$RUN_ID"
echo "[smoke] results=$RUN_DIR"

(
    cd "$VERIFIER_DIR"
    PYTHONPATH="$APP_DIR" "${DRIVER[@]}" "${COMMON_ARGS[@]}"
) >"$RUN_DIR/attestation_driver.log" 2>&1 &
DRIVER_PID=$!

cleanup() {
    if kill -0 "$DRIVER_PID" 2>/dev/null; then
        kill "$DRIVER_PID" 2>/dev/null || true
        wait "$DRIVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[smoke] waiting for the unmeasured baseline attestation"
deadline=$(( $(date +%s) + 600 ))
while [[ ! -f "$STAGE_HOST/ready.json" ]]; do
    if ! kill -0 "$DRIVER_PID" 2>/dev/null; then
        echo "attestation driver exited during baseline:" >&2
        tail -n 80 "$RUN_DIR/attestation_driver.log" >&2 || true
        exit 1
    fi
    if [[ $(date +%s) -ge $deadline ]]; then
        echo "timed out waiting for baseline attestation" >&2
        exit 1
    fi
    sleep 1
done

T0=$(python3 -c "import time; print(time.time() + 10.0)")
printf '{"start_at_epoch": %.6f}\n' "$T0" >"$STAGE_HOST/start.json"
echo "[smoke] baseline complete; measurement starts at $T0"

SAMPLER_REMOTE=""
if [[ -n "$SSH_USER" ]]; then
    SAMPLER_REMOTE="/tmp/pets2027-${CAMPAIGN_ID}-${RUN_ID}-sampler.csv"
    SAMPLER_DURATION=$(python3 -c "print(float('$DURATION_SEC') + 15.0)")
    SSH_OPTS=(
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
        -o BatchMode=yes
        -i "$SSH_KEY"
    )
    scp "${SSH_OPTS[@]}" "$SCRIPT_DIR/vm_sampler.py" \
        "${SSH_USER}@${VLLM_HOST}:/tmp/pets2027_vm_sampler.py"
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${VLLM_HOST}" \
        "sudo -n setsid --fork python3 -u /tmp/pets2027_vm_sampler.py \
        --interval 5 --duration $SAMPLER_DURATION \
        --start-at-epoch $T0 --skip-ima-bytes \
        --out $SAMPLER_REMOTE </dev/null \
        >/tmp/pets2027-sampler.log 2>&1"
fi

python3 -c "import time; time.sleep(max(0.0, float('$T0') - time.time()))"

echo "[smoke] running $MODEL_KEY load: rps=$RPS prompts=$NUM_PROMPTS"
"$SCRIPT_DIR/bench_serving_wrapper.sh" \
    --host "$VLLM_HOST" \
    --port "$VLLM_PORT" \
    --model-key "$MODEL_KEY" \
    --rps "$RPS" \
    --warmup-sec 0 \
    --duration-sec "$DURATION_SEC" \
    --num-prompts "$NUM_PROMPTS" \
    --out "$RUN_DIR/vllm.json" \
    >"$RUN_DIR/benchmark.log" 2>&1

set +e
wait "$DRIVER_PID"
DRIVER_RC=$?
set -e
trap - EXIT

cp "$STAGE_HOST/attestations.csv" "$RUN_DIR/"
cp "$STAGE_HOST/attestations.jsonl" "$RUN_DIR/"
cp "$STAGE_HOST/attestation_summary.json" "$RUN_DIR/"

if [[ -n "$SAMPLER_REMOTE" ]]; then
    scp "${SSH_OPTS[@]}" "${SSH_USER}@${VLLM_HOST}:$SAMPLER_REMOTE" \
        "$RUN_DIR/system_cvm.csv" || true
fi

GIT_COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
GIT_BRANCH=$(git -C "$REPO_ROOT" branch --show-current 2>/dev/null || echo unknown)
GIT_DIRTY=false
[[ -n "$(git -C "$REPO_ROOT" status --short 2>/dev/null)" ]] && GIT_DIRTY=true
END_EPOCH=$(date +%s)
TLS_VERIFY_INT=$((1 - NO_VERIFY))
python3 - "$RUN_DIR/run.json" <<PY
import json
import sys

value = {
    "schema_version": "pets2027-llm-run-v1",
    "campaign_id": "$CAMPAIGN_ID",
    "run_id": "$RUN_ID",
    "condition": "tdx-vordr",
    "interleave": "$INTERLEAVE",
    "verifier_environment": "$MODE",
    "model_key": "$MODEL_KEY",
    "rps": float("$RPS"),
    "num_prompts": int("$NUM_PROMPTS"),
    "epoch_sec": float("$EPOCH_SEC"),
    "duration_sec": float("$DURATION_SEC"),
    "measurement_start_epoch": float("$T0"),
    "run_end_epoch": float("$END_EPOCH"),
    "tdx_host": "$TDX_HOST",
    "tdx_port": int("$TDX_PORT"),
    "vllm_host": "$VLLM_HOST",
    "vllm_port": int("$VLLM_PORT"),
    "tls_verification": bool(int("$TLS_VERIFY_INT")),
    "require_ak_cert": bool(int("$REQUIRE_AK_CERT")),
    "require_golden": bool(int("$REQUIRE_GOLDEN")),
    "git_commit": "$GIT_COMMIT",
    "git_branch": "$GIT_BRANCH",
    "git_dirty": bool("$GIT_DIRTY" == "true"),
    "attestation_driver_exit_code": int("$DRIVER_RC"),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

(
    cd "$RUN_DIR"
    sha256sum run.json vllm.json attestations.csv attestations.jsonl \
        attestation_summary.json >artifact_hashes.sha256
)

python3 "$SCRIPT_DIR/validate_vtpm_smoke.py" \
    --run-dir "$RUN_DIR" \
    --expect-environment "$MODE"

if [[ "$DRIVER_RC" -ne 0 ]]; then
    echo "attestation driver failed with rc=$DRIVER_RC" >&2
    exit "$DRIVER_RC"
fi

echo "[smoke] complete: $RUN_DIR"
