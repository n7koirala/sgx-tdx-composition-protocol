#!/usr/bin/env bash
# One-run orchestrator for the LLM-workload evaluation.
#
# Assumes the target VM is already provisioned (see provision_vms.sh).
# Launches, in order:
#   1. vLLM server on target
#   2. (tdx-vordr only) CVM attestation agent
#   3. (warm-log runs) runs generate_ima_baseline.py on target to bring
#      the IMA log to ~100 K entries before measurement begins
#   4. In-VM sampler on target
#   5. Attestation driver on *this* host (the load-gen VM)
#   6. Load generator (benchmark_serving.py via bench_serving_wrapper.sh)
#   7. (with-updates only) update_injector.py firing apt@120s, pip@300s
# Then collects artifacts into an output directory.
#
# Usage:
#   ./run_experiment.sh \\
#       --condition tdx-vordr \\
#       --model-key phi3-mini \\
#       --epoch-sec 30 \\
#       --log-size warm \\
#       --interleave with-updates \\
#       --target-host 10.0.0.5 --target-user nkoirala --ssh-key ~/.ssh/id_rsa \\
#       --rps 4 \\
#       --out-dir ../results/llm/2026-04-21T14-00/tdx-vordr/30s_warm_updates \\
#       [--cvm-id c3-foo-123]   # only if condition=tdx-vordr via asp_client

set -euo pipefail

CONDITION=""
MODEL_KEY=""
EPOCH_SEC=""
LOG_SIZE="cold"          # cold | warm
INTERLEAVE="steady"      # steady | with-updates
TARGET_HOST=""
TARGET_USER=""
SSH_KEY=""
RPS=""
WARMUP_SEC=60
DURATION_SEC=300
OUT_DIR=""
CVM_ID=""
TDX_AGENT_PORT=8443
VLLM_PORT=8000
CA_CERT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --condition) CONDITION="$2"; shift 2 ;;
        --model-key) MODEL_KEY="$2"; shift 2 ;;
        --epoch-sec) EPOCH_SEC="$2"; shift 2 ;;
        --log-size)  LOG_SIZE="$2"; shift 2 ;;
        --interleave) INTERLEAVE="$2"; shift 2 ;;
        --target-host) TARGET_HOST="$2"; shift 2 ;;
        --target-user) TARGET_USER="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --rps) RPS="$2"; shift 2 ;;
        --warmup-sec) WARMUP_SEC="$2"; shift 2 ;;
        --duration-sec) DURATION_SEC="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --cvm-id) CVM_ID="$2"; shift 2 ;;
        --tdx-agent-port) TDX_AGENT_PORT="$2"; shift 2 ;;
        --vllm-port) VLLM_PORT="$2"; shift 2 ;;
        --ca-cert) CA_CERT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

for v in CONDITION MODEL_KEY TARGET_HOST TARGET_USER SSH_KEY RPS OUT_DIR; do
    [[ -z "${!v}" ]] && { echo "missing --${v,,}" >&2; exit 2; }
done
if [[ "$CONDITION" == "tdx-vordr" && -z "$EPOCH_SEC" ]]; then
    echo "--epoch-sec required for tdx-vordr" >&2; exit 2
fi

mkdir -p "$OUT_DIR"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVAL_DIR="$REPO_ROOT/evaluation/llm_workload"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -i "$SSH_KEY")

ssh_exec() { ssh "${SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_HOST}" "$@"; }
scp_to()   { scp "${SSH_OPTS[@]}" "$@" "${TARGET_USER}@${TARGET_HOST}:/tmp/"; }
scp_from() { scp "${SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_HOST}:$1" "$2"; }

# ─── 0a. SSH preflight — wait for target VM to accept connections ──────
echo "[orch] probing ssh to ${TARGET_USER}@${TARGET_HOST}"
PROBE_DEADLINE=$(( $(date +%s) + 180 ))
while : ; do
    if ssh -o ConnectTimeout=5 "${SSH_OPTS[@]}" \
            "${TARGET_USER}@${TARGET_HOST}" true 2>/dev/null; then
        echo "[orch] ssh reachable"
        break
    fi
    if [[ $(date +%s) -ge $PROBE_DEADLINE ]]; then
        echo "[orch] ssh probe timed out after 180s — aborting" >&2
        exit 1
    fi
    sleep 5
done

# ─── 0. Stage helper scripts on target VM ──────────────────────────────
scp_to "$EVAL_DIR/vllm_server_launch.sh" "$EVAL_DIR/vm_sampler.py"
ssh_exec "chmod +x /tmp/vllm_server_launch.sh"

# ─── 1. Launch vLLM on target ──────────────────────────────────────────
echo "[orch] launching vLLM on $TARGET_HOST"
ssh_exec "/tmp/vllm_server_launch.sh --model-key $MODEL_KEY --port $VLLM_PORT --log /tmp/vllm.log"

# ─── 2. Launch attestation agent (tdx-vordr only) ──────────────────────
if [[ "$CONDITION" == "tdx-vordr" ]]; then
    echo "[orch] launching CVM attestation agent"
    # The agent code is expected to already be present on the CVM
    # (placed there by the commissioning phase); we just start it.
    ssh_exec "sudo nohup python3 /opt/vordr/cvm_attestation_agent.py \
                --port $TDX_AGENT_PORT > /tmp/agent.log 2>&1 &"
    sleep 3
fi

# ─── 3. Warm IMA log if requested ──────────────────────────────────────
if [[ "$LOG_SIZE" == "warm" ]]; then
    echo "[orch] warming IMA log to 100K entries"
    ssh_exec "sudo python3 /opt/vordr/generate_ima_baseline.py --target 100000" || \
        echo "[orch] WARN: warm failed — continuing with current log size" >&2
fi

# Snapshot IMA count at t0 so the results file records starting size.
IMA_START=$(ssh_exec "cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo -1" | tr -d '\r')
echo "[orch] IMA entry count at t0: $IMA_START"

# ─── Coordinate t0 across all components ───────────────────────────────
# Add a small buffer so every component has time to launch and sleep to
# the alignment point.
T0=$(python3 -c "import time; print(time.time() + 10)")
echo "[orch] aligning all components at t0=$T0"

# ─── 4. Sampler on target (background) ─────────────────────────────────
SAMPLER_DURATION=$(python3 -c "print($WARMUP_SEC + $DURATION_SEC + 15)")
ssh_exec "nohup python3 /tmp/vm_sampler.py \
            --interval 5 --duration $SAMPLER_DURATION \
            --start-at-epoch $T0 \
            --out /tmp/sampler.csv > /tmp/sampler.out 2>&1 &"

# ─── 5. Attestation driver locally (background, only if tdx-vordr) ─────
ATTEST_DURATION=$(python3 -c "print($WARMUP_SEC + $DURATION_SEC + 15)")
if [[ "$CONDITION" == "tdx-vordr" ]]; then
    CA_FLAG=""
    [[ -n "$CA_CERT" ]] && CA_FLAG="--ca-cert $CA_CERT"
    # shellcheck disable=SC2086
    nohup python3 "$EVAL_DIR/attestation_driver.py" \
        --tdx-host "$TARGET_HOST" --tdx-port "$TDX_AGENT_PORT" \
        --epoch-sec "$EPOCH_SEC" --duration-sec "$ATTEST_DURATION" \
        --start-at-epoch "$T0" \
        --no-verify $CA_FLAG \
        --out "$OUT_DIR/attest.csv" \
        > "$OUT_DIR/attest.log" 2>&1 &
    ATTEST_PID=$!
    echo "[orch] attestation driver pid=$ATTEST_PID"
fi

# ─── 6. Update injector (background, only if with-updates) ─────────────
if [[ "$INTERLEAVE" == "with-updates" ]]; then
    # Offsets are measured from end of warmup.
    T_APT=$(python3 -c "print($WARMUP_SEC + 120)")
    T_PIP=$(python3 -c "print($WARMUP_SEC + 300)")
    nohup python3 "$EVAL_DIR/update_injector.py" \
        --start-at-epoch "$T0" \
        --t-apt-sec "$T_APT" --t-pip-sec "$T_PIP" \
        --via-ssh --ssh-host "$TARGET_HOST" \
        --ssh-user "$TARGET_USER" --ssh-key-file "$SSH_KEY" \
        --out "$OUT_DIR/updates.csv" \
        > "$OUT_DIR/updates.log" 2>&1 &
    INJECT_PID=$!
    echo "[orch] update injector pid=$INJECT_PID"
fi

# ─── 7. Align to t0, then run load generator (foreground) ──────────────
python3 -c "import time; d=$T0 - time.time(); time.sleep(max(0, d))"

echo "[orch] launching load generator (rps=$RPS warmup=${WARMUP_SEC}s dur=${DURATION_SEC}s)"
"$EVAL_DIR/bench_serving_wrapper.sh" \
    --host "$TARGET_HOST" --port "$VLLM_PORT" \
    --model-key "$MODEL_KEY" \
    --rps "$RPS" \
    --warmup-sec "$WARMUP_SEC" --duration-sec "$DURATION_SEC" \
    --out "$OUT_DIR/vllm.json" \
    > "$OUT_DIR/bench.log" 2>&1

# ─── 8. Wait for background jobs and collect artifacts ─────────────────
if [[ "$CONDITION" == "tdx-vordr" ]]; then
    wait "$ATTEST_PID" || true
fi
if [[ "$INTERLEAVE" == "with-updates" ]]; then
    wait "$INJECT_PID" || true
fi

# Fetch sampler + agent logs off the target.
scp_from "/tmp/sampler.csv" "$OUT_DIR/sampler.csv" || true
scp_from "/tmp/vllm.log"    "$OUT_DIR/vllm_server.log" || true
[[ "$CONDITION" == "tdx-vordr" ]] && \
    scp_from "/tmp/agent.log" "$OUT_DIR/agent.log" || true

IMA_END=$(ssh_exec "cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo -1" | tr -d '\r')

# Stop vLLM on target.
ssh_exec "kill \$(cat /tmp/vllm_${VLLM_PORT}.pid) 2>/dev/null || true"
[[ "$CONDITION" == "tdx-vordr" ]] && \
    ssh_exec "sudo pkill -f cvm_attestation_agent.py || true"

# ─── 9. Per-run manifest ───────────────────────────────────────────────
cat > "$OUT_DIR/run.json" <<EOF
{
  "condition": "$CONDITION",
  "model_key": "$MODEL_KEY",
  "epoch_sec": "${EPOCH_SEC:-null}",
  "log_size": "$LOG_SIZE",
  "interleave": "$INTERLEAVE",
  "rps": $RPS,
  "warmup_sec": $WARMUP_SEC,
  "duration_sec": $DURATION_SEC,
  "t0_epoch": $T0,
  "target_host": "$TARGET_HOST",
  "ima_count_start": $IMA_START,
  "ima_count_end": $IMA_END
}
EOF

echo "[orch] done → $OUT_DIR"
