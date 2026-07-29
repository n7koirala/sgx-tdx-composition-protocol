#!/usr/bin/env bash
# One-cell orchestrator for the NGINX-workload evaluation. Mirrors the
# LLM workload's run_experiment.sh — same t0 alignment, same staged
# helpers, same teardown — but swaps:
#   * §1 server launch:  vLLM   → nginx (Docker, host net)
#   * §7 load generator: vLLM bench → wrk2 (two-phase: warmup then measure)
#
# The reusable target/driver helpers (vm_sampler.py, attestation_driver.py,
# update_injector.py, provision_vms.sh) are taken from ../llm_workload/
# unchanged.
#
# Usage:
#   ./run_experiment.sh \
#       --condition tdx-vordr \
#       --payload 1kb \
#       --epoch-sec 30 \
#       --log-size warm --interleave with-updates \
#       --target-host 10.0.0.5 --target-user nkoirala \
#       --ssh-key ~/.ssh/vordr_id_rsa \
#       --rps 5000 --warmup-sec 30 --duration-sec 300 \
#       --out-dir ../results/nginx/2026-04-25/tdx-vordr/30s_warm_updates_1kb

set -euo pipefail

CONDITION=""
PAYLOAD=""
EPOCH_SEC=""
LOG_SIZE="cold"
INTERLEAVE="no-updates"
TARGET_HOST=""
TARGET_USER=""
SSH_KEY=""
RPS=""
WARMUP_SEC=30
DURATION_SEC=300
THREADS="${THREADS:-4}"
CONNECTIONS="${CONNECTIONS:-200}"
OUT_DIR=""
NGINX_PORT=8000
TDX_AGENT_PORT=8443
CA_CERT=""
AGENT_DIR="/home/\$USER/sgx-tdx-composition-protocol/research/incremental_attestation"
LLM_DIR=""
SYNC_REPO=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --condition) CONDITION="$2"; shift 2 ;;
        --payload) PAYLOAD="$2"; shift 2 ;;
        --epoch-sec) EPOCH_SEC="$2"; shift 2 ;;
        --log-size) LOG_SIZE="$2"; shift 2 ;;
        --interleave) INTERLEAVE="$2"; shift 2 ;;
        --target-host) TARGET_HOST="$2"; shift 2 ;;
        --target-user) TARGET_USER="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --rps) RPS="$2"; shift 2 ;;
        --warmup-sec) WARMUP_SEC="$2"; shift 2 ;;
        --duration-sec) DURATION_SEC="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --nginx-port) NGINX_PORT="$2"; shift 2 ;;
        --tdx-agent-port) TDX_AGENT_PORT="$2"; shift 2 ;;
        --ca-cert) CA_CERT="$2"; shift 2 ;;
        --agent-dir) AGENT_DIR="$2"; shift 2 ;;
        --llm-dir) LLM_DIR="$2"; shift 2 ;;
        --no-sync-repo) SYNC_REPO=0; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

for v in CONDITION PAYLOAD TARGET_HOST TARGET_USER SSH_KEY RPS OUT_DIR; do
    [[ -z "${!v}" ]] && { echo "missing --${v,,}" >&2; exit 2; }
done
if [[ "$CONDITION" == "tdx-vordr" && -z "$EPOCH_SEC" ]]; then
    echo "--epoch-sec required for tdx-vordr" >&2; exit 2
fi
case "$INTERLEAVE" in
    no-updates|with-updates) ;;
    *) echo "--interleave must be no-updates|with-updates" >&2; exit 2 ;;
esac
case "$PAYLOAD" in 1kb|100kb) ;; *) echo "--payload must be 1kb|100kb" >&2; exit 2 ;; esac

mkdir -p "$OUT_DIR"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVAL_DIR="$REPO_ROOT/evaluation/nginx_workload"
[[ -z "$LLM_DIR" ]] && LLM_DIR="$REPO_ROOT/evaluation/llm_workload"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -i "$SSH_KEY")

ssh_exec() { ssh "${SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_HOST}" "$@"; }
scp_to()   { scp "${SSH_OPTS[@]}" "$@" "${TARGET_USER}@${TARGET_HOST}:/tmp/"; }
scp_from() { scp "${SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_HOST}:$1" "$2"; }

# ─── 0a. SSH preflight ─────────────────────────────────────────────────
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

# ─── 0b. Sync latest agent code WEN → TDX ─────────────────────────────
# The snapshot freezes repo state at creation time. Anything modified in
# research/incremental_attestation/ (agent + helpers) or in
# research/sgx-tdx-attestation/{common,certs}/ since the snapshot was
# baked would otherwise leave TDX running stale code — most dangerous
# is a cert rotation where the agent's server.crt no longer chains to
# the CA the attestation_driver on WEN trusts. Light rsync of just
# those subtrees keeps every cell consistent with WEN's working tree.
if [[ "$SYNC_REPO" == "1" ]]; then
    echo "[orch] syncing agent code WEN → TDX"
    RSYNC_SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                   -o BatchMode=yes -i $SSH_KEY"
    rsync -az --no-owner --no-group \
        --exclude='__pycache__/' --exclude='*.pyc' \
        --exclude='charts*/' --exclude='prior_csvs/' --exclude='*.csv' \
        --exclude='*.tex' --exclude='*.pdf' --exclude='results_*.csv' \
        -e "$RSYNC_SSH" \
        "$REPO_ROOT/research/incremental_attestation/" \
        "${TARGET_USER}@${TARGET_HOST}:sgx-tdx-composition-protocol/research/incremental_attestation/"
    rsync -az --no-owner --no-group \
        --exclude='__pycache__/' --exclude='*.pyc' \
        --exclude='sgx-verifier/' --exclude='*.csv' --exclude='*.pdf' \
        -e "$RSYNC_SSH" \
        "$REPO_ROOT/research/sgx-tdx-attestation/" \
        "${TARGET_USER}@${TARGET_HOST}:sgx-tdx-composition-protocol/research/sgx-tdx-attestation/"
fi

# ─── 0c. Stage helper scripts on target ────────────────────────────────
scp_to "$EVAL_DIR/nginx_server_launch.sh" \
       "$EVAL_DIR/nginx.conf" \
       "$LLM_DIR/vm_sampler.py"
ssh_exec "chmod +x /tmp/nginx_server_launch.sh"

# Capture NIC offload state for forensics — TDX may disable offloads,
# which would partially explain native↔tdx-only deltas if not noted.
ssh_exec "ethtool -k eth0 2>/dev/null || ethtool -k ens4 2>/dev/null || true" \
    > "$OUT_DIR/ethtool_offloads.txt" 2>&1 || true

# ─── 1. Launch nginx on target ─────────────────────────────────────────
echo "[orch] launching nginx on $TARGET_HOST:$NGINX_PORT"
ssh_exec "/tmp/nginx_server_launch.sh --port $NGINX_PORT --config /tmp/nginx.conf"

# ─── 2. Launch attestation agent (tdx-vordr only) ──────────────────────
if [[ "$CONDITION" == "tdx-vordr" ]]; then
    echo "[orch] launching CVM attestation agent from $AGENT_DIR"
    timeout 15 ssh "${SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_HOST}" \
        "cd $AGENT_DIR && sudo -n setsid --fork python3 -u cvm_attestation_agent.py \
            --port $TDX_AGENT_PORT </dev/null >/tmp/agent.log 2>&1" \
        || echo "[orch] agent launch ssh returned non-zero (probing)"

    for i in 1 2 3 4 5 6 7 8; do
        if ssh_exec "sudo -n ss -tlnp 2>/dev/null | grep -q ':${TDX_AGENT_PORT} '"; then
            echo "[orch] agent confirmed listening on :$TDX_AGENT_PORT"
            break
        fi
        if [[ $i == 8 ]]; then
            echo "[orch] agent not listening after 16s — see /tmp/agent.log on CVM" >&2
            ssh_exec "tail -40 /tmp/agent.log" >&2 || true
            exit 1
        fi
        sleep 2
    done
fi

# ─── 3. Warm IMA log if requested ──────────────────────────────────────
if [[ "$LOG_SIZE" == "warm" ]]; then
    echo "[orch] warming IMA log to 100K entries"
    ssh_exec "cd $AGENT_DIR && sudo -n python3 generate_ima_baseline.py --target 100000 </dev/null" || \
        echo "[orch] WARN: warm failed — continuing with current log size" >&2
fi

IMA_START=$(ssh_exec "sudo -n cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo -1" | tr -d '\r')
echo "[orch] IMA entry count at t0: $IMA_START"

# ─── Coordinate t0 across all components ───────────────────────────────
T0=$(python3 -c "import time; print(time.time() + 10)")
echo "[orch] aligning all components at t0=$T0"

cat > "$OUT_DIR/run.json" <<EOF
{
  "condition": "$CONDITION",
  "payload": "$PAYLOAD",
  "epoch_sec": "${EPOCH_SEC:-null}",
  "log_size": "$LOG_SIZE",
  "interleave": "$INTERLEAVE",
  "rps": $RPS,
  "warmup_sec": $WARMUP_SEC,
  "duration_sec": $DURATION_SEC,
  "threads": $THREADS,
  "connections": $CONNECTIONS,
  "t0_epoch": $T0,
  "target_host": "$TARGET_HOST",
  "ima_count_start": $IMA_START,
  "ima_count_end": null
}
EOF

# ─── 4. Sampler on target (background) ─────────────────────────────────
SAMPLER_DURATION=$(python3 -c "print($WARMUP_SEC + $DURATION_SEC + 15)")
ssh_exec "sudo -n nohup python3 -u /tmp/vm_sampler.py \
            --interval 5 --duration $SAMPLER_DURATION \
            --start-at-epoch $T0 \
            --out /tmp/sampler.csv </dev/null >/tmp/sampler.out 2>&1 &"

# ─── 5. Attestation driver (background, tdx-vordr only) ────────────────
ATTEST_DURATION=$(python3 -c "print($WARMUP_SEC + $DURATION_SEC + 15)")
if [[ "$CONDITION" == "tdx-vordr" ]]; then
    CA_FLAG=""
    [[ -n "$CA_CERT" ]] && CA_FLAG="--ca-cert $CA_CERT"
    # shellcheck disable=SC2086
    nohup python3 "$LLM_DIR/attestation_driver.py" \
        --tdx-host "$TARGET_HOST" --tdx-port "$TDX_AGENT_PORT" \
        --epoch-sec "$EPOCH_SEC" --duration-sec "$ATTEST_DURATION" \
        --start-at-epoch "$T0" \
        --no-verify $CA_FLAG \
        --out "$OUT_DIR/attest.csv" \
        > "$OUT_DIR/attest.log" 2>&1 &
    ATTEST_PID=$!
    echo "[orch] attestation driver pid=$ATTEST_PID"
fi

# ─── 6. Update injector (background, with-updates only) ────────────────
if [[ "$INTERLEAVE" == "with-updates" ]]; then
    T_APT=$(python3 -c "print($WARMUP_SEC + 120)")
    T_PIP=$(python3 -c "print($WARMUP_SEC + 300)")
    nohup python3 "$LLM_DIR/update_injector.py" \
        --start-at-epoch "$T0" \
        --t-apt-sec "$T_APT" --t-pip-sec "$T_PIP" \
        --via-ssh --ssh-host "$TARGET_HOST" \
        --ssh-user "$TARGET_USER" --ssh-key-file "$SSH_KEY" \
        --out "$OUT_DIR/updates.csv" \
        > "$OUT_DIR/updates.log" 2>&1 &
    INJECT_PID=$!
    echo "[orch] update injector pid=$INJECT_PID"
fi

# ─── 7. Align to t0, then run wrk2 (foreground) ────────────────────────
python3 -c "import time; d=$T0 - time.time(); time.sleep(max(0, d))"

echo "[orch] launching wrk2 (rps=$RPS warmup=${WARMUP_SEC}s dur=${DURATION_SEC}s payload=$PAYLOAD)"
"$EVAL_DIR/wrk2_wrapper.sh" \
    --host "$TARGET_HOST" --port "$NGINX_PORT" \
    --payload "$PAYLOAD" \
    --rps "$RPS" \
    --warmup-sec "$WARMUP_SEC" --duration-sec "$DURATION_SEC" \
    --threads "$THREADS" --connections "$CONNECTIONS" \
    --out "$OUT_DIR/wrk.json" \
    > "$OUT_DIR/wrk.log" 2>&1

# ─── 8. Wait for background jobs and collect artifacts ─────────────────
if [[ "$CONDITION" == "tdx-vordr" ]]; then
    wait "$ATTEST_PID" || true
fi
if [[ "$INTERLEAVE" == "with-updates" ]]; then
    wait "$INJECT_PID" || true
fi

scp_from "/tmp/sampler.csv"        "$OUT_DIR/sampler.csv"     || true
scp_from "/tmp/nginx_${NGINX_PORT}.log" "$OUT_DIR/nginx_server.log" || true
[[ "$CONDITION" == "tdx-vordr" ]] && \
    scp_from "/tmp/agent.log" "$OUT_DIR/agent.log" || true

IMA_END=$(ssh_exec "sudo -n cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo -1" | tr -d '\r')

# Tear down nginx via the marker file (matches LLM teardown convention).
ssh_exec "bash -c 'f=/tmp/nginx_${NGINX_PORT}.pid; [[ -f \$f ]] || exit 0; \
    v=\$(cat \$f); \
    if [[ \$v == docker:* ]]; then docker rm -f \"\${v#docker:}\" >/dev/null 2>&1 || true; \
    else kill \"\$v\" 2>/dev/null || true; fi'"
[[ "$CONDITION" == "tdx-vordr" ]] && \
    ssh_exec "sudo pkill -f cvm_attestation_agent.py || true"

# ─── 9. Final per-run manifest ─────────────────────────────────────────
cat > "$OUT_DIR/run.json" <<EOF
{
  "condition": "$CONDITION",
  "payload": "$PAYLOAD",
  "epoch_sec": "${EPOCH_SEC:-null}",
  "log_size": "$LOG_SIZE",
  "interleave": "$INTERLEAVE",
  "rps": $RPS,
  "warmup_sec": $WARMUP_SEC,
  "duration_sec": $DURATION_SEC,
  "threads": $THREADS,
  "connections": $CONNECTIONS,
  "t0_epoch": $T0,
  "target_host": "$TARGET_HOST",
  "ima_count_start": $IMA_START,
  "ima_count_end": $IMA_END
}
EOF

echo "[orch] done → $OUT_DIR"
