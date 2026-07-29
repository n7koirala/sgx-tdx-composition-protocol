#!/usr/bin/env bash
# Launches a vLLM OpenAI-compatible server on CPU.
#
# Two launch backends:
#   default        → `python3 -m vllm.entrypoints.openai.api_server` (pip-install)
#   --via-docker   → `docker run vllm/vllm-openai:latest-cpu`
#
# Picks model via --model-key:
#   llama31-8b  → meta-llama/Llama-3.1-8B-Instruct (AWQ 4-bit)
#   phi3-mini   → microsoft/Phi-3-mini-4k-instruct
#
# Intended to be run on the target VM (native | tdx-only | tdx-vordr).
# Waits for the server to become ready on /v1/models before exiting.
#
# Writes a marker file /tmp/vllm_${PORT}.pid containing either:
#   <numeric pid>            (direct backend — kill with `kill`)
#   docker:<container-name>  (docker backend — teardown with `docker rm -f`)
#
# Usage:
#   ./vllm_server_launch.sh --model-key phi3-mini --port 8000 --via-docker

set -euo pipefail

MODEL_KEY=""
PORT=8000
LOG=""
MAX_MODEL_LEN=4096
DTYPE="bfloat16"
EXTRA_ARGS=""
VIA_DOCKER=0
DOCKER_IMAGE="${VLLM_DOCKER_IMAGE:-vllm-cpu:local}"
HF_CACHE="${HF_CACHE:-$HOME/.cache/huggingface}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --model-key) MODEL_KEY="$2"; shift 2 ;;
        --port)      PORT="$2"; shift 2 ;;
        --log)       LOG="$2"; shift 2 ;;
        --max-model-len) MAX_MODEL_LEN="$2"; shift 2 ;;
        --dtype)     DTYPE="$2"; shift 2 ;;
        --extra)     EXTRA_ARGS="$2"; shift 2 ;;
        --via-docker) VIA_DOCKER=1; shift ;;
        --docker-image) DOCKER_IMAGE="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "$MODEL_KEY" in
    llama31-8b)
        MODEL="hugging-quants/Meta-Llama-3.1-8B-Instruct-AWQ-INT4"
        QUANT="awq"
        ;;
    phi3-mini)
        MODEL="microsoft/Phi-3-mini-4k-instruct"
        QUANT=""
        ;;
    qwen25-7b)
        MODEL="Qwen/Qwen2.5-7B-Instruct-AWQ"
        QUANT="awq"
        ;;
    *)
        echo "--model-key must be one of: llama31-8b, phi3-mini, qwen25-7b" >&2
        exit 2
        ;;
esac

if [[ -z "$LOG" ]]; then
    LOG="/tmp/vllm_${MODEL_KEY}_${PORT}.log"
fi

QUANT_FLAG=""
if [[ -n "$QUANT" ]]; then
    QUANT_FLAG="--quantization $QUANT"
fi

PID_FILE="/tmp/vllm_${PORT}.pid"

if [[ "$VIA_DOCKER" == "1" ]]; then
    CONTAINER="vllm-${MODEL_KEY}-${PORT}"
    echo "[vllm] launching $DOCKER_IMAGE → $MODEL (container=$CONTAINER)"
    echo "[vllm] log: $LOG"

    # Ensure HF cache exists so downloads persist across runs.
    mkdir -p "$HF_CACHE"

    # Remove any stale container of the same name.
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

    # shellcheck disable=SC2086
    docker run -d --name "$CONTAINER" \
        --network host \
        --ipc=host \
        -v "$HF_CACHE":/root/.cache/huggingface \
        -e OMP_NUM_THREADS="${OMP_NUM_THREADS:-$(nproc)}" \
        -e VLLM_CPU_KVCACHE_SPACE="${VLLM_CPU_KVCACHE_SPACE:-4}" \
        -e HUGGING_FACE_HUB_TOKEN="${HF_TOKEN:-}" \
        "$DOCKER_IMAGE" \
        "$MODEL" \
        --dtype "$DTYPE" \
        --max-model-len "$MAX_MODEL_LEN" \
        --port "$PORT" \
        $QUANT_FLAG $EXTRA_ARGS \
        > /dev/null

    echo "docker:$CONTAINER" > "$PID_FILE"
    echo "[vllm] container started: $CONTAINER"

    # Stream container logs to $LOG in the background so a regular
    # `tail $LOG` on the host still works.
    ( docker logs -f "$CONTAINER" > "$LOG" 2>&1 ) &

    DEADLINE=$(( $(date +%s) + 1800 ))   # 30 min for first-time model DL
    while [[ $(date +%s) -lt $DEADLINE ]]; do
        if curl -sf "http://127.0.0.1:${PORT}/v1/models" > /dev/null; then
            echo "[vllm] ready on :${PORT}"
            exit 0
        fi
        if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
            echo "[vllm] container died — see $LOG" >&2
            tail -n 60 "$LOG" >&2 || true
            exit 1
        fi
        sleep 3
    done

    echo "[vllm] timed out waiting for readiness" >&2
    exit 1
fi

# ───── Direct (non-docker) backend ────────────────────────────────────
export VLLM_TARGET_DEVICE=cpu
export VLLM_CPU_KVCACHE_SPACE=${VLLM_CPU_KVCACHE_SPACE:-4}
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-$(nproc)}

echo "[vllm] launching $MODEL on port $PORT (cpu, dtype=$DTYPE)"
echo "[vllm] log: $LOG"

# shellcheck disable=SC2086
nohup vllm serve "$MODEL" \
    --dtype "$DTYPE" \
    --max-model-len "$MAX_MODEL_LEN" \
    --port "$PORT" \
    $QUANT_FLAG $EXTRA_ARGS \
    > "$LOG" 2>&1 &
VLLM_PID=$!
echo "$VLLM_PID" > "$PID_FILE"
echo "[vllm] pid=$VLLM_PID"

DEADLINE=$(( $(date +%s) + 900 ))
while [[ $(date +%s) -lt $DEADLINE ]]; do
    if curl -sf "http://127.0.0.1:${PORT}/v1/models" > /dev/null; then
        echo "[vllm] ready on :${PORT}"
        exit 0
    fi
    if ! kill -0 "$VLLM_PID" 2>/dev/null; then
        echo "[vllm] process died — see $LOG" >&2
        tail -n 40 "$LOG" >&2 || true
        exit 1
    fi
    sleep 3
done

echo "[vllm] timed out waiting for readiness" >&2
exit 1
