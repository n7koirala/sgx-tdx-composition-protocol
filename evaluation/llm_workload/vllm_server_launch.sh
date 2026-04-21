#!/usr/bin/env bash
# Launches a vLLM OpenAI-compatible server on CPU.
#
# Picks model via --model-key:
#   llama31-8b  → meta-llama/Llama-3.1-8B-Instruct (AWQ 4-bit)
#   phi3-mini   → microsoft/Phi-3-mini-4k-instruct
#
# Intended to be run on the target VM (native | tdx-only | tdx-vordr).
# Waits for the server to become ready on /v1/models before exiting.
#
# Usage:
#   ./vllm_server_launch.sh --model-key phi3-mini --port 8000 --log vllm.log

set -euo pipefail

MODEL_KEY=""
PORT=8000
LOG=""
MAX_MODEL_LEN=4096
DTYPE="bfloat16"
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --model-key) MODEL_KEY="$2"; shift 2 ;;
        --port)      PORT="$2"; shift 2 ;;
        --log)       LOG="$2"; shift 2 ;;
        --max-model-len) MAX_MODEL_LEN="$2"; shift 2 ;;
        --dtype)     DTYPE="$2"; shift 2 ;;
        --extra)     EXTRA_ARGS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "$MODEL_KEY" in
    llama31-8b)
        MODEL="TheBloke/Meta-Llama-3-8B-Instruct-AWQ"
        QUANT="awq"
        ;;
    phi3-mini)
        MODEL="microsoft/Phi-3-mini-4k-instruct"
        QUANT=""
        ;;
    *)
        echo "--model-key must be one of: llama31-8b, phi3-mini" >&2
        exit 2
        ;;
esac

if [[ -z "$LOG" ]]; then
    LOG="/tmp/vllm_${MODEL_KEY}_${PORT}.log"
fi

# CPU device + conservative thread cap so vLLM doesn't starve the
# attestation agent / sampler.
export VLLM_TARGET_DEVICE=cpu
export VLLM_CPU_KVCACHE_SPACE=${VLLM_CPU_KVCACHE_SPACE:-4}
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-$(nproc)}

QUANT_FLAG=""
if [[ -n "$QUANT" ]]; then
    QUANT_FLAG="--quantization $QUANT"
fi

echo "[vllm] launching $MODEL on port $PORT (cpu, dtype=$DTYPE)"
echo "[vllm] log: $LOG"

# shellcheck disable=SC2086
nohup python3 -m vllm.entrypoints.openai.api_server \
    --model "$MODEL" \
    --device cpu \
    --dtype "$DTYPE" \
    --max-model-len "$MAX_MODEL_LEN" \
    --port "$PORT" \
    $QUANT_FLAG $EXTRA_ARGS \
    > "$LOG" 2>&1 &
VLLM_PID=$!
echo $VLLM_PID > "/tmp/vllm_${PORT}.pid"
echo "[vllm] pid=$VLLM_PID"

# Wait for readiness. CPU cold-start of 8B quantized is slow (minutes).
DEADLINE=$(( $(date +%s) + 900 ))
while [[ $(date +%s) -lt $DEADLINE ]]; do
    if curl -sf "http://127.0.0.1:${PORT}/v1/models" > /dev/null; then
        echo "[vllm] ready on :${PORT}"
        exit 0
    fi
    if ! kill -0 $VLLM_PID 2>/dev/null; then
        echo "[vllm] process died — see $LOG" >&2
        tail -n 40 "$LOG" >&2 || true
        exit 1
    fi
    sleep 3
done

echo "[vllm] timed out waiting for readiness" >&2
exit 1
