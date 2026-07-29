#!/usr/bin/env bash
# Wraps vLLM's benchmark_serving.py with our defaults:
#   - ShareGPT_V3 unfiltered prompts (downloaded on first run)
#   - open-loop Poisson arrivals at fixed --rps
#   - --warmup-sec warmup that is excluded from summary metrics
#
# Usage:
#   ./bench_serving_wrapper.sh \\
#       --host 10.0.0.5 --port 8000 \\
#       --model-key phi3-mini \\
#       --rps 4 --warmup-sec 60 --duration-sec 300 \\
#       --out vllm.json
#
# Requires vLLM sources checked out somewhere; point to it via
# $VLLM_SRC or --vllm-src.
set -euo pipefail

HOST=""
PORT=8000
MODEL_KEY=""
RPS=""
WARMUP_SEC=60
DURATION_SEC=300
OUT=""
VLLM_SRC="${VLLM_SRC:-$HOME/vllm}"
DATASET_DIR="${DATASET_DIR:-$HOME/datasets}"
NUM_PROMPTS_OVERRIDE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --model-key) MODEL_KEY="$2"; shift 2 ;;
        --rps) RPS="$2"; shift 2 ;;
        --warmup-sec) WARMUP_SEC="$2"; shift 2 ;;
        --duration-sec) DURATION_SEC="$2"; shift 2 ;;
        --num-prompts) NUM_PROMPTS_OVERRIDE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --vllm-src) VLLM_SRC="$2"; shift 2 ;;
        --dataset-dir) DATASET_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

for v in HOST MODEL_KEY RPS OUT; do
    if [[ -z "${!v}" ]]; then echo "missing --${v,,}" >&2; exit 2; fi
done

case "$MODEL_KEY" in
    llama31-8b) MODEL="hugging-quants/Meta-Llama-3.1-8B-Instruct-AWQ-INT4" ;;
    phi3-mini)  MODEL="microsoft/Phi-3-mini-4k-instruct" ;;
    qwen25-7b)  MODEL="Qwen/Qwen2.5-7B-Instruct-AWQ" ;;
    *) echo "--model-key must be llama31-8b, phi3-mini, or qwen25-7b" >&2; exit 2 ;;
esac

SHAREGPT="$DATASET_DIR/ShareGPT_V3_unfiltered_cleaned_split.json"
if [[ ! -f "$SHAREGPT" ]]; then
    echo "[bench] fetching ShareGPT V3 → $SHAREGPT"
    mkdir -p "$DATASET_DIR"
    curl -fL --retry 3 -o "$SHAREGPT" \
        "https://huggingface.co/datasets/anon8231489123/ShareGPT_Vicuna_unfiltered/resolve/main/ShareGPT_V3_unfiltered_cleaned_split.json"
fi

BENCH="$VLLM_SRC/benchmarks/benchmark_serving.py"
if [[ ! -f "$BENCH" ]]; then
    echo "[bench] benchmark_serving.py not found at $BENCH" >&2
    echo "        set VLLM_SRC or pass --vllm-src /path/to/vllm" >&2
    exit 2
fi

# Poisson open-loop. benchmark_serving.py expects --request-rate (req/s)
# and --num-prompts total. We convert wall-clock duration → prompt count,
# which assumes the server can keep up with arrival rate. On CPU that's
# often wrong (bench waits for every queued request to drain), so
# --num-prompts lets callers override with a hard cap.
if [[ -n "$NUM_PROMPTS_OVERRIDE" ]]; then
    NUM_PROMPTS="$NUM_PROMPTS_OVERRIDE"
else
    NUM_PROMPTS=$(python3 -c "import math; print(max(1, int(math.ceil($RPS * ($WARMUP_SEC + $DURATION_SEC)))))")
fi

mkdir -p "$(dirname "$OUT")"
echo "[bench] host=$HOST:$PORT model=$MODEL rps=$RPS n=$NUM_PROMPTS out=$OUT"

python3 "$BENCH" \
    --backend openai \
    --base-url "http://${HOST}:${PORT}" \
    --endpoint /v1/completions \
    --model "$MODEL" \
    --dataset-name sharegpt \
    --dataset-path "$SHAREGPT" \
    --num-prompts "$NUM_PROMPTS" \
    --request-rate "$RPS" \
    --save-result \
    --result-filename "$OUT" \
    --metadata "warmup_sec=${WARMUP_SEC}" "duration_sec=${DURATION_SEC}" \
    --seed 20260421

echo "[bench] done → $OUT"
