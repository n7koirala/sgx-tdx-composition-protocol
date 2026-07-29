#!/usr/bin/env bash
# Two-phase wrk2 wrapper: a discarded warmup phase, then the recorded
# measurement phase with --latency (HdrHistogram). The warmup is needed
# because wrk2's percentile output is computed over the entire run and
# can't be post-filtered by timestamp. Two invocations is the cleanest
# way to keep coordinated-omission correction honest while still getting
# stable latency percentiles.
#
# Output: $OUT (a JSON file shaped like vllm.json) + $OUT.txt (raw wrk2
# stdout from the measurement phase) + $OUT.warmup.txt (raw warmup).
#
# Usage:
#   ./wrk2_wrapper.sh \
#       --host 10.0.0.5 --port 8000 \
#       --payload 1kb \
#       --rps 5000 --warmup-sec 30 --duration-sec 300 \
#       --threads 4 --connections 200 \
#       --out wrk.json

set -euo pipefail

HOST=""
PORT=8000
PAYLOAD=""
RPS=""
WARMUP_SEC=30
DURATION_SEC=300
THREADS="${THREADS:-4}"
CONNECTIONS="${CONNECTIONS:-200}"
OUT=""
WRK2_BIN="${WRK2_BIN:-$HOME/wrk2/wrk}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --payload) PAYLOAD="$2"; shift 2 ;;
        --rps) RPS="$2"; shift 2 ;;
        --warmup-sec) WARMUP_SEC="$2"; shift 2 ;;
        --duration-sec) DURATION_SEC="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --wrk2-bin) WRK2_BIN="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

for v in HOST PAYLOAD RPS OUT; do
    [[ -z "${!v}" ]] && { echo "missing --${v,,}" >&2; exit 2; }
done

case "$PAYLOAD" in
    1kb|100kb) URL="http://${HOST}:${PORT}/${PAYLOAD}" ;;
    *) echo "--payload must be 1kb|100kb" >&2; exit 2 ;;
esac

if [[ ! -x "$WRK2_BIN" ]]; then
    echo "wrk2 binary not found at $WRK2_BIN" >&2
    echo "run wrk2_install.sh first, or pass --wrk2-bin" >&2
    exit 2
fi

mkdir -p "$(dirname "$OUT")"

echo "[wrk2] warmup ${WARMUP_SEC}s @ rps=$RPS → $URL"
"$WRK2_BIN" \
    -t "$THREADS" -c "$CONNECTIONS" -d "${WARMUP_SEC}s" \
    -R "$RPS" "$URL" \
    > "$OUT.warmup.txt" 2>&1 || {
        echo "[wrk2] warmup FAILED — see $OUT.warmup.txt" >&2
        tail -n 30 "$OUT.warmup.txt" >&2 || true
        exit 1
    }

echo "[wrk2] measure ${DURATION_SEC}s @ rps=$RPS → $URL"
"$WRK2_BIN" \
    -t "$THREADS" -c "$CONNECTIONS" -d "${DURATION_SEC}s" \
    -R "$RPS" --latency "$URL" \
    > "$OUT.txt" 2>&1 || {
        echo "[wrk2] measure FAILED — see $OUT.txt" >&2
        tail -n 30 "$OUT.txt" >&2 || true
        exit 1
    }

PARSER="$(dirname "$0")/parse_wrk2.py"
python3 "$PARSER" --in "$OUT.txt" --out "$OUT"
