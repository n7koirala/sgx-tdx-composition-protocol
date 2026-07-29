#!/usr/bin/env bash
# Launches nginx (Docker, host networking) on the target VM with two
# fixed-size static routes:
#   /1kb   → 1024 bytes
#   /100kb → 102400 bytes
#
# Also tunes kernel TCP/socket limits required for high-RPS small-payload
# tests. Without this tuning, native saturation is artificially low and
# the TDX-tax delta is contaminated by SYN drops / ephemeral-port
# exhaustion rather than real TDX overhead.
#
# Writes /tmp/nginx_${PORT}.pid containing `docker:<container-name>` so
# run_experiment.sh teardown matches the LLM workload's marker scheme.
#
# Usage (on target VM):
#   ./nginx_server_launch.sh --port 8000

set -euo pipefail

PORT=8000
LOG=""
IMAGE="nginx:1.27-alpine"
CONFIG_PATH="${CONFIG_PATH:-/tmp/nginx.conf}"
STATIC_DIR="${STATIC_DIR:-/tmp/nginx_static}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)        PORT="$2"; shift 2 ;;
        --log)         LOG="$2"; shift 2 ;;
        --image)       IMAGE="$2"; shift 2 ;;
        --config)      CONFIG_PATH="$2"; shift 2 ;;
        --static-dir)  STATIC_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$LOG" ]] && LOG="/tmp/nginx_${PORT}.log"
PID_FILE="/tmp/nginx_${PORT}.pid"
CONTAINER="nginx-eval-${PORT}"

# ─── Kernel/TCP tuning (idempotent; sudo -n so missing NOPASSWD fails fast) ──
echo "[nginx] tuning sysctl + ulimits"
sudo -n sysctl -q -w net.core.somaxconn=65535 || true
sudo -n sysctl -q -w net.ipv4.tcp_tw_reuse=1 || true
sudo -n sysctl -q -w net.ipv4.ip_local_port_range="1024 65535" || true
sudo -n sysctl -q -w net.core.netdev_max_backlog=250000 || true
sudo -n sysctl -q -w net.ipv4.tcp_max_syn_backlog=65535 || true

# ─── Generate static files (deterministic length, printable bytes) ──────
mkdir -p "$STATIC_DIR"
if [[ ! -s "$STATIC_DIR/1kb.html" ]]; then
    head -c 1024  /dev/urandom | base64 | tr -d '\n' | head -c 1024  > "$STATIC_DIR/1kb.html"
fi
if [[ ! -s "$STATIC_DIR/100kb.html" ]]; then
    head -c 102400 /dev/urandom | base64 | tr -d '\n' | head -c 102400 > "$STATIC_DIR/100kb.html"
fi

# Verify exact byte count — anything else means our throughput math is off.
for f in 1kb.html:1024 100kb.html:102400; do
    name="${f%:*}"; want="${f#*:}"
    got=$(stat -c '%s' "$STATIC_DIR/$name")
    if [[ "$got" != "$want" ]]; then
        echo "[nginx] static file $name: expected $want bytes, got $got" >&2
        exit 1
    fi
done

# ─── Stage nginx.conf if not pre-staged at $CONFIG_PATH ─────────────────
if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "[nginx] missing config at $CONFIG_PATH" >&2
    exit 1
fi

# ─── Tear down any prior container of the same name ─────────────────────
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# Pull image up front so the Docker run latency doesn't bleed into t0.
docker pull "$IMAGE" >/dev/null

echo "[nginx] launching $IMAGE → :${PORT} (container=$CONTAINER)"
docker run -d --name "$CONTAINER" \
    --network host \
    --ulimit nofile=1048576:1048576 \
    -v "$CONFIG_PATH":/etc/nginx/nginx.conf:ro \
    -v "$STATIC_DIR":/usr/share/nginx/html:ro \
    "$IMAGE" \
    > /dev/null

echo "docker:$CONTAINER" > "$PID_FILE"

# Stream container logs so the host-side $LOG works the same as vLLM.
( docker logs -f "$CONTAINER" > "$LOG" 2>&1 ) &

# ─── Readiness probe ────────────────────────────────────────────────────
DEADLINE=$(( $(date +%s) + 60 ))
while [[ $(date +%s) -lt $DEADLINE ]]; do
    if curl -sf "http://127.0.0.1:${PORT}/healthz" > /dev/null; then
        # Also confirm both static routes resolve and have correct length.
        for path in "/1kb:1024" "/100kb:102400"; do
            url="${path%:*}"; want="${path#*:}"
            got=$(curl -s -o /dev/null -w '%{size_download}' "http://127.0.0.1:${PORT}${url}")
            if [[ "$got" != "$want" ]]; then
                echo "[nginx] route $url returned $got bytes, expected $want" >&2
                exit 1
            fi
        done
        echo "[nginx] ready on :${PORT} (/1kb=1024B, /100kb=102400B)"
        exit 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
        echo "[nginx] container died — see $LOG" >&2
        tail -n 40 "$LOG" >&2 || true
        exit 1
    fi
    sleep 1
done

echo "[nginx] timed out waiting for readiness" >&2
exit 1
