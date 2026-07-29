#!/usr/bin/env bash
# Matrix driver — iterates the 24-cell matrix for a single payload,
# provisioning a fresh TARGET VM per cell. Mirrors the LLM workload's
# run_matrix.sh, but parameterized for one payload at a time and with
# per-interleave repetition counts (no-updates cells get N reps for error
# bars on the matched-delta figure; with-updates cells get fewer reps
# because they're noisier-by-design and we don't put error bars on them).
#
# Cell budget per payload (default reps):
#   native    × {cold,warm} × ({no-updates×3} + {with-updates×1})         = 8 cells
#   tdx-only  × same                                                   = 8 cells
#   tdx-vordr × {15,30,60,300}s × {cold,warm} × ({s×3}+{u×1})         = 32 cells
#   TOTAL per payload                                                  = 48 cells
#
# Idempotent: cells whose `wrk.json` already exists are skipped, so
# interrupted runs can be resumed by re-invoking with the same --root.
#
# Usage (on DRIVER):
#   ./run_matrix.sh --payload 1kb --rps 24000 \
#       --root ../results/nginx/matrix-1kb-$(date +%Y%m%d)
#
# Optional:
#   --no-updates-reps N        # default 3
#   --updates-reps N       # default 1
#   --duration-sec N       # default 300
#   --warmup-sec N         # default 30
#   --threads N            # default 4 (wrk2 -t)
#   --connections N        # default 200 (wrk2 -c)
#   --only <comma-list>    # subset of conditions, e.g. "native,tdx-only"
#   --dry-run              # print plan without provisioning
#   --keep-vms             # do not delete TARGETs after each cell (debug)

set -euo pipefail

PAYLOAD=""
RPS=""
NO_UPDATES_REPS="${NO_UPDATES_REPS:-3}"
UPDATES_REPS="${UPDATES_REPS:-1}"
DURATION_SEC="${DURATION_SEC:-300}"
WARMUP_SEC="${WARMUP_SEC:-30}"
THREADS="${THREADS:-4}"
CONNECTIONS="${CONNECTIONS:-200}"
ROOT=""
SSH_KEY="${SSH_KEY:-$HOME/.ssh/vordr_id_rsa}"
SSH_USER="${SSH_USER:-$USER}"
SNAPSHOT="${SNAPSHOT:-vordr-vllm-base}"
IMAGE="${IMAGE:-vordr-vllm-base-img}"
ZONE="${ZONE:-us-central1-a}"
ONLY_CONDITIONS=""
DRY_RUN=0
KEEP_VMS=0
PROVISION_RETRIES="${PROVISION_RETRIES:-2}"
PROVISION_RETRY_SLEEP="${PROVISION_RETRY_SLEEP:-90}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --payload)       PAYLOAD="$2"; shift 2 ;;
        --rps)           RPS="$2"; shift 2 ;;
        --no-updates-reps)   NO_UPDATES_REPS="$2"; shift 2 ;;
        --updates-reps)  UPDATES_REPS="$2"; shift 2 ;;
        --duration-sec)  DURATION_SEC="$2"; shift 2 ;;
        --warmup-sec)    WARMUP_SEC="$2"; shift 2 ;;
        --threads)       THREADS="$2"; shift 2 ;;
        --connections)   CONNECTIONS="$2"; shift 2 ;;
        --root)          ROOT="$2"; shift 2 ;;
        --ssh-key)       SSH_KEY="$2"; shift 2 ;;
        --ssh-user)      SSH_USER="$2"; shift 2 ;;
        --snapshot)      SNAPSHOT="$2"; shift 2 ;;
        --image)         IMAGE="$2"; shift 2 ;;
        --zone)          ZONE="$2"; shift 2 ;;
        --only)          ONLY_CONDITIONS="$2"; shift 2 ;;
        --dry-run)       DRY_RUN=1; shift ;;
        --keep-vms)      KEEP_VMS=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$PAYLOAD" ]] && { echo "missing --payload (1kb|100kb)" >&2; exit 2; }
[[ -z "$RPS" ]]     && { echo "missing --rps" >&2; exit 2; }
[[ -z "$ROOT" ]]    && { echo "missing --root" >&2; exit 2; }
case "$PAYLOAD" in 1kb|100kb) ;; *) echo "--payload must be 1kb|100kb" >&2; exit 2 ;; esac

mkdir -p "$ROOT"
EVAL_DIR="$(cd "$(dirname "$0")" && pwd)"
LLM_DIR="$(cd "$EVAL_DIR/../llm_workload" && pwd)"

LOG_SIZES=(cold warm)
INTERLEAVES=(no-updates with-updates)
EPOCHS=(15 30 60 300)
CONDITIONS=(native tdx-only tdx-vordr)

if [[ -n "$ONLY_CONDITIONS" ]]; then
    IFS=',' read -r -a CONDITIONS <<< "$ONLY_CONDITIONS"
fi

# Build cell list. Each entry: cond|log_size|interleave|epoch (- for non-vordr)
cells=()
for cond in "${CONDITIONS[@]}"; do
    case "$cond" in
        native|tdx-only)
            for ls in "${LOG_SIZES[@]}"; do
                for il in "${INTERLEAVES[@]}"; do
                    cells+=("$cond|$ls|$il|-")
                done
            done
            ;;
        tdx-vordr)
            for ep in "${EPOCHS[@]}"; do
                for ls in "${LOG_SIZES[@]}"; do
                    for il in "${INTERLEAVES[@]}"; do
                        cells+=("tdx-vordr|$ls|$il|$ep")
                    done
                done
            done
            ;;
        *) echo "unknown condition in --only: $cond" >&2; exit 2 ;;
    esac
done

# Expand cells with reps.
expanded=()
for cell in "${cells[@]}"; do
    IFS='|' read -r cond ls il ep <<< "$cell"
    if [[ "$il" == "with-updates" ]]; then
        nreps=$UPDATES_REPS
    else
        nreps=$NO_UPDATES_REPS
    fi
    for rep in $(seq 1 "$nreps"); do
        expanded+=("$cell|$rep")
    done
done

TOTAL=${#expanded[@]}
echo "[matrix] payload=$PAYLOAD rps=$RPS cells=$TOTAL root=$ROOT"
echo "[matrix] reps: no-updates=$NO_UPDATES_REPS updates=$UPDATES_REPS"

IDX=0
for cell in "${expanded[@]}"; do
    IDX=$((IDX + 1))
    IFS='|' read -r cond ls il ep rep <<< "$cell"

    if [[ "$cond" == "tdx-vordr" ]]; then
        tag="${ep}s_${ls}_${il}_${PAYLOAD}_rep${rep}"
        EXTRA_ORCH=(--epoch-sec "$ep")
    else
        tag="${ls}_${il}_${PAYLOAD}_rep${rep}"
        EXTRA_ORCH=()
    fi

    OUT_DIR="$ROOT/$cond/$tag"
    if [[ -f "$OUT_DIR/wrk.json" ]]; then
        echo "[matrix] ($IDX/$TOTAL) SKIP $cond/$tag — wrk.json exists"
        continue
    fi

    mkdir -p "$OUT_DIR"
    # GCE instance-name: <=63 chars, lowercase, no underscores.
    RAW_NAME="vordr-n-${PAYLOAD}-${cond}-${tag}-$(date +%s)"
    VM_NAME="${RAW_NAME//_/-}"
    VM_NAME="${VM_NAME:0:62}"

    echo "[matrix] ($IDX/$TOTAL) $cond/$tag → VM=$VM_NAME"
    if [[ $DRY_RUN == 1 ]]; then
        continue
    fi

    CELL_START=$(date +%s)

    # Provision args. Prefer --image over --snapshot (avoids the
    # per-snapshot concurrent-op rate limit that bites the matrix).
    PROV_ARGS=(
        --condition "$cond"
        --name "$VM_NAME"
        --zone "$ZONE"
        --ssh-user "$SSH_USER"
        --pubkey "${SSH_KEY}.pub"
    )
    if [[ -n "$IMAGE" ]]; then
        PROV_ARGS+=(--image "$IMAGE")
    else
        PROV_ARGS+=(--snapshot "$SNAPSHOT")
    fi

    # Retry transient provision failures (rate limits, transient gcloud
    # errors). Each retry waits PROVISION_RETRY_SLEEP seconds.
    PROV_LINE=""
    PROV_OK=0
    for attempt in $(seq 1 $((PROVISION_RETRIES + 1))); do
        if PROV_LINE=$("$LLM_DIR/provision_vms.sh" "${PROV_ARGS[@]}" 2>/tmp/_prov_err.$$); then
            PROV_OK=1
            break
        fi
        echo "[matrix] ($IDX/$TOTAL) provision attempt $attempt failed for $cond/$tag" >&2
        sed -n '1,5p' /tmp/_prov_err.$$ >&2 || true
        if [[ $attempt -le $PROVISION_RETRIES ]]; then
            echo "[matrix] sleeping ${PROVISION_RETRY_SLEEP}s before retry" >&2
            sleep "$PROVISION_RETRY_SLEEP"
            # Bump the timestamp suffix so the next attempt uses a fresh name.
            VM_NAME="${RAW_NAME//_/-}-r${attempt}"
            VM_NAME="${VM_NAME:0:62}"
            PROV_ARGS=("${PROV_ARGS[@]/--name $VM_NAME}")
            PROV_ARGS+=(--name "$VM_NAME")
        fi
    done
    rm -f /tmp/_prov_err.$$

    if [[ $PROV_OK -ne 1 ]]; then
        echo "[matrix] ($IDX/$TOTAL) PROVISION FAILED $cond/$tag (after retries)" >&2
        continue
    fi
    eval "$PROV_LINE"

    # CVM_INTERNAL_IP is what we want — sub-ms RTT from DRIVER to TARGET.
    set +e
    "$EVAL_DIR/run_experiment.sh" \
        --condition "$cond" \
        --payload "$PAYLOAD" \
        "${EXTRA_ORCH[@]}" \
        --log-size "$ls" --interleave "$il" \
        --target-host "$CVM_INTERNAL_IP" --target-user "$SSH_USER" \
        --ssh-key "$SSH_KEY" \
        --rps "$RPS" \
        --warmup-sec "$WARMUP_SEC" --duration-sec "$DURATION_SEC" \
        --threads "$THREADS" --connections "$CONNECTIONS" \
        --out-dir "$OUT_DIR"
    rc=$?
    set -e

    if [[ $KEEP_VMS == 0 ]]; then
        gcloud compute instances delete "$CVM_NAME" --zone="$ZONE" --quiet >&2 || true
    fi

    DUR=$(( $(date +%s) - CELL_START ))
    if [[ $rc -ne 0 ]]; then
        echo "[matrix] ($IDX/$TOTAL) FAIL $cond/$tag after ${DUR}s (rc=$rc)" >&2
    else
        echo "[matrix] ($IDX/$TOTAL) OK   $cond/$tag in ${DUR}s"
    fi
done

python3 "$EVAL_DIR/collect_results.py" --root "$ROOT" || \
    echo "[matrix] collect_results.py exited non-zero (partial matrix?)" >&2

echo "[matrix] done → $ROOT"
