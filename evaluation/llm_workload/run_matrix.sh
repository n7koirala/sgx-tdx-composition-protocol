#!/usr/bin/env bash
# Matrix driver — iterates 24 cells for one model, provisioning a fresh
# VM per cell from the prepared snapshot (default `vordr-vllm-base`).
#
# Cells:
#   native    × {cold,warm} × {no-updates,with-updates}            =  4 cells
#   tdx-only  × {cold,warm} × {no-updates,with-updates}            =  4 cells
#   tdx-vordr × {15,30,60,300}s × {cold,warm} × {no-updates,upd}   = 16 cells
#   TOTAL                                                        24
#
# Idempotent: cells whose `summary.json` already exists are skipped,
# so interrupted runs can be resumed by re-invoking with the same --root.
#
# Usage:
#   ./run_matrix.sh --model-key phi3-mini --rps 0.15 \
#       --root ../results/llm/matrix-phi3-$(date +%Y%m%d)
#
# Optional:
#   --only <comma-list>  # subset of conditions, e.g. "native,tdx-only"
#   --dry-run            # print plan without provisioning
#   --keep-vms           # do not delete VMs after each cell (debug)

set -euo pipefail

MODEL_KEY=""
RPS=""
DURATION_SEC="${DURATION_SEC:-600}"
WARMUP_SEC="${WARMUP_SEC:-60}"
NUM_PROMPTS=""
ROOT=""
SSH_KEY="${SSH_KEY:-$HOME/.ssh/vordr_id_rsa}"
SSH_USER="${SSH_USER:-nkoirala}"
SNAPSHOT="${SNAPSHOT:-vordr-vllm-base}"
ZONE="${ZONE:-us-central1-a}"
DOCKER_IMAGE="${DOCKER_IMAGE:-vllm-cpu:local}"
ONLY_CONDITIONS=""
DRY_RUN=0
KEEP_VMS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --model-key)    MODEL_KEY="$2"; shift 2 ;;
        --rps)          RPS="$2"; shift 2 ;;
        --duration-sec) DURATION_SEC="$2"; shift 2 ;;
        --warmup-sec)   WARMUP_SEC="$2"; shift 2 ;;
        --num-prompts)  NUM_PROMPTS="$2"; shift 2 ;;
        --root)         ROOT="$2"; shift 2 ;;
        --ssh-key)      SSH_KEY="$2"; shift 2 ;;
        --ssh-user)     SSH_USER="$2"; shift 2 ;;
        --snapshot)     SNAPSHOT="$2"; shift 2 ;;
        --zone)         ZONE="$2"; shift 2 ;;
        --docker-image) DOCKER_IMAGE="$2"; shift 2 ;;
        --only)         ONLY_CONDITIONS="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=1; shift ;;
        --keep-vms)     KEEP_VMS=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$MODEL_KEY" ]] && { echo "missing --model-key" >&2; exit 2; }
[[ -z "$RPS" ]]       && { echo "missing --rps"       >&2; exit 2; }
[[ -z "$ROOT" ]]      && { echo "missing --root"      >&2; exit 2; }

mkdir -p "$ROOT"
EVAL_DIR="$(cd "$(dirname "$0")" && pwd)"

LOG_SIZES=(cold warm)
INTERLEAVES=(no-updates with-updates)
EPOCHS=(15 30 60 300)
CONDITIONS=(native tdx-only tdx-vordr)

if [[ -n "$ONLY_CONDITIONS" ]]; then
    IFS=',' read -r -a CONDITIONS <<< "$ONLY_CONDITIONS"
fi

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
        *)
            echo "unknown condition in --only: $cond" >&2; exit 2 ;;
    esac
done

TOTAL=${#cells[@]}
echo "[matrix] model=$MODEL_KEY rps=$RPS cells=$TOTAL root=$ROOT"

IDX=0
for cell in "${cells[@]}"; do
    IDX=$((IDX + 1))
    IFS='|' read -r cond ls il ep <<< "$cell"

    if [[ "$cond" == "tdx-vordr" ]]; then
        tag="${ep}s_${ls}_${il}"
        EXTRA_ORCH=(--epoch-sec "$ep")
    else
        tag="${ls}_${il}"
        EXTRA_ORCH=()
    fi

    OUT_DIR="$ROOT/$cond/$tag"
    if [[ -f "$OUT_DIR/summary.json" ]]; then
        echo "[matrix] ($IDX/$TOTAL) SKIP $cond/$tag — summary.json exists"
        continue
    fi

    mkdir -p "$OUT_DIR"
    # GCE instance-name: <=63 chars, lowercase, no underscores.
    RAW_NAME="vordr-m-${MODEL_KEY}-${cond}-${tag}-$(date +%s)"
    VM_NAME="${RAW_NAME//_/-}"
    VM_NAME="${VM_NAME:0:62}"

    echo "[matrix] ($IDX/$TOTAL) $cond/$tag → VM=$VM_NAME"
    if [[ $DRY_RUN == 1 ]]; then
        continue
    fi

    CELL_START=$(date +%s)

    PROV_LINE=$("$EVAL_DIR/provision_vms.sh" \
                    --condition "$cond" \
                    --name "$VM_NAME" \
                    --zone "$ZONE" \
                    --snapshot "$SNAPSHOT" \
                    --ssh-user "$SSH_USER" \
                    --pubkey "${SSH_KEY}.pub") || {
        echo "[matrix] ($IDX/$TOTAL) PROVISION FAILED $cond/$tag" >&2
        continue
    }
    eval "$PROV_LINE"

    set +e
    "$EVAL_DIR/run_experiment.sh" \
        --condition "$cond" \
        --model-key "$MODEL_KEY" \
        "${EXTRA_ORCH[@]}" \
        --log-size "$ls" --interleave "$il" \
        --target-host "$CVM_IP" --target-user "$SSH_USER" \
        --ssh-key "$SSH_KEY" \
        --rps "$RPS" \
        --warmup-sec "$WARMUP_SEC" --duration-sec "$DURATION_SEC" \
        ${NUM_PROMPTS:+--num-prompts "$NUM_PROMPTS"} \
        --via-docker --docker-image "$DOCKER_IMAGE" \
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
