#!/usr/bin/env bash
# Provision a fresh target VM for one experiment run — from a prepared
# boot-disk snapshot (default `vordr-vllm-base`) so every cell skips the
# 45–70 min vLLM-CPU image build.
#
# Three conditions:
#   native     — plain c3-standard-* (no TDX)
#   tdx-only   — c3-standard-* CVM with TDX, no Vordr agent
#   tdx-vordr  — c3-standard-* CVM with TDX + agent
#                (snapshot is assumed to have the agent bits staged)
#
# After creation:
#   - ssh-keys metadata re-injected (snapshot-booted VMs lose the
#     commissioning-phase SSH setup)
#   - enable-oslogin=FALSE (so plain `ssh -i` works — run_experiment.sh
#     does not use `gcloud ssh`)
#   - startup-script that loads the IMA policy on first boot
#     (write-once per boot; only fires on CVM conditions)
#   - waits for SSH readiness so the caller can immediately run the orchestrator
#
# Emits one line on stdout:
#   CVM_NAME=<name> CVM_IP=<external-ip>
#
# Usage:
#   ./provision_vms.sh --condition tdx-only --name vordr-eval-$(date +%s)

set -euo pipefail

CONDITION=""
NAME=""
MACHINE_TYPE="${MACHINE_TYPE:-c3-standard-8}"
ZONE="${ZONE:-us-central1-a}"
SNAPSHOT="${SNAPSHOT:-vordr-vllm-base}"
IMAGE="${IMAGE:-}"
BOOT_DISK_SIZE="${BOOT_DISK_SIZE:-200GB}"
PUBKEY="${PUBKEY:-$HOME/.ssh/vordr_id_rsa.pub}"
SSH_USER="${SSH_USER:-nkoirala}"
PROJECT="${GCP_PROJECT:-}"
SSH_TIMEOUT="${SSH_TIMEOUT:-180}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --condition)     CONDITION="$2"; shift 2 ;;
        --name)          NAME="$2"; shift 2 ;;
        --machine-type)  MACHINE_TYPE="$2"; shift 2 ;;
        --zone)          ZONE="$2"; shift 2 ;;
        --snapshot)      SNAPSHOT="$2"; shift 2 ;;
        --image)         IMAGE="$2"; shift 2 ;;
        --boot-disk-size) BOOT_DISK_SIZE="$2"; shift 2 ;;
        --pubkey)        PUBKEY="$2"; shift 2 ;;
        --ssh-user)      SSH_USER="$2"; shift 2 ;;
        --project)       PROJECT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$CONDITION" ]] && { echo "missing --condition" >&2; exit 2; }
[[ -z "$NAME" ]]      && { echo "missing --name"      >&2; exit 2; }
[[ -r "$PUBKEY" ]]    || { echo "pubkey not readable: $PUBKEY" >&2; exit 2; }

PROJ_FLAG=""
[[ -n "$PROJECT" ]] && PROJ_FLAG="--project=$PROJECT"

STARTUP_SCRIPT='#!/usr/bin/env bash
# Load IMA policy on every boot (write-once per boot). Harmless on non-CVMs.
if [[ -w /sys/kernel/security/ima/policy ]]; then
    cat <<POLICY > /sys/kernel/security/ima/policy 2>/dev/null || true
measure func=BPRM_CHECK
measure func=MMAP_CHECK
measure func=MODULE_CHECK
POLICY
fi
'

# Common base args. Prefer --image when given (avoids the per-snapshot
# concurrent-operation rate limit that bites sequential matrix runs);
# fall back to --source-snapshot for backwards compat.
BASE_ARGS=(
    --zone="$ZONE"
    --machine-type="$MACHINE_TYPE"
    --boot-disk-size="$BOOT_DISK_SIZE"
)
if [[ -n "$IMAGE" ]]; then
    BASE_ARGS+=("--image=$IMAGE")
else
    BASE_ARGS+=("--source-snapshot=$SNAPSHOT")
fi
[[ -n "$PROJECT" ]] && BASE_ARGS+=("--project=$PROJECT")

case "$CONDITION" in
    native)
        gcloud compute instances create "$NAME" "${BASE_ARGS[@]}" >&2
        ;;
    tdx-only|tdx-vordr)
        gcloud compute instances create "$NAME" "${BASE_ARGS[@]}" \
            --confidential-compute-type=TDX \
            --maintenance-policy=TERMINATE >&2
        ;;
    *)
        echo "--condition must be native|tdx-only|tdx-vordr" >&2
        exit 2
        ;;
esac

# Re-inject ssh-keys + disable OS Login so plain `ssh -i` works, and
# attach the IMA-policy startup-script (harmless on native since it
# checks for /sys/kernel/security/ima/policy writability).
TMP_STARTUP=$(mktemp)
TMP_SSHKEYS=$(mktemp)
trap 'rm -f "$TMP_STARTUP" "$TMP_SSHKEYS"' EXIT
printf '%s' "$STARTUP_SCRIPT" > "$TMP_STARTUP"
printf '%s:%s\n' "$SSH_USER" "$(cat "$PUBKEY")" > "$TMP_SSHKEYS"

gcloud compute instances add-metadata "$NAME" \
    --zone="$ZONE" $PROJ_FLAG \
    --metadata="enable-oslogin=FALSE" \
    --metadata-from-file="ssh-keys=$TMP_SSHKEYS,startup-script=$TMP_STARTUP" >&2

# External IP for SSH from outside the VPC (e.g. WEN). Internal IP for
# in-VPC drivers (e.g. the NGINX-workload driver VM, where sub-ms RTT
# matters for the syscall-bound measurement).
IP=$(gcloud compute instances describe "$NAME" --zone="$ZONE" $PROJ_FLAG \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)')
INTERNAL_IP=$(gcloud compute instances describe "$NAME" --zone="$ZONE" $PROJ_FLAG \
        --format='value(networkInterfaces[0].networkIP)')

# Wait for SSH to come up so the caller can immediately run experiments.
# Give the guest agent a moment to pick up the ssh-keys metadata first.
sleep 15
DEADLINE=$(( $(date +%s) + SSH_TIMEOUT ))
SSH_KEY_PATH="${PUBKEY%.pub}"
while : ; do
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o BatchMode=yes -o ConnectTimeout=5 \
           -i "$SSH_KEY_PATH" "${SSH_USER}@${IP}" true 2>/dev/null; then
        echo "[provision] ssh reachable at ${SSH_USER}@${IP}" >&2
        break
    fi
    if [[ $(date +%s) -ge $DEADLINE ]]; then
        echo "[provision] ssh probe timed out after ${SSH_TIMEOUT}s" >&2
        exit 1
    fi
    sleep 5
done

echo "CVM_NAME=$NAME CVM_IP=$IP CVM_INTERNAL_IP=$INTERNAL_IP CVM_ZONE=$ZONE"
