#!/usr/bin/env bash
# Provisions the NGINX-workload DRIVER VM in the same zone as targets,
# so wrk2 measurements aren't contaminated by WEN→cloud WAN latency.
#
# This is a ONE-TIME setup. The driver VM stays running across the full
# matrix (no per-cell teardown). Tear it down only when the experiment
# campaign is done:
#   gcloud compute instances delete <DRIVER_NAME> --zone=<ZONE> --quiet
#
# What this script does (idempotent — safe to re-run):
#   1. Creates a c3-standard-8 non-CVM in the target zone, with
#      cloud-platform scope so the driver can itself provision/teardown
#      target VMs without re-authenticating gcloud.
#   2. Injects WEN's SSH pubkey so you can ssh in from WEN.
#   3. Installs build deps + builds wrk2 (pinned commit).
#   4. Installs Python deps used by attestation_driver / update_injector.
#   5. Pushes WEN's SSH private key to the driver so the driver can SSH
#      into target VMs (using the same key vordr_id_rsa).
#   6. Rsyncs WEN's repo working tree to the driver (so any local
#      uncommitted edits in research/incremental_attestation/ etc. are
#      reflected on the driver, exactly like run_experiment.sh's WEN→TDX
#      sync — but here it's WEN→DRIVER).
#
# Emits one line on stdout (consume with eval):
#   DRIVER_NAME=<name> DRIVER_IP=<external-ip> DRIVER_ZONE=<zone>
#
# Usage (from WEN):
#   eval "$(./provision_driver.sh --name nginx-driver)"
#   ssh -i ~/.ssh/vordr_id_rsa "$USER@$DRIVER_IP"

set -euo pipefail

NAME="nginx-driver"
ZONE="${ZONE:-us-central1-a}"
MACHINE_TYPE="${MACHINE_TYPE:-c3-standard-8}"
BOOT_DISK_SIZE="${BOOT_DISK_SIZE:-100GB}"
IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2204-lts}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"
PUBKEY="${PUBKEY:-$HOME/.ssh/vordr_id_rsa.pub}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/vordr_id_rsa}"
SSH_USER="${SSH_USER:-$USER}"
PROJECT="${GCP_PROJECT:-}"
SSH_TIMEOUT=180

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) NAME="$2"; shift 2 ;;
        --zone) ZONE="$2"; shift 2 ;;
        --machine-type) MACHINE_TYPE="$2"; shift 2 ;;
        --boot-disk-size) BOOT_DISK_SIZE="$2"; shift 2 ;;
        --pubkey) PUBKEY="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ssh-user) SSH_USER="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -r "$PUBKEY" ]]   || { echo "pubkey not readable: $PUBKEY"   >&2; exit 2; }
[[ -r "$SSH_KEY" ]]  || { echo "ssh-key not readable: $SSH_KEY" >&2; exit 2; }

PROJ_FLAG=""
[[ -n "$PROJECT" ]] && PROJ_FLAG="--project=$PROJECT"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ─── 1. Create driver VM (or reuse existing) ───────────────────────────
if gcloud compute instances describe "$NAME" --zone="$ZONE" $PROJ_FLAG \
        > /dev/null 2>&1; then
    echo "[driver-prov] $NAME already exists in $ZONE — reusing" >&2
else
    echo "[driver-prov] creating $NAME ($MACHINE_TYPE) in $ZONE" >&2
    TMP_SSHKEYS=$(mktemp)
    trap 'rm -f "$TMP_SSHKEYS"' EXIT
    printf '%s:%s\n' "$SSH_USER" "$(cat "$PUBKEY")" > "$TMP_SSHKEYS"

    gcloud compute instances create "$NAME" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --image-family="$IMAGE_FAMILY" \
        --image-project="$IMAGE_PROJECT" \
        --boot-disk-size="$BOOT_DISK_SIZE" \
        --scopes=https://www.googleapis.com/auth/cloud-platform \
        --metadata="enable-oslogin=FALSE" \
        --metadata-from-file="ssh-keys=$TMP_SSHKEYS" \
        $PROJ_FLAG >&2
fi

IP=$(gcloud compute instances describe "$NAME" --zone="$ZONE" $PROJ_FLAG \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)')

# ─── 2. Wait for SSH ────────────────────────────────────────────────────
sleep 10
DEADLINE=$(( $(date +%s) + SSH_TIMEOUT ))
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -o ConnectTimeout=5 -i "$SSH_KEY")

while : ; do
    if ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" true 2>/dev/null; then
        echo "[driver-prov] ssh reachable at ${SSH_USER}@${IP}" >&2
        break
    fi
    if [[ $(date +%s) -ge $DEADLINE ]]; then
        echo "[driver-prov] ssh probe timed out after ${SSH_TIMEOUT}s" >&2
        exit 1
    fi
    sleep 5
done

# ─── 3. Install build deps + wrk2 + Python deps on driver ──────────────
# All remote output goes to local stderr (>&2 on the ssh): otherwise apt
# / make output lands on the script's stdout and corrupts the final eval
# line that callers consume.
echo "[driver-prov] installing toolchain + wrk2 on driver" >&2
ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" 'bash -s' >&2 2>&1 <<'REMOTE'
set -e
sudo apt-get update -y -qq
sudo apt-get install -y -qq \
    build-essential libssl-dev zlib1g-dev git \
    python3-pip python3-venv rsync curl jq

if [[ ! -x "$HOME/wrk2/wrk" ]]; then
    git clone https://github.com/giltene/wrk2.git "$HOME/wrk2"
    cd "$HOME/wrk2"
    git checkout 44a94c17d8e6a0bac8559b53da76848e430cb7a7
    make -j"$(nproc)"
fi

pip3 install --user --quiet cryptography requests

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

echo "[driver-prov:remote] toolchain ready"
"$HOME/wrk2/wrk" --version 2>&1 | head -1 || true
REMOTE

# ─── 4. Push SSH key for target access ─────────────────────────────────
echo "[driver-prov] copying SSH key (for driver→target SSH)" >&2
scp "${SSH_OPTS[@]}" "$SSH_KEY" "${PUBKEY}" \
    "${SSH_USER}@${IP}:.ssh/" >&2
ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" \
    "chmod 600 .ssh/$(basename "$SSH_KEY"); chmod 644 .ssh/$(basename "$PUBKEY")" >&2

# ─── 5. Rsync repo (working tree) WEN → driver ─────────────────────────
echo "[driver-prov] rsyncing repo WEN → driver" >&2
RSYNC_SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o BatchMode=yes -i $SSH_KEY"
rsync -az --no-owner --no-group \
    --exclude='__pycache__/' --exclude='*.pyc' \
    --exclude='.git/objects/pack/' \
    --exclude='charts*/' --exclude='prior_csvs/' \
    --exclude='evaluation/results/' \
    --exclude='*.pdf' \
    -e "$RSYNC_SSH" \
    "$REPO_ROOT/" \
    "${SSH_USER}@${IP}:sgx-tdx-composition-protocol/" >&2

# ─── 6. Verify driver can run the orchestrator ─────────────────────────
echo "[driver-prov] sanity-check driver" >&2
ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" \
    "cd sgx-tdx-composition-protocol/evaluation/nginx_workload && \
     bash -n run_experiment.sh && echo '[driver-prov:remote] run_experiment.sh OK'" >&2

echo "[driver-prov] driver ready at ${SSH_USER}@${IP}" >&2
echo "DRIVER_NAME=$NAME DRIVER_IP=$IP DRIVER_ZONE=$ZONE"
