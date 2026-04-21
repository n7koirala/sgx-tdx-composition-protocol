#!/usr/bin/env bash
# Provision a fresh target VM for one experiment run.
#
# Three conditions:
#   native     — plain c3-standard-* (no TDX)
#   tdx-only   — c3-standard-* CVM with TDX, no Vordr agent
#   tdx-vordr  — c3-standard-* CVM with TDX; launched via asp_client so
#                the controller injects SSH key + installs the IMA agent
#
# Emits one line on stdout:
#   CVM_NAME=<name> CVM_IP=<internal-ip> [CVM_ID=<controller-id>]
#
# Usage:
#   ./provision_vms.sh --condition tdx-vordr --name vordr-eval-$(date +%s)
#
# Driver VM must be in the same zone. Reuse an existing driver VM
# across runs — we only reprovision the target.

set -euo pipefail

CONDITION=""
NAME=""
MACHINE_TYPE="${MACHINE_TYPE:-c3-standard-8}"
ZONE="${ZONE:-us-central1-a}"
IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2204-lts}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"
PROJECT="${GCP_PROJECT:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --condition) CONDITION="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --machine-type) MACHINE_TYPE="$2"; shift 2 ;;
        --zone) ZONE="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$CONDITION" ]] && { echo "missing --condition" >&2; exit 2; }
[[ -z "$NAME" ]]      && { echo "missing --name"      >&2; exit 2; }

PROJ_FLAG=""
[[ -n "$PROJECT" ]] && PROJ_FLAG="--project=$PROJECT"

case "$CONDITION" in
    native)
        gcloud compute instances create "$NAME" \
            --zone="$ZONE" \
            --machine-type="$MACHINE_TYPE" \
            --image-family="$IMAGE_FAMILY" \
            --image-project="$IMAGE_PROJECT" \
            --boot-disk-size=80GB \
            $PROJ_FLAG >&2
        IP=$(gcloud compute instances describe "$NAME" --zone="$ZONE" \
                $PROJ_FLAG --format='value(networkInterfaces[0].networkIP)')
        echo "CVM_NAME=$NAME CVM_IP=$IP"
        ;;
    tdx-only)
        gcloud compute instances create "$NAME" \
            --zone="$ZONE" \
            --machine-type="$MACHINE_TYPE" \
            --image-family="$IMAGE_FAMILY" \
            --image-project="$IMAGE_PROJECT" \
            --confidential-compute-type=TDX \
            --maintenance-policy=TERMINATE \
            --boot-disk-size=80GB \
            $PROJ_FLAG >&2
        IP=$(gcloud compute instances describe "$NAME" --zone="$ZONE" \
                $PROJ_FLAG --format='value(networkInterfaces[0].networkIP)')
        echo "CVM_NAME=$NAME CVM_IP=$IP"
        ;;
    tdx-vordr)
        REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
        # Delegate to the existing commissioning path so the CVM comes
        # up with the SGX controller's SSH key + agent bits in place.
        OUT=$(cd "$REPO_ROOT" && python3 -m commissioning_phase.asp_client \
                --action start-cvm --cvm-name "$NAME" 2>&1)
        echo "$OUT" >&2
        CVM_ID=$(echo "$OUT" | awk -F'[:= ]+' '/CVM[_ ]?ID/ {print $2; exit}')
        IP=$(gcloud compute instances describe "$NAME" --zone="$ZONE" \
                $PROJ_FLAG --format='value(networkInterfaces[0].networkIP)' \
                2>/dev/null || echo "")
        echo "CVM_NAME=$NAME CVM_IP=$IP CVM_ID=$CVM_ID"
        ;;
    *)
        echo "--condition must be native|tdx-only|tdx-vordr" >&2
        exit 2
        ;;
esac
