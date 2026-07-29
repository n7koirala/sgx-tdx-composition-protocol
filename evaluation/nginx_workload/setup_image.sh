#!/usr/bin/env bash
# One-time: creates a GCE image from the snapshot, so per-cell VM
# provisioning isn't bottlenecked by GCP's per-snapshot operation rate
# limit. Without this, sequential matrix runs trip
#   "Operation rate exceeded for resource 'projects/.../snapshots/X'.
#    Too frequent operations from the source resource."
# after only a handful of cells.
#
# Idempotent — safe to re-run; exits cleanly if the image already exists.
# Image creation takes ~5–10 minutes.
#
# Usage:
#   ./setup_image.sh
#   ./setup_image.sh --snapshot foo --image foo-img

set -euo pipefail

SNAPSHOT="${SNAPSHOT:-vordr-vllm-base}"
IMAGE="${IMAGE:-vordr-vllm-base-img}"
PROJECT="${GCP_PROJECT:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --snapshot) SNAPSHOT="$2"; shift 2 ;;
        --image)    IMAGE="$2"; shift 2 ;;
        --project)  PROJECT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

PROJ_FLAG=""
[[ -n "$PROJECT" ]] && PROJ_FLAG="--project=$PROJECT"

if gcloud compute images describe "$IMAGE" $PROJ_FLAG > /dev/null 2>&1; then
    echo "[setup-image] $IMAGE already exists — reusing" >&2
    echo "VORDR_IMAGE=$IMAGE"
    exit 0
fi

echo "[setup-image] creating image $IMAGE from snapshot $SNAPSHOT" >&2
echo "[setup-image] this takes ~5-10 min; one-time per campaign" >&2
gcloud compute images create "$IMAGE" \
    --source-snapshot="$SNAPSHOT" \
    $PROJ_FLAG >&2

echo "[setup-image] done. $IMAGE is ready for matrix runs." >&2
echo "VORDR_IMAGE=$IMAGE"
