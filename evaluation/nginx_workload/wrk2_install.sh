#!/usr/bin/env bash
# Idempotent wrk2 install on the driver VM. wrk2 is not in apt, must be
# built from source. Pinned to a known-good commit so successive
# experiment runs get a consistent measurement tool.
#
# Result: `wrk` binary at $WRK2_DIR/wrk (default $HOME/wrk2/wrk).

set -euo pipefail

WRK2_DIR="${WRK2_DIR:-$HOME/wrk2}"
WRK2_REPO="${WRK2_REPO:-https://github.com/giltene/wrk2.git}"
WRK2_COMMIT="${WRK2_COMMIT:-44a94c17d8e6a0bac8559b53da76848e430cb7a7}"

BIN="$WRK2_DIR/wrk"

if [[ -x "$BIN" ]]; then
    echo "[wrk2] already at $BIN"
    exit 0
fi

echo "[wrk2] installing build deps"
sudo apt-get update -y -qq
sudo apt-get install -y -qq build-essential libssl-dev zlib1g-dev git

if [[ ! -d "$WRK2_DIR/.git" ]]; then
    git clone "$WRK2_REPO" "$WRK2_DIR"
fi

cd "$WRK2_DIR"
git fetch --all --quiet
git checkout --quiet "$WRK2_COMMIT"
make -j"$(nproc)"

echo "[wrk2] built → $BIN"
"$BIN" --version 2>&1 | head -1 || true
