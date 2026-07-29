# Native + TDX-only Smoke Tests and RPS Calibration

Goal of this session: verify the `native` and `tdx-only` branches of
`run_experiment.sh` work end-to-end on `phi3-mini`, then pick the fixed
RPS that every 24-cell matrix run will use.

This runbook assumes you have already completed
`validation_instructions/README.md` (a `tdx-vordr` cell ran end-to-end)
so the driver venv, firewall rule, Docker image, and TLS certs are in
place on the existing validation CVM.

Estimated wall-clock: ~45 min.

---

## Prereqs (one-time, carried over from validation)

Driver VM:

- `~/vordr-driver-venv` activated — `source ~/vordr-driver-venv/bin/activate`
- `VLLM_SRC=~/vllm` (v0.6.3 pinned) exported
- `~/.ssh/vordr_id_rsa` keypair exists
- `gcloud` auth + project set (`gcloud config get-value project`)
- Firewall rule `vordr-eval-ports` exists

Your existing validation CVM is expected to still be running at
`$TARGET_IP` with `vllm-cpu:local` image built. If you've since stopped
it, just re-provision first with the `validation_instructions/` flow.

All commands below are run from `~/sgx-tdx-composition-protocol/evaluation/llm_workload/`.

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/llm_workload
```

---

## Script wiring — already verified

- `provision_vms.sh` has all three condition branches: `native`,
  `tdx-only`, `tdx-vordr` (lines 47, 59, 73).
- `run_experiment.sh` gates attestation-only work behind
  `CONDITION == "tdx-vordr"` (agent launch, attestation driver,
  `wait $ATTEST_PID`, scp agent.log, pkill agent).
- `IMA_START` will be `-1` on `native` (no sysfs IMA) — that's fine,
  recorded as-is in `run.json`.

---

## Step 0 — Smoke-test `tdx-only` on the existing CVM (free)

No new VM needed. Same CVM, just skip attestation by changing
`--condition`. Confirms the `tdx-only` branch before we spend money on
new VMs.

```bash
export OUT_DIR=~/sgx-tdx-composition-protocol/evaluation/results/llm/tdx-only-smoke-$(date +%s)/tdx-only/30s_cold_no-updates
mkdir -p "$OUT_DIR"

./run_experiment.sh \
    --condition tdx-only \
    --model-key phi3-mini \
    --log-size cold --interleave no-updates \
    --target-host "$TARGET_IP" --target-user nkoirala \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps 1 --warmup-sec 30 --duration-sec 120 \
    --num-prompts 30 \
    --via-docker --docker-image vllm-cpu:local \
    --out-dir "$OUT_DIR"
```

**Expect:**

- No `[orch] launching CVM attestation agent` line
- No `attest.csv` in `$OUT_DIR`
- `bench.log` reaches `100%|██████████| 30/30` and prints the
  `Serving Benchmark Result` block
- `[orch] done → $OUT_DIR` at the end
- `run.json`, `sampler.csv`, `vllm.json` all present

If it runs clean, the `tdx-only` branch is good.

---

## Step 1 — Snapshot the current CVM's boot disk

The snapshot becomes the parent for all future matrix VMs, so
every new instance boots with `vllm-cpu:local` already built and all
commissioning bits in place. Saves 45–70 min of Docker build per VM.

```bash
# Disk name is usually same as the instance name — confirm with:
gcloud compute disks list --filter="name~vordr" --format="value(name)"

gcloud compute disks snapshot vordr-valid-1776832711 \
    --snapshot-names=vordr-vllm-base \
    --zone=us-central1-a
```

~3–5 min. Keep this snapshot around for the whole matrix — don't delete
it after this session.

---

## Step 2 — Spin up a `native` VM from the snapshot

Same x86 image, no TDX flag → plain non-confidential c3-standard-8.

**Note on boot-disk-size:** GCE refuses to create an instance with a
boot disk smaller than the source snapshot. The validation CVM's boot
disk is 200 GB, so `--boot-disk-size=200GB` is required.

```bash
NATIVE_NAME=vordr-native-$(date +%s)

gcloud compute instances create "$NATIVE_NAME" \
    --zone=us-central1-a \
    --machine-type=c3-standard-8 \
    --source-snapshot=vordr-vllm-base \
    --boot-disk-size=200GB

NATIVE_IP=$(gcloud compute instances describe "$NATIVE_NAME" --zone=us-central1-a \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)')

echo "NATIVE_NAME=$NATIVE_NAME"
echo "NATIVE_IP=$NATIVE_IP"

# Snapshot-booted VMs are NOT carrying over the `nkoirala` SSH user
# that was injected by the commissioning flow. Re-inject the pubkey
# via instance metadata so the guest agent adds it to
# ~nkoirala/.ssh/authorized_keys.
gcloud compute instances add-metadata "$NATIVE_NAME" \
    --zone=us-central1-a \
    --metadata ssh-keys="nkoirala:$(cat ~/.ssh/vordr_id_rsa.pub)"

# If the project has OS Login enabled, override per-instance so plain
# ssh with -i ~/.ssh/vordr_id_rsa works (run_experiment.sh needs this
# — it does not use gcloud ssh):
gcloud compute instances add-metadata "$NATIVE_NAME" \
    --zone=us-central1-a \
    --metadata enable-oslogin=FALSE

# Wait ~20s for the guest agent to sync the metadata, then probe.
sleep 20

# If your driver public IP changed since you set the firewall rule,
# refresh it:
gcloud compute firewall-rules update vordr-eval-ports \
    --source-ranges="$(curl -s ifconfig.me)/32" 2>/dev/null || true

# SSH probe
ssh -o StrictHostKeyChecking=no -i ~/.ssh/vordr_id_rsa \
    nkoirala@"$NATIVE_IP" 'uname -a && docker images vllm-cpu:local'
```

The `docker images` check should show `vllm-cpu:local` already present
from the snapshot. If not, the snapshot didn't capture the image — stop
and debug before proceeding.

**If the SSH probe still fails with `Permission denied (publickey)`:**
fall back to `gcloud compute ssh nkoirala@"$NATIVE_NAME" --zone=us-central1-a`
to get in and inspect the VM. Then check `sudo cat ~nkoirala/.ssh/authorized_keys`
on the VM to confirm the guest agent picked up the metadata.

---

## Step 3 — Smoke-test `native`

```bash
export OUT_DIR=~/sgx-tdx-composition-protocol/evaluation/results/llm/native-smoke-$(date +%s)/native/30s_cold_no-updates
mkdir -p "$OUT_DIR"

./run_experiment.sh \
    --condition native \
    --model-key phi3-mini \
    --log-size cold --interleave no-updates \
    --target-host "$NATIVE_IP" --target-user nkoirala \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps 1 --warmup-sec 30 --duration-sec 120 \
    --num-prompts 30 \
    --via-docker --docker-image vllm-cpu:local \
    --out-dir "$OUT_DIR"
```

**Expect:**

- No agent launch
- No attestation driver
- `[orch] IMA entry count at t0: -1` (native has no IMA — that's fine)
- Bench completes 30/30
- `run.json` has `"ima_count_start": -1, "ima_count_end": -1`
- `[orch] done → $OUT_DIR`

If it runs clean, the `native` branch is good.

---

## Step 4 — RPS calibration on `native` (picks fixed RPS for the matrix)

Five short runs at increasing RPS. Where achieved `request_throughput`
stops tracking target RPS = saturation. Pick **80% of saturation** as
the fixed RPS for all 24 phi3-mini matrix cells.

```bash
CALIB_ROOT=~/sgx-tdx-composition-protocol/evaluation/results/llm/rps-calib-phi3-$(date +%s)

for RPS in 1 2 4 8 16; do
    OUT="$CALIB_ROOT/native/rps${RPS}"
    mkdir -p "$OUT"
    ./run_experiment.sh \
        --condition native \
        --model-key phi3-mini \
        --log-size cold --interleave no-updates \
        --target-host "$NATIVE_IP" --target-user nkoirala \
        --ssh-key ~/.ssh/vordr_id_rsa \
        --rps "$RPS" --warmup-sec 20 --duration-sec 90 \
        --num-prompts 60 \
        --via-docker --docker-image vllm-cpu:local \
        --out-dir "$OUT"
done

# Join all five into one table
python3 collect_results.py --root "$CALIB_ROOT"

# Quick look — compare target vs achieved req/s
column -t -s, "$CALIB_ROOT/all_runs.csv" | \
    awk 'NR==1 || /native/ {print $0}' | \
    cut -d' ' -f1-12
```

Eyeball the `req_per_s` column. The point where increasing target RPS
stops raising achieved req/s is saturation. Record the chosen
`RPS_PHI3 = floor(0.8 * saturation_rps)` — you'll pass this value to
every phi3-mini matrix cell.

Total calibration time: ~25 min (5 runs × ~4 min each at the smaller RPS
values; faster at higher RPS).

---

## Step 5 — Teardown

Delete the `native` VM (you'll spin up a fresh one from the snapshot for
each matrix cell later).

```bash
gcloud compute instances delete "$NATIVE_NAME" --zone=us-central1-a --quiet
```

**Keep** the snapshot `vordr-vllm-base` — it's the parent for all 24
matrix VMs.

Also keep the existing validation CVM (`vordr-valid-…`) up if you plan
to use it as the `tdx-vordr` source; otherwise delete it and re-provision
from the snapshot when the matrix driver runs.

---

## What comes next (not this session)

After this runbook you will have:

- Confirmed `tdx-only` and `native` orchestrator branches work
- A re-usable boot-disk snapshot (`vordr-vllm-base`)
- A fixed phi3-mini RPS (80 % of saturation) to reuse across all cells

The next session tackles:

1. Edit `provision_vms.sh` to pass `--source-snapshot=vordr-vllm-base`.
2. Bake IMA-policy-load into a CVM startup script (fixes PCR mismatch
   from Step 2a being missed on first boot).
3. Write `run_matrix.sh` — top-level iterator over the 24 cells, with
   resumability (skip cells whose `summary.json` exists).
4. Kick off full phi3-mini sweep (~4 hrs).
5. Repeat for `llama31-8b`.

---

## Report-back checklist

After you finish Step 4, paste back:

1. `summary.json` from the `tdx-only` smoke run
2. `summary.json` from the `native` smoke run
3. The `all_runs.csv` from the calibration root
4. The RPS you picked for phi3-mini
