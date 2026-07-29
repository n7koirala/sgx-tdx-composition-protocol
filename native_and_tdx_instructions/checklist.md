# Native + tdx-only + RPS calibration — quick checklist

Tick each box as you go. Full runbook is in `README.md` in this folder.

## Step 0 — `tdx-only` smoke on existing CVM

- [ ] `OUT_DIR` exported and directory created
- [ ] `./run_experiment.sh --condition tdx-only …` kicked off against existing `$TARGET_IP`
- [ ] Orch log has NO `launching CVM attestation agent` line
- [ ] No `attest.csv` in `$OUT_DIR`
- [ ] Bench reaches `100%|██████████| 30/30`
- [ ] `[orch] done → …` printed
- [ ] `run.json`, `sampler.csv`, `vllm.json` all present

## Step 1 — Snapshot

- [ ] `gcloud compute disks list` confirms disk name matches instance
- [ ] `gcloud compute disks snapshot … --snapshot-names=vordr-vllm-base` succeeded
- [ ] `gcloud compute snapshots list` shows `vordr-vllm-base` READY

## Step 2 — Create `native` VM from snapshot

- [ ] `NATIVE_NAME` and `NATIVE_IP` exported
- [ ] SSH probe works
- [ ] `docker images vllm-cpu:local` on the native VM shows the image present
- [ ] Firewall source range covers current driver IP

## Step 3 — `native` smoke

- [ ] `OUT_DIR` created
- [ ] `./run_experiment.sh --condition native …` kicked off
- [ ] `[orch] IMA entry count at t0: -1` (expected on non-CVM)
- [ ] No attestation driver launched
- [ ] Bench 30/30 complete
- [ ] `run.json` shows `ima_count_start: -1, ima_count_end: -1`
- [ ] `[orch] done → …` printed

## Step 4 — RPS calibration on native

- [ ] `CALIB_ROOT` exported
- [ ] Loop over RPS=1,2,4,8,16 each writing under `$CALIB_ROOT/native/rps<N>/`
- [ ] All five runs produced `summary.json`
- [ ] `collect_results.py --root $CALIB_ROOT` produced `all_runs.csv`
- [ ] Identified saturation RPS (where achieved req/s plateaus)
- [ ] Recorded `RPS_PHI3 = floor(0.8 * saturation_rps)` for use in matrix

## Step 5 — Teardown

- [ ] `gcloud compute instances delete $NATIVE_NAME` (native VM gone)
- [ ] Snapshot `vordr-vllm-base` STILL EXISTS (do not delete)

## Red flags (stop and report if any)

- [ ] `docker images vllm-cpu:local` on snapshot-booted VM returns empty
      (snapshot didn't capture the image — do NOT proceed, debug first)
- [ ] Bench hangs mid-run or `KeyboardInterrupt` (check firewall source range)
- [ ] `req_per_s` collapses at low RPS (vLLM on CPU slower than expected —
      may need to raise `--duration-sec`)
- [ ] `IMA entry count at t0: -1` on `tdx-only` smoke (IMA sysfs missing —
      CVM may need IMA policy loaded if later running `tdx-vordr`)

## Report back

Paste when Step 4 is done:

1. `summary.json` from `tdx-only` smoke
2. `summary.json` from `native` smoke
3. `all_runs.csv` from calibration root
4. Picked `RPS_PHI3` value
