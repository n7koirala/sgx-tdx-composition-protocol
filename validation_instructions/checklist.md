# Quick Validation Checklist

Tick each box as you go. Full walkthrough is in README.md — this page is
a single-screen reference.

## Step 0 — Driver prereqs

- [ ] `gcloud auth list` shows the right account
- [ ] `gcloud config get-value project` = your eval project
- [ ] TDX-capable zone set (e.g. `us-central1-a`)
- [ ] `~/vllm/benchmarks/benchmark_serving.py` exists **and first line isn't `DEPRECATED`** (v0.6.3 pinned)
- [ ] `~/vordr-driver-venv` created, activated (`which python3` inside it)
- [ ] Venv has aiohttp, transformers, pillow, cryptography
- [ ] SSH keypair `~/.ssh/vordr_id_rsa{,.pub}` exists

## Step 1 — Provision

- [ ] `gcloud compute instances create --confidential-compute-type=TDX` succeeds
- [ ] `$TARGET_IP` captured from `accessConfigs[0].natIP` (external, not internal)
- [ ] SSH probe works: `ssh … 'uname -a'`
- [ ] `grep -c tdx /proc/cpuinfo` on CVM returns > 0
- [ ] IMA exposed: `ls /sys/kernel/security/ima/` shows `ascii_runtime_measurements`
- [ ] Firewall rule `vordr-eval-ports` allows 8000/8443 from `$DRIVER_IP`
- [ ] Passwordless sudo on CVM: `sudo -n true` → prints `SUDO_OK`

## Step 2 — Stage CVM

- [ ] Repo rsynced to `/home/$USER/sgx-tdx-composition-protocol/` on CVM
- [ ] **IMA policy loaded** (2a): `sudo cat /sys/kernel/security/ima/runtime_measurements_count` > 1 (re-run after any CVM reboot — policy is write-once per boot)
- [ ] CVM has: `python3-pip`, `curl`, `git`, `openssl`, `docker`
- [ ] `pip3 install --user cryptography psutil` completed on CVM
- [ ] 16 GB swap on CVM (`swapon --show` shows `/swapfile`)
- [ ] Re-ssh'd once after `usermod -aG docker` so group takes effect
- [ ] `docker build --build-arg max_jobs=2 -f docker/Dockerfile.cpu -t vllm-cpu:local .` completed
- [ ] `docker run --rm vllm-cpu:local --help` prints `vllm serve` usage
- [ ] `libtdx_attest.so` installed (else agent refuses to start)
- [ ] `research/sgx-tdx-attestation/certs/server.{crt,key}` exist on CVM (names exact)

## Step 3 — Agent dry-run

- [ ] `sudo python3 -u cvm_attestation_agent.py --port 8443` prints `Waiting for attestation requests…`
- [ ] IMA Entry Count line > 0
- [ ] Ctrl-C clean; no lingering python process

## Step 4 — Run the cell

- [ ] Orphan cleanup one-liner ran (no stale containers / processes)
- [ ] `./run_experiment.sh --condition tdx-vordr --model-key phi3-mini --num-prompts 30 --via-docker …` kicked off
- [ ] See `[orch] ssh reachable`
- [ ] See `[vllm] ready on :8000`
- [ ] See `[orch] agent confirmed listening on :8443`
- [ ] See `[orch] IMA entry count at t0: <N>` with `N > 1000` (not `1` or `-1` — `1` means IMA policy wasn't loaded)
- [ ] See `[orch] attestation driver pid=…`
- [ ] See `[orch] launching load generator`
- [ ] Bench progress bar reaches 100% (DO NOT Ctrl-C even if slow)
- [ ] See `[bench] done → …`
- [ ] See `[orch] done → …`

## Step 5 — Collect + inspect

- [ ] Orch log ends with `[orch] done → …` (if not, script was interrupted before teardown — manifest still OK thanks to preliminary write, but `ima_count_end` will be `null`)
- [ ] `collect_results.py` runs without error
- [ ] `summary.json`: `attest.rounds >= 4`
- [ ] `summary.json`: `attest.pcr_mismatches == 0`
- [ ] `summary.json`: `vllm.completed == 30`
- [ ] `attest.csv`: every row `pcr_match=True`
- [ ] `sampler.csv`: `ima_entry_count` monotonically non-decreasing, values > 0
- [ ] `run.json`: `ima_count_start` and `ima_count_end` both ≥ 1
- [ ] No Python tracebacks in any `*.log`

## Red flags (report back if any)

- [ ] `pcr_match=False` on any round
- [ ] `delta_n=0` on every round after round 0
- [ ] `runtime_verdict` not in {`CLEAN`, `CLEAN_NO_DELTA`}
- [ ] `vllm.completed` < 30
- [ ] `ima_entry_count = -1` everywhere (sudo-read of IMA failed)
- [ ] Only round 0 present in `attest.csv`

## Teardown

- [ ] `gcloud compute instances delete $TARGET_NAME --zone=$ZONE --quiet`
- [ ] (optional) `gcloud compute firewall-rules delete vordr-eval-ports`

## Report back

Paste these and I'll sign off or diagnose:

1. Full `summary.json`
2. First 20 lines of `attest.log` + `agent.log`
3. Last ~30 lines of `bench.log` (the `Serving Benchmark Result` block)
4. Any ticked red-flag box
