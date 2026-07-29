# Vordr NGINX-Workload Evaluation

The syscall- and TCP-stack-bound counterpart to `evaluation/llm_workload/`.
Where LLM was compute-bound (inference matmul dominates), NGINX exercises
the regime where any TDX or Vordr tax on the guest-kernel boundary is
most visible.

What the experiment proves:

| Comparison                          | Paper claim                                          |
| ----------------------------------- | ---------------------------------------------------- |
| `native` vs `tdx-only`              | Real TDX syscall tax (regime-dependent: high on /1kb) |
| `tdx-only` vs `tdx-vordr` (matched) | Vordr's *additional* overhead is small even here     |
| Epoch sweep on `tdx-vordr`          | Tail latency degrades gracefully as T shrinks        |

---

## Machine layout

This experiment uses **three** machines. Every command in this README
is tagged **[WEN]**, **[DRIVER]**, or **[TARGET]**.

| Machine    | Lives where           | Role                                  | What runs there                                                |
| ---------- | --------------------- | ------------------------------------- | -------------------------------------------------------------- |
| **WEN**    | your lab (`tjws-06`)  | Operator console                      | `gcloud` to provision DRIVER (one time); SSH to DRIVER         |
| **DRIVER** | GCP `us-central1-a`   | Load generator / orchestrator         | `wrk2`, `attestation_driver.py`, `run_experiment.sh`, `gcloud` for TARGET lifecycle |
| **TARGET** | GCP `us-central1-a` (per cell) | Workload host                | `nginx` (Docker), Vordr agent, `vm_sampler.py`                 |

**Why three machines?** Measured WEN→cloud RTT is ~21 ms. NGINX serving
a 1KB static file takes <1 ms of actual server work, so a WEN-driven
load generator would measure pure WAN latency, not the TDX or Vordr
overhead we care about. Co-locating the driver in the same zone as the
target gives sub-ms internal-IP RTT, restoring our measurement
sensitivity to the syscall-bound effects of interest.

**Workflow at a glance:**
1. **[WEN]** Provision DRIVER once (`provision_driver.sh`). Stays up
   for the whole campaign.
2. **[WEN]** SSH into DRIVER.
3. **[DRIVER]** Provision TARGET (`../llm_workload/provision_vms.sh`).
4. **[DRIVER]** Run cell (`run_experiment.sh` against TARGET's
   *internal* IP, not external).
5. **[DRIVER]** Tear down TARGET. Repeat 3–5 per cell.
6. **[WEN]** When the whole campaign is done, tear down DRIVER.

You will rarely touch TARGET manually — `run_experiment.sh` stages
everything over SSH for you.

---

## Status

**End-to-end harness is implemented**: per-cell orchestrator
(`run_experiment.sh`), 24-cell-per-payload matrix driver
(`run_matrix.sh`), per-cell + flat-table joiner (`collect_results.py`),
and 5-figure plotter (`plots/generate_plots.py`). Smoke + calibration
recipe is documented below; matrix recipe in §Step 9.

---

## Files (this directory)

| File                       | Runs on  | Purpose                                                          |
| -------------------------- | -------- | ---------------------------------------------------------------- |
| `provision_driver.sh`      | WEN      | One-time: creates DRIVER VM, installs wrk2 + deps, syncs repo + SSH key |
| `wrk2_install.sh`          | DRIVER   | Standalone wrk2 builder (also called by `provision_driver.sh`)   |
| `nginx.conf`               | TARGET   | Tuned config: epoll, reuseport, big backlog, no access log       |
| `nginx_server_launch.sh`   | TARGET   | Sysctl tuning + Docker run + readiness probe                     |
| `wrk2_wrapper.sh`          | DRIVER   | Two-phase wrk2 (warmup discarded → measure recorded)             |
| `parse_wrk2.py`            | DRIVER   | wrk2 stdout → wrk.json (vllm.json-shaped)                        |
| `run_experiment.sh`        | DRIVER   | Per-cell orchestrator (one cell = one TARGET VM lifecycle)       |
| `run_matrix.sh`            | DRIVER   | 24-cell-per-payload matrix driver, idempotent resume             |
| `collect_results.py`       | DRIVER   | Joins wrk.json + attest.csv + sampler.csv → summary.json + all_runs.csv |
| `plots/generate_plots.py`  | DRIVER   | Produces the 5 paper figures from all_runs.csv + raw artefacts   |

Reused unchanged from `../llm_workload/` (run on DRIVER):
- `provision_vms.sh` (creates a fresh TARGET from snapshot `vordr-vllm-base`; now also emits `CVM_INTERNAL_IP` and `CVM_ZONE`)
- `attestation_driver.py` (fires every T s, against TARGET internal IP)
- `vm_sampler.py` (staged onto TARGET, samples CPU/mem/IMA every 5 s)
- `update_injector.py` (fires apt@120s + pip@300s on TARGET)

The same snapshot works as-is — we just `docker pull nginx:1.27-alpine`
(~10 MB) instead of running vLLM.

### Code sync to TDX (don't skip this section)

The snapshot freezes the repo state at snapshot-creation time. Several
agent-side files have been modified in WEN's working tree since:
`research/sgx-tdx-attestation/certs/{ca,server}.{crt,key}` (TLS material)
and various Python helpers in `research/incremental_attestation/`. If
TDX runs the snapshot's stale copies, the most likely failure is a TLS
handshake error in the `attestation_driver` on WEN because the agent's
`server.crt` no longer chains to the CA the driver trusts.

`run_experiment.sh` handles this automatically: at every cell start
(after SSH preflight), it `rsync`'s `research/incremental_attestation/`
and `research/sgx-tdx-attestation/` from WEN → TDX, excluding local
artefacts (charts, CSVs, the `sgx-verifier/` subtree which is SGX-host
specific). Cost is ~2–5 s per cell and the rsync is delta-based so
re-runs are near-instant.

To opt out (e.g. running against an externally-managed TDX where you
explicitly want the snapshot version):
```bash
./run_experiment.sh ... --no-sync-repo
```

You should *not* opt out unless you have a reason. If you ever rotate
the certs or change the agent code on WEN, re-baking the snapshot is
optional — the rsync covers it.

---

## Matrix shape (built later, not yet)

```
native    × {cold,warm} × {no-updates,with-updates}            =  4 cells
tdx-only  × {cold,warm} × {no-updates,with-updates}            =  4 cells
tdx-vordr × {15,30,60,300}s × {cold,warm} × {no-updates,upd}   = 16 cells
TOTAL per payload                                          = 24
```

`no-updates` allows normal workload and service activity but performs no
intentional software installation during the measurement window.
`with-updates` additionally runs the controlled update injector.

Two payloads (`/1kb`, `/100kb`) → 48 cells total, with `N=3` reps on the
12 no-updates cells per payload and `N=1` on with-updates → ~9 hrs/payload
overnight.

---

## Step 1 — WEN prerequisites (one time, ~30 s)

**[WEN]** Confirm gcloud auth + SSH keypair:

```bash
gcloud auth list                                    # must be authenticated
gcloud config get-value project                     # confirm correct project
ls -l ~/.ssh/vordr_id_rsa ~/.ssh/vordr_id_rsa.pub   # both must exist
```

You **do not** need to install wrk2 on WEN — `provision_driver.sh`
installs it on the DRIVER for you. (`wrk2_install.sh` in this directory
is left available as a standalone helper; ignore it on WEN.)

---

## Step 2 — Provision the DRIVER VM (one time per campaign)

**[WEN]** Create the driver VM in `us-central1-a` and capture its
external IP into your shell:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/nginx_workload

eval "$(./provision_driver.sh --name nginx-driver)"
echo "DRIVER: $DRIVER_NAME @ $DRIVER_IP"
```

What this does (~3–5 min total):
1. Creates `nginx-driver` (c3-standard-8, no TDX) with `cloud-platform`
   scope so the driver can itself provision TARGET VMs without
   re-authenticating gcloud.
2. Injects WEN's pubkey (`~/.ssh/vordr_id_rsa.pub`) so you can SSH in.
3. Installs build deps + builds wrk2 (pinned commit) on the driver.
4. Installs Python deps (`cryptography`, `requests`) used by
   `attestation_driver.py` and `update_injector.py`.
5. Pushes WEN's SSH **private** key to the driver so the driver can
   SSH into TARGET VMs with the same key.
6. Rsyncs your repo working tree WEN → DRIVER (so any uncommitted
   edits in `research/incremental_attestation/` etc. are reflected).
7. Bash-syntax-checks `run_experiment.sh` on the driver.

The script is idempotent — re-running with the same `--name` reuses an
existing VM and just re-syncs the repo + SSH key.

**[WEN]** SSH into the driver and confirm wrk2 is there:

```bash
ssh -i ~/.ssh/vordr_id_rsa "$USER@$DRIVER_IP" \
    'cd sgx-tdx-composition-protocol/evaluation/nginx_workload && \
     ~/wrk2/wrk --version 2>&1 | head -1 && pwd'
```

Then SSH in for real and stay there for steps 3–7:

```bash
ssh -i ~/.ssh/vordr_id_rsa "$USER@$DRIVER_IP"

# Inside the driver from now on:
cd ~/sgx-tdx-composition-protocol/evaluation/nginx_workload
```

---

## Step 3 — Provision a TARGET VM (per cell)

**[DRIVER]** From inside the DRIVER, call the LLM workload's
provisioner. It prints `CVM_NAME=... CVM_IP=... CVM_INTERNAL_IP=... CVM_ZONE=...`
on success — `eval` it to export all four into your shell.

For a **native** TARGET (no TDX):
```bash
cd ~/sgx-tdx-composition-protocol/evaluation/nginx_workload
eval "$(../llm_workload/provision_vms.sh \
            --condition native \
            --name nginx-smoke-$(date +%s))"
echo "TARGET: $CVM_NAME  external=$CVM_IP  internal=$CVM_INTERNAL_IP"
```

For a **TDX-only** TARGET:
```bash
eval "$(../llm_workload/provision_vms.sh \
            --condition tdx-only \
            --name nginx-tdx-only-$(date +%s))"
```

For a **tdx-vordr** TARGET:
```bash
eval "$(../llm_workload/provision_vms.sh \
            --condition tdx-vordr \
            --name nginx-tdx-vordr-$(date +%s))"
```

**Critical: from now on, always use `$CVM_INTERNAL_IP` as
`--target-host`**, not `$CVM_IP`. Internal IP gives sub-ms RTT;
external IP would route over the public NAT and reintroduce the
21 ms WAN floor we just fixed.

Quick RTT sanity check from DRIVER:

```bash
ping -c 5 "$CVM_INTERNAL_IP"   # should show <1 ms RTT
```

---

## Step 4 — Run a single experiment cell (the smoke test)

This is the **first thing to do** with the new setup. Validates the
whole orchestration end-to-end at low RPS before you trust higher loads.

**[DRIVER]** With `$CVM_INTERNAL_IP` exported from step 3:

```bash
./run_experiment.sh \
    --condition native \
    --payload 1kb \
    --target-host "$CVM_INTERNAL_IP" --target-user "$USER" \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps 1000 --warmup-sec 10 --duration-sec 30 \
    --out-dir ../results/nginx/smoke-native-1kb-$(date +%s)
```

`run_experiment.sh` automatically:
1. Probes SSH to TARGET (over internal IP from DRIVER)
2. **Rsyncs `research/incremental_attestation/` and `research/sgx-tdx-attestation/` from DRIVER → TARGET** (so the agent runs the synced working-tree code, not the snapshot's frozen version). Disable with `--no-sync-repo`.
3. Stages `nginx_server_launch.sh`, `nginx.conf`, `vm_sampler.py` to `/tmp/` on TARGET
4. Captures NIC offload state on TARGET (forensics)
5. Launches nginx in Docker with host networking on TARGET
6. *(tdx-vordr only)* Launches the Vordr CVM attestation agent on TARGET
7. *(warm only)* Burns IMA log to ~100 K entries on TARGET
8. Computes a shared `t0` and aligns the sampler / attestation driver / wrk2
9. Runs wrk2 from DRIVER against TARGET (warmup phase, then measurement phase)
10. Tears down nginx + agent on TARGET, scp's `sampler.csv` + logs back to DRIVER
11. Writes the final per-cell `run.json` manifest

**Expected output directory contents:**
```
../results/nginx/smoke-native-1kb-.../
  run.json                    # cell manifest (condition, payload, t0, …)
  wrk.json                    # parsed wrk2 measure-phase output
  wrk.json.txt                # raw wrk2 measure-phase stdout
  wrk.json.warmup.txt         # raw wrk2 warmup-phase stdout (discarded data)
  wrk.log                     # wrk2_wrapper stdout
  sampler.csv                 # CPU/mem/IMA every 5s on TARGET
  nginx_server.log            # nginx Docker container stdout
  ethtool_offloads.txt        # NIC offload state on TARGET
  attest.csv  / attest.log    # tdx-vordr only
  updates.csv / updates.log   # with-updates only
  agent.log                   # tdx-vordr only
```

**[DRIVER]** Check the smoke output is sane:

```bash
python3 -c "
import json
j = json.load(open('../results/nginx/smoke-native-1kb-.../wrk.json'))
print('completed   :', j['completed'])
print('throughput  : %.1f rps' % j['request_throughput'])
print('p50 latency : %s ms' % j['latency_ms']['p50'])
print('p99 latency : %s ms' % j['latency_ms']['p99'])
print('errors      :', j['errors'])
"
```

Expected for native /1kb @ 1000 rps **with the new in-zone driver**:
- `completed` ≈ 30 000 (1000 × 30 s)
- `throughput` ≈ 1000 (within 1 %)
- **`p50` < 1 ms** (was 22.83 ms with WEN driver — that's the network fix proving itself)
- **`p99` < 5 ms** (was 254.72 ms)
- `errors` all zero

If `p50` is still > 5 ms, you accidentally passed `$CVM_IP` (external)
instead of `$CVM_INTERNAL_IP`. Stop and fix.

---

## Step 5 — RPS saturation calibration on native

Finds the RPS we'll fix for the matrix. Without this, the entire
experiment is meaningless: too low and we don't expose the TDX tax; too
high and wrk2's coordinated-omission correction inflates p99 into garbage.

**[DRIVER]** Sweep `/1kb` (reuse the same native TARGET from step 3/4):

```bash
ROOT=../results/nginx/calib-1kb-$(date +%Y%m%d)
for RPS in 1000 5000 10000 20000 30000 50000 75000; do
    OUT="$ROOT/rps-$RPS"
    [[ -f "$OUT/wrk.json" ]] && { echo "skip $RPS"; continue; }
    ./run_experiment.sh \
        --condition native --payload 1kb \
        --target-host "$CVM_INTERNAL_IP" --target-user "$USER" \
        --ssh-key ~/.ssh/vordr_id_rsa \
        --rps "$RPS" --warmup-sec 10 --duration-sec 60 \
        --out-dir "$OUT" || break
done
```

**[DRIVER]** Print a saturation table:

```bash
ROOT=../results/nginx/calib-1kb-$(date +%Y%m%d)
printf '%-10s %-12s %-10s %-10s %-10s %-10s\n' \
    target achieved p50_ms p99_ms timeouts non2xx
for d in "$ROOT"/rps-*; do
    python3 -c "
import json,os
d='$d'
j=json.load(open(os.path.join(d,'wrk.json')))
target=int(os.path.basename(d).split('-')[1])
print('%-10d %-12.0f %-10s %-10s %-10d %-10d' % (
    target, j['request_throughput'],
    j['latency_ms']['p50'], j['latency_ms']['p99'],
    j['errors']['timeout'], j['errors']['non2xx_3xx']))
"
done
```

**Pick the saturation point**: the **highest** RPS where all of these hold:
- `achieved` is within 1 % of `target`
- `timeouts == 0` and `non2xx == 0`
- `p99 < 2 × p50`

The matrix RPS for `/1kb` is **80 % of that saturation point**. Write it
down — you'll pass it to `run_matrix.sh` later.

**[DRIVER]** Repeat for `/100kb` (lower RPS, NIC-bound):

```bash
ROOT=../results/nginx/calib-100kb-$(date +%Y%m%d)
for RPS in 100 500 1000 2000 5000 10000; do
    OUT="$ROOT/rps-$RPS"
    [[ -f "$OUT/wrk.json" ]] && continue
    ./run_experiment.sh \
        --condition native --payload 100kb \
        --target-host "$CVM_INTERNAL_IP" --target-user "$USER" \
        --ssh-key ~/.ssh/vordr_id_rsa \
        --rps "$RPS" --warmup-sec 10 --duration-sec 60 \
        --out-dir "$OUT" || break
done
```

Expected ceiling: 1.5–3 K rps on c3-standard-8 (NIC-bound at ~2 Gbps × 100 KB).

---

## Step 6 — Verify the DRIVER isn't the bottleneck

Highest-risk failure mode: if `wrk` on the DRIVER saturates before the
TARGET does, the "TDX tax" measurement is contaminated by driver-side
overhead, not real TDX cost.

**[DRIVER]** While step 5's high-RPS run is in progress, in another
terminal SSH'd into the DRIVER:

```bash
top -b -n 5 -d 2 | grep -E "wrk|Cpu|MiB"
# or just `top` and look for the wrk process across its 4 threads
```

Look for:
- `wrk` CPU%: should be < ~90 % per thread (we use 4 threads → < 360 %
  out of 800 % on c3-standard-8). If pinned at the per-thread ceiling,
  the DRIVER is the bottleneck.
- Idle CPU %: should be ≥ 30 %.

If the DRIVER is the bottleneck, options:
- Bump `--threads` (matches `-t` to wrk2): `THREADS=8 ./run_experiment.sh ...`
- Bump `--connections` only if response time is also fine
- Provision a bigger DRIVER (re-run `provision_driver.sh --machine-type c3-standard-16`
  after deleting the existing driver)

---

## Step 7 — tdx-vordr smoke (verify the agent + attestation path)

**[DRIVER]** Tear down the native TARGET from step 5:

```bash
gcloud compute instances delete "$CVM_NAME" --zone="$CVM_ZONE" --quiet
```

**[DRIVER]** Provision a tdx-vordr TARGET, then run a short cell at
the calibrated RPS for /1kb:

```bash
eval "$(../llm_workload/provision_vms.sh \
            --condition tdx-vordr \
            --name nginx-tdx-vordr-smoke-$(date +%s))"

CALIB_RPS_1KB=<paste from step 5>     # e.g. 30000

./run_experiment.sh \
    --condition tdx-vordr --payload 1kb --epoch-sec 30 \
    --log-size cold --interleave no-updates \
    --target-host "$CVM_INTERNAL_IP" --target-user "$USER" \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps "$CALIB_RPS_1KB" \
    --warmup-sec 30 --duration-sec 120 \
    --out-dir ../results/nginx/smoke-tdx-vordr-1kb-$(date +%s)
```

**[DRIVER]** Verify the attestation rounds happened:

```bash
OUT=../results/nginx/smoke-tdx-vordr-1kb-...
wc -l "$OUT/attest.csv"               # ~5 lines: header + 4 rounds (120s / 30s)
column -t -s, "$OUT/attest.csv" | head
# Every row should show pcr_match=True
```

**[DRIVER]** Tear down the TARGET, but leave the DRIVER running:

```bash
gcloud compute instances delete "$CVM_NAME" --zone="$CVM_ZONE" --quiet
```

You're now ready for the full matrix.

---

## Step 8 — Tear down the DRIVER (campaign end only)

When the entire experiment campaign is finished and all results are
copied off the DRIVER:

**[DRIVER]** Pull results back to WEN first (run from WEN):

```bash
# On WEN:
rsync -av -e "ssh -i ~/.ssh/vordr_id_rsa" \
    "$USER@$DRIVER_IP:sgx-tdx-composition-protocol/evaluation/results/nginx/" \
    ~/sgx-tdx-composition-protocol/evaluation/results/nginx/
```

**[WEN]** Delete the DRIVER:

```bash
gcloud compute instances delete "$DRIVER_NAME" \
    --zone="$DRIVER_ZONE" --quiet
```

---

## Risks to validate during smoke (before scaling up)

- **DRIVER saturation** — see step 6. Most common at >10 K rps on /1kb.
- **Coordinated-omission inflation** — `wrk.json.txt` shows the
  "Thread calibration: ..." warnings persisting beyond a few iterations,
  or `request_throughput << target rps` in `wrk.json`. Fix: drop RPS.
- **Ephemeral-port exhaustion** on TARGET — `errors.connect > 0` or
  `errors.timeout > 0` at low RPS suggests sysctl tuning didn't apply.
  Fix: confirm `sudo -n` works on TARGET (`ssh "$USER@$CVM_INTERNAL_IP" 'sudo -n true'`);
  the snapshot must have NOPASSWD configured.
- **External vs internal IP** — if `p50` is in the 20-ms range, you're
  routing through the public NAT instead of the VPC. Re-check that
  `--target-host` was `$CVM_INTERNAL_IP`, not `$CVM_IP`.
- **NIC offloads diverge** — spot-check `ethtool_offloads.txt` between a
  native cell and a tdx-only cell. If they differ significantly (e.g.
  `tx-checksumming: on` on native, `off` on TDX), call it out in the
  paper's methodology section as a confound.
- **Docker host networking on TARGET** — historically flaky on some CVM
  configs. If `nginx` doesn't reach ready state, check `nginx_server.log`
  in the cell directory.

---

## Quick-reference command cheat sheet

```bash
# ───────────────── [WEN] one-time ─────────────────
cd ~/sgx-tdx-composition-protocol/evaluation/nginx_workload

# Provision DRIVER (idempotent — safe to re-run to re-sync repo/SSH key)
eval "$(./provision_driver.sh --name nginx-driver)"
echo "DRIVER: $DRIVER_NAME @ $DRIVER_IP"

# SSH into DRIVER (stay there for everything below)
ssh -i ~/.ssh/vordr_id_rsa "$USER@$DRIVER_IP"

# ───────────── [DRIVER] per cell (smoke / calib) ──────────────
cd ~/sgx-tdx-composition-protocol/evaluation/nginx_workload

# 1. Provision a TARGET (any condition)
eval "$(../llm_workload/provision_vms.sh \
            --condition <native|tdx-only|tdx-vordr> \
            --name nginx-<tag>-$(date +%s))"
echo "TARGET: $CVM_NAME  internal=$CVM_INTERNAL_IP"

# 2. RTT sanity (should be sub-ms)
ping -c 3 "$CVM_INTERNAL_IP"

# 3. Single cell (native|tdx-only)
./run_experiment.sh \
    --condition native --payload 1kb \
    --target-host "$CVM_INTERNAL_IP" --target-user "$USER" \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps 1000 --warmup-sec 10 --duration-sec 30 \
    --out-dir ../results/nginx/smoke-native-1kb

# 4. Single cell (tdx-vordr)
./run_experiment.sh \
    --condition tdx-vordr --payload 1kb \
    --epoch-sec 30 --log-size cold --interleave no-updates \
    --target-host "$CVM_INTERNAL_IP" --target-user "$USER" \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps 25000 --warmup-sec 30 --duration-sec 120 \
    --out-dir ../results/nginx/smoke-tdx-vordr-1kb

# 5. Inspect a cell's wrk2 result
python3 -c "
import json,sys
j=json.load(open(sys.argv[1]))
print('rps  :', j['request_throughput'])
print('p50  :', j['latency_ms']['p50'], 'ms')
print('p99  :', j['latency_ms']['p99'], 'ms')
print('errs :', j['errors'])
" ../results/nginx/smoke-.../wrk.json

# 6. Inspect attestation rounds (tdx-vordr only)
column -t -s, ../results/nginx/smoke-.../attest.csv | head

# 7. Teardown TARGET (DRIVER stays)
gcloud compute instances delete "$CVM_NAME" --zone="$CVM_ZONE" --quiet

# ─────────── [DRIVER] full matrix, post-process, plot ───────────
# In tmux on the DRIVER (matrix runs ~7-8 hrs per payload):
tmux new -s matrix
./run_matrix.sh --payload 1kb  --rps <calib> --root ../results/nginx/matrix-1kb-$(date +%Y%m%d)
./run_matrix.sh --payload 100kb --rps <calib> --root ../results/nginx/matrix-100kb-$(date +%Y%m%d)
# detach: Ctrl-b d. reattach: tmux attach -t matrix

# Joiner + plotter
python3 collect_results.py --root ../results/nginx/matrix-1kb-...
python3 plots/generate_plots.py \
    --roots ../results/nginx/matrix-1kb-...,../results/nginx/matrix-100kb-...

# ──────────────── [WEN] campaign teardown ────────────────
# Pull results back to WEN, then delete the DRIVER:
rsync -av -e "ssh -i ~/.ssh/vordr_id_rsa" \
    "$USER@$DRIVER_IP:sgx-tdx-composition-protocol/evaluation/results/nginx/" \
    ~/sgx-tdx-composition-protocol/evaluation/results/nginx/
gcloud compute instances delete "$DRIVER_NAME" --zone="$DRIVER_ZONE" --quiet
```

---

## Output layout

```
evaluation/results/nginx/<root>/
  <condition>/
    <epoch>s_<log>_<interleave>_<payload>[_rep<N>]/
      run.json
      wrk.json              # parsed wrk2 measurement output
      wrk.json.txt          # raw wrk2 measure stdout
      wrk.json.warmup.txt   # raw wrk2 warmup stdout (discarded data)
      wrk.log
      attest.csv            # tdx-vordr only
      sampler.csv
      updates.csv           # with-updates only
      ethtool_offloads.txt
      nginx_server.log
      *.log
  all_runs.csv              # produced later by collect_results.py
  figures/                  # produced later by plots/generate_plots.py
```

---

## Step 9 — Run the matrix (after smoke + calibration pass)

The matrix is the long-running, expensive part. Do it in **tmux** on the
DRIVER so a flaky SSH session from WEN won't kill it. Each payload is
a separate invocation (cleaner per-cell artefacts; identical to what
the LLM matrix did).

**[DRIVER]** Start a tmux session:

```bash
tmux new -s matrix
cd ~/sgx-tdx-composition-protocol/evaluation/nginx_workload
```

**[DRIVER]** Run the /1kb matrix (`--rps` = 80% of saturation from step 5):

```bash
./run_matrix.sh \
    --payload 1kb \
    --rps <CALIB_RPS_1KB> \
    --root ../results/nginx/matrix-1kb-$(date +%Y%m%d)
```

What the matrix does per cell:
1. Provisions a fresh TARGET (~2-3 min via snapshot).
2. Calls `run_experiment.sh` against the TARGET's internal IP.
3. Tears down the TARGET (unless `--keep-vms`).
4. Skips cells where `wrk.json` already exists — interrupted matrices
   resume cleanly with the same `--root`.

Cell budget per payload (defaults: 3 reps for no-updates, 1 for with-updates):
- native     × 2 log_sizes × (3 no-updates + 1 updates) =  8 cells
- tdx-only   × same                                  =  8 cells
- tdx-vordr  × 4 epochs × 2 log_sizes × same         = 32 cells
- **TOTAL per payload                                 = 48 cells**

At ~9 min/cell, that's **~7-8 hrs/payload**. Detach with `Ctrl-b d`.
Reattach with `tmux attach -t matrix`.

**[DRIVER]** When /1kb finishes, run /100kb the same way:

```bash
./run_matrix.sh \
    --payload 100kb \
    --rps <CALIB_RPS_100KB> \
    --root ../results/nginx/matrix-100kb-$(date +%Y%m%d)
```

### Matrix flags worth knowing

| Flag                       | Default        | When to use                              |
| -------------------------- | -------------- | ---------------------------------------- |
| `--no-updates-reps N`          | 3              | More reps → tighter error bars on fig3   |
| `--updates-reps N`         | 1              | Bump to 2 if fig3 with-updates is noisy  |
| `--duration-sec N`         | 300            | Longer = stabler tails; doubles cell time |
| `--warmup-sec N`           | 30             | Sufficient unless RPS very high          |
| `--threads N`              | 4              | Bump to 8 if DRIVER is the bottleneck    |
| `--connections N`          | 200            | Higher only if response time stays low   |
| `--only native,tdx-only`   | all 3          | Partial debug runs                       |
| `--dry-run`                | off            | Print plan, provision nothing            |
| `--keep-vms`               | off            | Debug a single failing cell              |

### Resuming an interrupted matrix

Just re-run with the same `--root`. Cells with existing `wrk.json` are
skipped; failures are retried. Failed cells re-provision a fresh VM, so
a transient quota / SSH glitch doesn't poison subsequent cells.

---

## Step 10 — Post-process (joins per-cell artefacts)

`run_matrix.sh` runs `collect_results.py` automatically at the end. To
re-run manually (e.g. after a partial matrix or hand-fixed cell):

```bash
python3 collect_results.py --root ../results/nginx/matrix-1kb-<DATE>
```

This produces:
- `<root>/<condition>/<cell-tag>/summary.json` — per-cell joined
  view of run.json + wrk.json + attest.csv + sampler.csv (with stats).
- `<root>/all_runs.csv` — flat one-row-per-cell table that drives all
  the plots and any custom analysis you want to do in pandas.

### Quick sanity checks on `all_runs.csv`

```bash
ROOT=../results/nginx/matrix-1kb-<DATE>

# How many cells per condition × interleave finished?
python3 -c "
import csv,collections
c=collections.Counter()
for r in csv.DictReader(open('$ROOT/all_runs.csv')):
    c[(r['condition'],r['interleave'])] += 1
for k,v in sorted(c.items()): print(k,v)
"

# Any PCR mismatches in the tdx-vordr cells? (Should be zero.)
python3 -c "
import csv
for r in csv.DictReader(open('$ROOT/all_runs.csv')):
    if r['condition']=='tdx-vordr' and int(r.get('pcr_mismatches','0') or 0)>0:
        print('MISMATCH', r['run_dir'], r['pcr_mismatches'])
"
```

If a cell shows PCR mismatches, that's an attestation failure — the
agent on TARGET and the verifier on DRIVER disagreed on the IMA log /
PCR-10 state. Most common cause: the TLS certs got rotated on WEN
between the snapshot bake and now, and `--no-sync-repo` was used.
Re-run that cell with sync enabled.

`pcr_mismatches` in `all_runs.csv` is intentionally only the count of
rounds with `delta_n > 0` AND `pcr_match=False` — i.e. rounds where new
IMA entries should have verified but didn't. Rounds with no new entries
(`delta_n=0`) report `pcr_match=False` because the field doesn't apply,
and their `runtime_verdict` is `CLEAN_NO_DELTA`. Those aren't security
failures and aren't counted.

---

## Step 11 — Generate the figures

```bash
# Single-payload figures (uses just one root):
python3 plots/generate_plots.py --root ../results/nginx/matrix-1kb-<DATE>
# → ../results/nginx/matrix-1kb-<DATE>/figures/fig1..5.pdf

# Cross-payload figures (recommended — fig1/2/3 are 2-panel by payload):
python3 plots/generate_plots.py \
    --roots ../results/nginx/matrix-1kb-<DATE>,../results/nginx/matrix-100kb-<DATE> \
    --out-dir ../results/nginx/figures-$(date +%Y%m%d)
```

Outputs:

| Figure                                  | What it shows                                                |
| --------------------------------------- | ------------------------------------------------------------ |
| `fig1_throughput_by_condition.pdf`      | Two panels (1KB / 100KB). Bars: req/s × 3 conditions × no-updates/with-updates. Error bars from reps. |
| `fig2_latency_tail_by_condition.pdf`    | Two panels. Grouped p50/p95/p99/p999 across conditions. Log-y. |
| `fig3_matched_delta.pdf`                | **Headline.** (tdx-vordr − tdx-only) / tdx-only %, throughput + p99 latency, faceted by payload × log_size × interleave. |
| `fig4_epoch_sweep.pdf`                  | log-x epoch axis, p99 latency overhead %, one curve per payload. |
| `fig5_timeline.pdf`                     | Two-row timeline of one representative tdx-vordr cell: TARGET CPU% + Δn-per-round stem. Default cell: `30s_warm_with-updates_1kb_rep1`. |

To pick a different fig5 cell, pass `--root` containing only that one
matrix and the script will pick the first match. Or edit the `fig5_timeline`
defaults in `plots/generate_plots.py`.

---

## Step 12 — Pull results to WEN, tear down DRIVER

**[WEN]** When you're done:

```bash
# Copy results back from DRIVER
rsync -av -e "ssh -i ~/.ssh/vordr_id_rsa" \
    "$USER@$DRIVER_IP:sgx-tdx-composition-protocol/evaluation/results/nginx/" \
    ~/sgx-tdx-composition-protocol/evaluation/results/nginx/

# Delete the DRIVER
gcloud compute instances delete "$DRIVER_NAME" \
    --zone="$DRIVER_ZONE" --quiet
```

The DRIVER costs ~$0.40/hr (c3-standard-8), so a multi-day campaign is
~$30-40. Don't forget this teardown step.
