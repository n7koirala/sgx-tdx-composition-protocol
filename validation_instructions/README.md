# Single-Cell Validation — Vordr LLM Workload Harness

Before committing to the full 24-cell matrix, we validate the harness on
**one cell** that exercises the most code with the least wall-clock cost.
If this cell produces clean artifacts end-to-end, the matrix driver can be
built and the real sweeps started.

## What we're validating

- Provisioning a TDX CVM and reaching it over SSH
- vLLM serving a small model on CPU (via pre-built CPU Docker image)
- The Vordr CVM attestation agent handling `optimized` incremental reads
- The **attestation driver** on the driver VM running on a fixed cadence,
  with correct rolling PCR-10 state
- The **in-VM sampler** capturing CPU/mem/IMA-count timeline
- The **load generator** (v0.6.3's `benchmark_serving.py` with ShareGPT)
- The **result collector** joining all artifacts into `summary.json`

## The cell

| Dimension    | Value             | Why                                                    |
| ------------ | ----------------- | ------------------------------------------------------ |
| Condition    | `tdx-vordr`       | Exercises agent + driver (most novel code paths)       |
| Model        | `phi3-mini`       | Fastest CPU cold-start; Llama-8B would add ~10 min     |
| Epoch        | `30 s`            | Paper's target sweet-spot                              |
| Log size     | `cold`            | Skip the 100 K warming step for now                    |
| Interleaving | `no-updates`      | Normal service activity; no intentional software installation |
| RPS          | `1`               | Low open-loop arrival rate (server will queue slower)  |
| Warmup       | `30 s`            | Shorter than the real 60 s; validation only            |
| Duration     | `120 s`           | Shorter than the real 300 s; 4 attestation rounds      |
| `num_prompts`| `30` (cap)        | Phi-3 on CPU ≈ 5 s/req; caps wall-clock to ~4 min      |

**Expected wall-clock (after one-time setup):**
- Fresh CVM boot: ~1–2 min
- vLLM container start + model download (first time, cached after): ~7–10 min
- Actual bench run: ~4 min
- Collector + teardown: ~30 s

**One-time setup cost per CVM** (model pull into docker image cache + vLLM
CPU image build): ~60–90 min the very first time. Reusable via GCE disk
snapshot for the full matrix — see note at the end.

---

## Step 0 — Driver prerequisites

On the machine you'll run the orchestrator from (your **driver** — can
be your workstation; doesn't need to be in GCP):

```bash
# GCP SDK authenticated against the right project:
gcloud auth list
gcloud config get-value project
gcloud config get-value compute/zone     # should be a TDX-capable zone (e.g. us-central1-a)

# vLLM sources on the driver — PIN TO v0.6.3. Newer tags converted
# benchmark_serving.py into a deprecation shim that forwards to
# `vllm bench serve`, which requires the full vllm package installed
# (which we specifically can't install on the driver). v0.6.3 is the
# last tag where the script is a self-contained ~800-line async client.
if [[ ! -f "$HOME/vllm/benchmarks/benchmark_serving.py" ]] || \
   head -1 "$HOME/vllm/benchmarks/benchmark_serving.py" | grep -q DEPRECATED; then
    rm -rf "$HOME/vllm"
    git clone --depth 1 --branch v0.6.3 https://github.com/vllm-project/vllm.git "$HOME/vllm"
fi
export VLLM_SRC="$HOME/vllm"

# Ubuntu 23.04+ blocks system-pip with PEP 668. Use a venv; every python3
# call the orchestrator makes inherits the activated environment.
if [[ ! -d "$HOME/vordr-driver-venv" ]]; then
    python3 -m venv "$HOME/vordr-driver-venv"
fi
source "$HOME/vordr-driver-venv/bin/activate"
pip install -q aiohttp tqdm numpy transformers datasets pandas pillow \
                cryptography requests

# SSH key the CVM will trust (see Step 1).  Should NOT be your personal key.
if [[ ! -f ~/.ssh/vordr_id_rsa ]]; then
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/vordr_id_rsa -N ""
fi
```

**Re-open a new shell later?** Rerun the venv activation + `export VLLM_SRC`:
```bash
source "$HOME/vordr-driver-venv/bin/activate"
export VLLM_SRC="$HOME/vllm"
```

---

## Step 1 — Provision the target CVM

For the first validation we **bypass `asp_client`** and provision the CVM
directly with `gcloud`. This isolates "does the eval harness work" from
"does the commissioning phase work" — those are separate pieces and the
commissioning phase is already validated.

```bash
TARGET_NAME="vordr-valid-$(date +%s)"
ZONE="us-central1-a"                      # must be a TDX-capable zone
MACHINE_TYPE="c3-standard-8"              # 32 GB RAM, 8 vCPU
PUBKEY_PATH="$HOME/.ssh/vordr_id_rsa.pub"

gcloud compute instances create "$TARGET_NAME" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --confidential-compute-type=TDX \
    --maintenance-policy=TERMINATE \
    --boot-disk-size=200GB \
    --metadata="ssh-keys=$(whoami):$(cat $PUBKEY_PATH)"

# Grab the EXTERNAL IP — driver is off-VPC so the internal IP won't work.
TARGET_IP=$(gcloud compute instances describe "$TARGET_NAME" --zone="$ZONE" \
              --format='value(networkInterfaces[0].accessConfigs[0].natIP)')
echo "TARGET_IP=$TARGET_IP"
```

**SSH sanity-check:**
```bash
ssh -o StrictHostKeyChecking=no -i ~/.ssh/vordr_id_rsa \
    "$(whoami)@$TARGET_IP" 'uname -a; grep -c tdx /proc/cpuinfo'
```
Expect a kernel string and tdx count > 0.

**Open CVM ports 8000 (vLLM) + 8443 (agent) to the driver.** GCE blocks
all inbound except SSH by default — without this, Step 4 will fail at
"launching load generator" with `ClientConnectorError`:
```bash
DRIVER_IP=$(curl -s ifconfig.me)
gcloud compute firewall-rules create vordr-eval-ports \
    --direction=INGRESS --action=ALLOW \
    --rules=tcp:8000,tcp:8443 \
    --source-ranges="${DRIVER_IP}/32" \
    2>/dev/null || echo "rule already exists — OK"
```
This rule persists across CVMs. Delete on full teardown:
`gcloud compute firewall-rules delete vordr-eval-ports`.

**Enable passwordless sudo on the CVM.** The orchestrator launches the
agent + sampler under `sudo -n`; a password prompt would hang ssh
indefinitely:
```bash
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP" \
    'echo "'$(whoami)' ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/'$(whoami)'-nopw \
     && sudo chmod 440 /etc/sudoers.d/'$(whoami)'-nopw \
     && sudo -n true && echo SUDO_OK'
```

---

## Step 2 — Stage the repo + dependencies on the CVM

The agent has **relative imports** into sibling files (`ima_pcr_verify.py`,
`../sgx-tdx-attestation/common/protocol.py`), so it must be launched from
its own directory. Simplest: rsync the whole repo onto the CVM at the
same absolute path it has on the driver.

```bash
REPO_LOCAL="$HOME/sgx-tdx-composition-protocol"
REPO_CVM="/home/$(whoami)/sgx-tdx-composition-protocol"

rsync -avz -e "ssh -i ~/.ssh/vordr_id_rsa" \
    --exclude '.git' --exclude '__pycache__' --exclude 'papers/' \
    --exclude 'gemini_experiments/' --exclude 'evaluation/results/' \
    "$REPO_LOCAL/" "$(whoami)@$TARGET_IP:$REPO_CVM/"
```

### 2a — Enable IMA measurement policy (run after every CVM boot)

The CVM's kernel has IMA compiled in, but on Ubuntu 22.04 TDX images the
runtime measurement policy is **not loaded by default** — so the IMA log
stays at 1 entry (just `boot_aggregate`) and nothing gets measured. We
have to load a policy that tells IMA what to measure.

The policy file `/sys/kernel/security/ima/policy` is **write-once per
boot**: all rules must go in a single write, after which it locks until
reboot. Meaning: if the CVM ever gets hard-reset (e.g., OOM recovery
during the Docker build in Step 2c), re-run this block before Step 4.

```bash
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP" bash <<'REMOTE'
set -e

# 1. Ensure securityfs is mounted (required for IMA).
if ! mountpoint -q /sys/kernel/security 2>/dev/null; then
    sudo mount -t securityfs securityfs /sys/kernel/security
fi

# 2. Load all rules in a single write (BPRM=executables, MMAP=libraries, MODULE=kernel modules).
printf 'measure func=BPRM_CHECK\nmeasure func=MMAP_CHECK mask=MAY_EXEC\nmeasure func=MODULE_CHECK\n' \
    | sudo tee /sys/kernel/security/ima/policy > /dev/null

# 3. Verify — should be growing within a second.
sleep 1
IMA_COUNT=$(sudo cat /sys/kernel/security/ima/runtime_measurements_count)
echo "IMA entry count: $IMA_COUNT"
[ "$IMA_COUNT" -gt 1 ] && echo "IMA_OK" || { echo "IMA policy did not load" >&2; exit 1; }
REMOTE
```

Expect `IMA_OK` and a count in the thousands (kernel modules alone add
several hundred right after policy load). If the write fails with
"device or resource busy", the policy is already locked — which means
either it was already loaded (safe to proceed) or something wrote an
empty policy (requires reboot to clear).

### 2b — System deps + Python harness deps

```bash
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP" bash <<'REMOTE'
set -e
sudo apt-get update -y
sudo apt-get install -y python3-pip curl git openssl
pip3 install --user cryptography psutil

# Docker.
if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER"
fi

# 16 GB swap — the Dockerfile.cpu compile can momentarily spike past
# 32 GB RAM. If it does, oom-killer takes out sshd and the VM goes
# unreachable. Swap gives headroom so the build completes.
if [[ ! -f /swapfile ]]; then
    sudo fallocate -l 16G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
fi
free -h
REMOTE
```

After `usermod`, **exit the ssh session and re-ssh** before the next step
so the new `docker` group membership takes effect. (Or prefix docker
commands with `sudo`.)

### 2c — Build the vLLM CPU image

vLLM has no prebuilt CPU wheel on PyPI, **no pre-built CPU image on
Docker Hub** (`vllm/vllm-openai` only publishes CUDA tags), and
source-building on the host fails on Ubuntu 22.04's oneDNN v2.x (vLLM
needs v3.x API). Build the CPU image from the project's own
`docker/Dockerfile.cpu` — it encapsulates oneDNN + build tools inside
the container, avoiding the host mess.

```bash
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP" bash <<'REMOTE'
set -e
# Dockerfile.cpu defaults max_jobs=32 which OOMs any machine under
# ~128 GB RAM. max_jobs=2 keeps us below the 32 GB ceiling.
rm -rf /tmp/vllm-src
git clone --depth 1 https://github.com/vllm-project/vllm.git /tmp/vllm-src
cd /tmp/vllm-src
sudo docker build --build-arg max_jobs=2 \
    -f docker/Dockerfile.cpu -t vllm-cpu:local .
REMOTE
```

**Expected time: 45–70 min** (first build only — cached thereafter). The
progress bar will linger at `[vllm-build 7/7]` for ~40 min while CMake
compiles ~470 C++ kernel objects two-at-a-time.

**If the build hangs and ssh stops responding:** it OOM'd despite swap.
Hard-reset the VM (`gcloud compute instances reset "$TARGET_NAME" --zone="$ZONE"`)
and rerun 2a (IMA re-load — the reset wiped the policy), 2b, and 2c.

**Sanity-check:**
```bash
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP" \
    'docker images vllm-cpu:local && docker run --rm vllm-cpu:local --help | head -5'
```
Expect the image listed (~5 GB) and the help output showing
`usage: vllm serve [model_tag] [options]`.

The harness defaults `--docker-image` to `vllm-cpu:local`; override with
`--docker-image <ref>` only if you named it differently.

### 2d — Install libtdx_attest

The agent calls into `libtdx_attest.so` for DCAP quote generation.
Follow Intel's standard DCAP install for TDX guests. Symptom of it
missing: agent startup aborts with "libtdx_attest.so not found".
Run the following commands to install libtdx_attest:
```bash
cd ~/sgx-tdx-composition-protocol
sudo bash setup_tdx_cvm.sh --check
sudo bash setup_tdx_cvm.sh 
```


### 2e — Generate TLS certs for the agent

The agent resolves `server.crt` / `server.key` relative to its own
script dir — specifically `research/sgx-tdx-attestation/certs/`. Names
must be exactly `server.crt` / `server.key`:

```bash
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP" bash <<'REMOTE'
set -e
CERTS_DIR="$HOME/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"
openssl req -x509 -newkey rsa:4096 -sha256 -days 7 -nodes \
    -keyout server.key -out server.crt \
    -subj "/CN=vordr-cvm-agent" \
    -addext "subjectAltName = IP:127.0.0.1,IP:0.0.0.0,DNS:localhost"
chmod 600 server.key && chmod 644 server.crt
ls -l server.crt server.key
REMOTE
```

Driver runs with `--no-verify`, so self-signed is fine — no need to ship
the cert back to the driver.

---

## Step 3 — Dry-run the agent manually

Before the orchestrator drives it, prove the agent starts cleanly.
Running in the **foreground** avoids stdout buffering / nohup tricks
that can make failures invisible. From a fresh ssh session on the CVM:

```bash
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP"

# Now on the CVM:
cd ~/sgx-tdx-composition-protocol/research/incremental_attestation
sudo python3 -u cvm_attestation_agent.py --port 8443
```

Healthy output ends with:
```
TLS Certificate:   …/sgx-tdx-attestation/certs/server.crt
IMA Entry Count:   <N>
Supports Modes:    non_optimized, optimized
…
Waiting for attestation requests from subscribers...
```

`Ctrl-C` to stop, then `exit` back to the driver.

---

## Step 4 — Run the validation cell

From the driver, in the venv-activated shell:

```bash
cd $HOME/sgx-tdx-composition-protocol/evaluation/llm_workload

export VLLM_SRC="$HOME/vllm"            # v0.6.3 pinned
OUT_DIR="../results/llm/validation-$(date +%Y%m%d-%H%M%S)/tdx-vordr/30s_cold_no-updates"
mkdir -p "$OUT_DIR"

# Cleanup belt — kills any orphans from a prior attempt on the CVM or driver.
ssh -i ~/.ssh/vordr_id_rsa "$(whoami)@$TARGET_IP" \
    "sudo pkill -f cvm_attestation_agent.py; sudo pkill -f vm_sampler.py; docker rm -f vllm-phi3-mini-8000 2>/dev/null; true"
pkill -f attestation_driver.py 2>/dev/null
pkill -f benchmark_serving.py 2>/dev/null

./run_experiment.sh \
    --condition tdx-vordr \
    --model-key phi3-mini \
    --epoch-sec 30 \
    --log-size cold \
    --interleave no-updates \
    --target-host "$TARGET_IP" \
    --target-user "$(whoami)" \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps 1 \
    --warmup-sec 30 \
    --duration-sec 120 \
    --num-prompts 30 \
    --out-dir "$OUT_DIR" \
    --agent-dir "/home/$(whoami)/sgx-tdx-composition-protocol/research/incremental_attestation" \
    --via-docker \
    2>&1 | tee "$OUT_DIR/orch.log"
```

**Expected orchestrator lines, in order:**

1. `[orch] probing ssh to …` → `[orch] ssh reachable`
2. `[vllm] launching vllm-cpu:local → microsoft/Phi-3-mini-4k-instruct`
3. `[vllm] container started: …`
4. `[vllm] ready on :8000`  *(5–10 min first run while model downloads;
   < 1 min subsequent runs from the HF cache)*
5. `[orch] launching CVM attestation agent from …`
6. `[orch] agent confirmed listening on :8443`
7. `[orch] IMA entry count at t0: <N>`  *(should be > 0 — on a
   just-booted CVM it may be as low as 1–10)*
8. `[orch] aligning all components at t0=…`
9. `[orch] attestation driver pid=…`
10. `[orch] launching load generator (rps=1 warmup=30s dur=120s)`
11. Benchmark progress bar climbing 0% → 100% (~4 min total)
12. `[bench] done → …/vllm.json`
13. `[orch] done → …`

**Do NOT Ctrl-C if the progress bar looks slow** — at ~4.6–7.9 s/req on
CPU, 30 prompts at RPS=1 takes ~3–4 min to drain the queue. That's
expected; it's not stuck.

If Step 6 fails ("agent not listening after 16s"), the orchestrator will
automatically dump the last 40 lines of `/tmp/agent.log` from the CVM —
that's where to look.

---

## Step 5 — Run the collector + inspect outputs

```bash
python3 collect_results.py --root "$(dirname "$(dirname "$OUT_DIR")")"
cat "$OUT_DIR/summary.json" | python3 -m json.tool | head -60
```

**What healthy looks like (with `--num-prompts 30`):**

| Artifact              | Expect                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------- |
| `run.json`            | All fields populated; `t0_epoch` non-zero; `ima_count_end ≥ ima_count_start` (both ≥ 1)  |
| `vllm.json`           | `completed == 30`; TTFT median ~1–5 s on CPU; P99 may be 8–15 s                           |
| `attest.csv`          | 4–5 rows; `pcr_match=True` on every row; `delta_n` small (tens–hundreds) and accumulating |
| `sampler.csv`         | ~30 rows (≈150 s / 5 s); `ima_entry_count` monotonically non-decreasing; `cpu_pct` varies |
| `summary.json`        | `attest.rounds >= 4`; `attest.pcr_mismatches == 0`; `vllm.completed == 30`                |
| `agent.log`           | No Python tracebacks; one round-handled entry per attestation round                       |
| `bench.log`           | Ends with a `Serving Benchmark Result` summary table                                      |

**Red flags to report back:**

- `pcr_match=False` on any attestation round (PCR-10 replay bug)
- `delta_n=0` on every round after round 0 (agent not advancing fd)
- `runtime_verdict` anything other than `CLEAN` or `CLEAN_NO_DELTA`
- `vllm.completed < 30` (some requests timed out or errored)
- `ima_entry_count == -1` in every sampler row (sudo-read of IMA failed)
- Only round 0 present in `attest.csv`

---

## Step 6 — Tear down

```bash
gcloud compute instances delete "$TARGET_NAME" --zone="$ZONE" --quiet
```

Keep the firewall rule (`vordr-eval-ports`) in place if you'll provision
another CVM. Delete it when fully done:
```bash
gcloud compute firewall-rules delete vordr-eval-ports --quiet
```

---

## Step 7 — Report back

After the run, share:

1. `summary.json` (paste the whole thing).
2. First 20 lines of `attest.log` and `agent.log`.
3. The `Serving Benchmark Result` block from `bench.log`.
4. Any red flags from the table above.

If everything looks clean, the matrix driver can be built and we move on
to the full sweep (+ the warm / with-updates paths + the Llama model).

---

## Note — skipping Step 2b on future CVMs

Step 2b (the 45–70 min Docker image build) is the dominant wall-clock
cost per fresh CVM. For the 24-cell matrix you don't want to pay this
24 times. Two options, both cheap:

1. **Snapshot** after the first successful build:
   ```bash
   gcloud compute instances stop "$TARGET_NAME" --zone="$ZONE"
   gcloud compute images create vordr-eval-base --source-disk="$TARGET_NAME" --source-disk-zone="$ZONE"
   ```
   Subsequent CVMs use `--image=vordr-eval-base` instead of
   `--image-family=ubuntu-2204-lts`, and Step 2b becomes a no-op.
2. **`docker save` → GCS**: export the image tar, copy to a bucket, load
   on each CVM. Load takes ~1–2 min vs the 45–70 min rebuild.

Pick one of these *after* validation passes, not before.
