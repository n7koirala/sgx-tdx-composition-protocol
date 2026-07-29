# Vordr LLM-Workload Evaluation

End-to-end evaluation of Vordr's attestation overhead while a confidential
VM serves a vLLM-hosted LLM under an open-loop, community-standard load
generator. Produces the figures used in the evaluation section of the
CCS paper.

## Conditions (run all three per experiment)

| Condition   | Machine                                | TDX | IMA agent | Attestation | Purpose                          |
| ----------- | -------------------------------------- | --- | --------- | ----------- | -------------------------------- |
| `native`    | `c3-standard-*` (non-CVM)              |  —  |    —      |     —       | "cost of security" anchor        |
| `tdx-only`  | `c3-standard-*` CVM                    |  ✓  |    —      |     —       | "cost of TDX alone" anchor       |
| `tdx-vordr` | `c3-standard-*` CVM + agent + updates  |  ✓  |    ✓      |   every T s | full Vordr stack                 |

## Sweeps (tdx-vordr)

- **Attestation epoch** `T`: 15, 30, 60, 300 s
- **Baseline IMA log**: `cold` (~5–10 K entries, just-booted) or `warm`
  (~100 K, pre-burned via `generate_ima_baseline.py --target 100000`)
- **Update interleaving**: `no-updates` or `with-updates`
  - `no-updates` allows normal workload and service activity but performs no
    intentional software installation during the measurement window.
  - `with-updates` additionally runs apt at t+120 s and pip at t+300 s.

`native` and `tdx-only` run only the log-size × interleaving matrix (4 cells
each); `tdx-vordr` runs the full 4 × 2 × 2 = 16 cells. 24 runs total per model.

## Models

- `llama31-8b` → `TheBloke/Meta-Llama-3-8B-Instruct-AWQ` (4-bit AWQ, fits 14 GB)
- `phi3-mini`  → `microsoft/Phi-3-mini-4k-instruct`

Both served via `vllm.entrypoints.openai.api_server --device cpu`.

## Workload driver

The load generator is vLLM's own `benchmark_serving.py` with ShareGPT v3
unfiltered prompts, open-loop Poisson arrivals at fixed RPS. The wrapper
fetches the dataset on first run into `$DATASET_DIR` (default `~/datasets`).

Pick RPS once per model via a preliminary saturation run against
`native`, then fix at 80 % of saturation and reuse across all runs.

## Files

| File                          | Where it runs     | What it does                                   |
| ----------------------------- | ----------------- | ---------------------------------------------- |
| `provision_vms.sh`            | control VM        | Creates one target VM for the given condition  |
| `vllm_server_launch.sh`       | target VM         | Launches vLLM OpenAI server on CPU             |
| `vm_sampler.py`               | target VM         | Samples CPU/mem/IMA count every 5 s            |
| `attestation_driver.py`       | driver VM         | Fires attestation every T s; writes `attest.csv`|
| `bench_serving_wrapper.sh`    | driver VM         | Wraps vLLM `benchmark_serving.py`              |
| `update_injector.py`          | driver VM         | apt@t+120s, pip@t+300s via ssh or asp_client   |
| `run_experiment.sh`           | driver VM         | Inner-loop orchestrator (one run)              |
| `collect_results.py`          | anywhere          | Joins artifacts → `summary.json` + `all_runs.csv`|
| `plots/generate_plots.py`     | anywhere          | Produces the six paper figures                 |

All component timers align against a shared `t0` that the orchestrator
computes as `now() + 10 s` and passes as `--start-at-epoch`.

## Prerequisites

On the **driver VM**:
- `gcloud` authenticated against your project (for provisioning)
- vLLM sources checked out; set `VLLM_SRC=/path/to/vllm` (needed for
  `benchmark_serving.py`)
- Python deps used by the attestation driver:
  `pip install cryptography requests`  (already satisfied if the repo's
  commissioning-phase deps are installed)

On the **target VM** (for `tdx-vordr`):
- TDX enabled
- `/opt/vordr/cvm_attestation_agent.py` and `/opt/vordr/generate_ima_baseline.py`
  already staged by the commissioning phase

## One experiment run

```bash
# 1. Provision a fresh target VM for this condition.
eval "$(./provision_vms.sh --condition tdx-vordr --name vordr-eval-$(date +%s))"
# → exports CVM_NAME, CVM_IP, CVM_ID

# 2. Run the inner loop.
./run_experiment.sh \
    --condition tdx-vordr \
    --model-key phi3-mini \
    --epoch-sec 30 --log-size warm --interleave with-updates \
    --target-host "$CVM_IP" --target-user nkoirala \
    --ssh-key ~/.ssh/vordr_id_rsa \
    --rps 4 --warmup-sec 60 --duration-sec 300 \
    --out-dir ../results/llm/2026-04-21/tdx-vordr/30s_warm_updates

# 3. Tear down.
gcloud compute instances delete "$CVM_NAME" --zone=us-central1-a --quiet
```

## Full matrix

A top-level driver script (not yet written) would iterate the matrix and
call `run_experiment.sh` per cell. Each cell needs a fresh target VM, so
run time ≈ 24 runs × (3 min boot + 7 min run) ≈ 4 hrs wall-clock per model.

## Post-processing

```bash
# Joins vllm.json + attest.csv + sampler.csv under <root>/**/run.json
python3 collect_results.py --root ../results/llm/2026-04-21

# Produces six PDFs in <root>/figures/
python3 plots/generate_plots.py --root ../results/llm/2026-04-21
```

## Output layout

```
evaluation/results/llm/<timestamp>/
  <condition>/
    <epoch>s_<log>_<interleave>/
      run.json          # manifest (condition, epoch, t0, …)
      vllm.json         # benchmark_serving output (per-request + summary)
      attest.csv        # one row per attestation round (tdx-vordr only)
      sampler.csv       # CPU/mem/IMA every 5 s
      updates.csv       # apt/pip fire times (with-updates only)
      summary.json      # produced by collect_results.py
      *.log             # stdout/stderr of each component
  all_runs.csv          # one row per run (flat table for plotting)
  figures/              # PDFs
```

## Analysis outputs

Six figures matching the style of `research/incremental_attestation/charts_final/`:

1. **`fig1_throughput_by_condition.pdf`** — bars: req/s and out-tok/s for
   native / tdx-only / tdx-vordr × no-updates / with-updates (epoch=30 s).
2. **`fig2_ttft_tail_by_condition.pdf`** — p50 / p95 / p99 TTFT, same grouping.
3. **`fig3_epoch_sweep.pdf`** — twin-axis line plot: throughput and p99 TTFT
   overhead (%) vs epoch (log x), one curve per log size.
4. **`fig4_delta_n_histogram.pdf`** — pooled Δn distribution across one
   representative with-updates run (shows the heavy-tail driver of per-round cost).
5. **`fig5_timeline.pdf`** — per-request TTFT scatter + per-round Δn stem
   plot, aligned on the x-axis (reviewers can visually check tail/Δn coupling).
6. **`fig6_ima_growth.pdf`** — IMA entries/min across (log size, interleaving).
