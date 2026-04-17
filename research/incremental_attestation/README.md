# Incremental Attestation Microbenchmark

This experiment measures the end-to-end latency of **incremental IMA attestation** for TDX Confidential VMs, comparing three approaches across varying baseline IMA log sizes and delta entries.

## Experiment Overview

### Setup

```
┌──────────────────────────┐                    ┌──────────────────────────┐
│   SGX Machine            │                    │   TDX CVM                │
│                          │    TLS/DCAP        │                          │
│   Subscriber:            │ ◀─────────────────▶│   CVM Agent:             │
│   • SGX Enclave (Gramine)│   attestation      │   • IMA log reader       │
│   • or Python server     │   protocol         │   • PCR 10 reader        │
│                          │                    │   • TDX DCAP quote gen   │
│   Benchmark Orchestrator │                    │   • IMA entry generator  │
└──────────────────────────┘                    └──────────────────────────┘
```

### Three Experimental Conditions

| # | Condition | CVM Agent Mode | Subscriber | IMA Read Cost |
|---|-----------|---------------|------------|---------------|
| 1 | **Non-Optimized** | Reopens IMA fd each epoch, seeks to offset | Python | O(N + Δn) |
| 2 | **Optimized (SGX)** | Keeps IMA fd open (persistent) | SGX Enclave via Gramine | O(Δn) |
| 3 | **Optimized (Python)** | Keeps IMA fd open (persistent) | Plain Python | O(Δn) |

### Independent Variables

| Variable | Values |
|----------|--------|
| **N** (baseline IMA entries) | 10,000 / 50,000 / 100,000 / 200,000 |
| **Δn** (new entries per epoch) | 100 / 500 / 1,000 / 5,000 / 10,000 / 15,000 |

### Measurements

| Metric | Description |
|--------|-------------|
| `t_server_ima_read_ms` | Server-side IMA log read time |
| `t_server_quote_ms` | TDX DCAP quote generation time |
| `t_connect_ms` | TLS handshake time |
| `t_response_ms` | Network transfer (includes server processing) |
| `t_quote_verify_ms` | DCAP quote verification on subscriber |
| `t_ima_verify_ms` | IMA entry verification on subscriber |
| `t_total_ms` | End-to-end attestation latency |

## Directory Structure

```
incremental_attestation/
├── README.md                   # This file
├── Makefile                    # Convenience targets
├── cvm_attestation_agent.py    # CVM-side attestation agent
├── generate_ima_baseline.py    # IMA baseline/delta generator
├── benchmark_incremental.py    # Main benchmark orchestrator
└── plot_results.py             # Publication-quality chart generator
```

## Prerequisites

- **TDX CVM** with IMA enabled, Intel DCAP packages, TLS certificates
- **SGX Machine** with Gramine installed (for SGX condition)
- **Shared TLS certificates** from `../sgx-tdx-attestation/certs/`
- Python 3.8+, `matplotlib`, `numpy` (for plotting)

## Quick Start

### Step 1: Start CVM Agent (on TDX CVM)

```bash
cd research/incremental_attestation

# Start agent (supports both non-optimized and optimized reads):
sudo python3 cvm_attestation_agent.py --port 8443 --method dcap

# Or via Makefile:
make agent METHOD=dcap
```

### Step 2: Run Benchmarks (on SGX/benchmark machine)

```bash
# ── Condition 1: Non-Optimized ──
make bench-non-optimized TDX_HOST=<CVM_IP>

# ── Condition 2: Optimized (Python, no SGX) ──
make bench-optimized-python TDX_HOST=<CVM_IP>

# ── Condition 3: Optimized (SGX) ──
# First build Gramine manifest if not already done:
make -C ../sgx-tdx-attestation/sgx-verifier all
# Then run:
make bench-optimized-sgx TDX_HOST=<CVM_IP>
```

Each benchmark will prompt you to generate IMA entries on the CVM. Follow the prompts:

```
>>> Ensure CVM IMA log has 10,000 entries.
>>> On CVM: sudo python3 generate_ima_baseline.py --target 10000
>>> Press Enter when ready...

>>> Generate 100 new entries on CVM:
>>> sudo python3 generate_ima_baseline.py --delta 100
>>> Press Enter when done...
```

### Step 3: Generate Charts

```bash
# Merge all result CSVs:
make merge-csv

# Generate charts:
make plot CSV=results_all.csv
```

## Running Individual Commands

### CVM-Side

```bash
# Check current IMA count:
make ima-status

# Generate baselines:
make ima-baseline-10k
make ima-baseline-50k
make ima-baseline-100k
make ima-baseline-200k

# Generate deltas:
make ima-delta-100
make ima-delta-500
make ima-delta-1000
make ima-delta-5000
make ima-delta-10000
make ima-delta-15000
```

### Subscriber-Side

```bash
# Dry run (see experiment matrix):
make dry-run

# Custom experiment matrix:
python3 benchmark_incremental.py \
    --tdx-host <CVM_IP> \
    --mode non_optimized \
    --baselines 10000,50000 \
    --deltas 100,1000,10000 \
    --repeats 5 \
    --output my_results.csv
```

## Important Notes

1. **IMA entries persist until reboot.** Run baselines in order: 10K → 50K → 100K → 200K. Between each N, deltas accumulate. A reboot is needed to reset fully.

2. **Non-optimized mode is significantly slower** for large N. The server must seek through the kernel's doubly-linked list from HEAD to reach the offset.

3. **The CVM agent supports both modes simultaneously.** The subscriber tells the agent which mode to use via the `read_mode` field in each request.

4. **SGX condition** requires the Gramine manifest to include `benchmark_incremental.py` as a trusted file. Update `verifier.manifest.template` if needed.

## Output

### CSV Format

The benchmarks produce CSV files with one row per attestation round:

| Column | Description |
|--------|-------------|
| `baseline_N` | Baseline IMA entries |
| `delta_n` | Delta entries for this round |
| `mode` | Experimental condition |
| `repeat` | Repeat number |
| `t_total_ms` | End-to-end latency |
| `t_server_ima_read_ms` | Server IMA read time |
| ... | (see code for full list) |

### Charts

The plotter produces 6 charts:
1. **Latency vs Δn** — subplots per N, lines per mode (log-log)
2. **Server Read Heatmap** — N × Δn matrix per mode
3. **SGX Overhead** — Python vs SGX bar chart
4. **Speedup** — Non-optimized / Optimized per (N, Δn)
5. **Time Breakdown** — Stacked bars by phase
6. **Combined Latency** — All modes and N values on one chart
