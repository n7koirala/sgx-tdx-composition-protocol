# Scalability Evaluation

This folder contains a paper-oriented benchmark harness for comparing:

- `Direct DCAP`: every end-user nonce triggers a fresh TDX quote.
- `Vordr (single WEN)`: one background TDX attestation refresh serves many end users.

## Files

- `run_direct_dcap_sweep.py`: reuses `research/tdx-dcap-attestation/dcap_with_library.py` and writes CSV/JSON summaries for the direct fresh-quote baseline.
- `vordr_server.py`: single-WEN service with cached verified TDX state; supports both lightweight and full-evidence responses.
- `run_vordr_sweep.py`: drives a concurrency sweep against one WEN and records throughput, latency, staleness, amplification, and full-evidence payload sizes.
- `generate_command_logs.py`: generates realistic ASP/WEN command audit logs for the full-evidence path.
- `generate_ima_workload.py`: generates file/exec activity on a CVM so the IMA event log grows before a benchmark run.
- `plot_scalability.py`: generates comparison figures from the resulting CSV files.
- `challenge.tex`: short formal paragraph for the paper's motivation/challenge section.

## Recommended First Targets

For a first credible single-WEN result, do not jump directly to `5000` end-user attestations/s. The better progression is:

1. Show the direct DCAP ceiling first:
   - `users = 1,2,4,8,16,32`
   - `count = 500` or `2000`
   - Expect throughput to flatten near the fresh-quote service rate.
2. Shake out the single-WEN fast path:
   - `users = 1,4,16,64,256`
   - `duration = 10s`
   - Start with the synthetic refresh backend to validate the harness.
3. Move to the real single-WEN run:
   - `users = 16,64,256,512,1024`
   - `duration = 10s` or `20s`
   - Use `--refresh-backend sgx-verifier` against a live TDX attestation server.

Paper-grade milestones to target in order:

- `>= 500` end-user attestations/s with stable p95/p99.
- `>= 1000` end-user attestations/s on one WEN.
- `>= 2000` end-user attestations/s if transport and proof verification stay cheap.
- `5000` end-user attestations/s only if the measurement is done with a realistic transport setup and the resulting p99 latency remains defensible.

## Example Commands

Direct DCAP sweep:

```bash
cd evaluation/scalability
sudo python3 run_direct_dcap_sweep.py \
  --method libtdx_attest \
  --counts 500,2000 \
  --users 1,2,4,8
```

Single-WEN dry run with synthetic background refresh:

```bash
cd evaluation/scalability
python3 run_vordr_sweep.py \
  --users 1,4,16,64,256,512 \
  --duration-s 10 \
  --refresh-backend synthetic \
  --synthetic-refresh-ms 42
```

Single-WEN run with real background attestation:

```bash
cd evaluation/scalability
python3 run_vordr_sweep.py \
  --users 16,64,256,512,1024 \
  --duration-s 10 \
  --refresh-backend sgx-verifier \
  --tdx-host <TDX_IP> \
  --tdx-port 8443 \
  --no-verify-tdx
```

Generate a command log bundle on the WEN machine:

```bash
cd evaluation/scalability
python3 generate_command_logs.py \
  --entries 2000 \
  --with-transition-log \
  --out-dir ../results/scalability/full-evidence-inputs
```

Generate more IMA activity on the TDX/CVM machine before a full-evidence run:

```bash
cd evaluation/scalability
python3 generate_ima_workload.py --count 500 --keep-files
```

Single-WEN run with the full evidence bundle (`quote + IMA log + PCR10 + command log`):

```bash
cd evaluation/scalability
python3 run_vordr_sweep.py \
  --users 16,64,256,512,1024 \
  --duration-s 10 \
  --evidence-mode full \
  --refresh-backend sgx-verifier \
  --tdx-host <TDX_IP> \
  --tdx-port 8443 \
  --command-log-file ../results/scalability/full-evidence-inputs/audit_log.jsonl \
  --no-verify-tdx
```

Plotting:

```bash
python3 plot_scalability.py \
  --direct-csv evaluation/results/scalability/direct-dcap-.../direct_dcap_summary.csv \
  --vordr-csv evaluation/results/scalability/vordr-single-wen-.../vordr_single_wen_summary.csv \
  --out-dir evaluation/results/scalability/figures
```

## Interpretation

The direct baseline should be reported as a fresh-quote system: each request forces quote generation. The Vordr benchmark should be reported as a cached-attestation system: the WEN amortizes one background TDX attestation over many end-user responses. The key comparison metric is therefore not just throughput, but also `amplification = successful_end_user_attestations / TDX_refreshes`.

For `--evidence-mode full`, the CSV also reports response payload sizes and the snapshot sizes of the raw quote, IMA log, and command log. That mode answers a different question from the lightweight mode: not just whether one WEN can serve many users, but whether it can serve many users while returning the full attestation evidence set that an end user would need to verify the CVM state independently.
