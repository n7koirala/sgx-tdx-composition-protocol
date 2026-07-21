# Re-running Figures 1, 2, 3, and 6 with Protocol 1.2

This procedure replaces the legacy IMA/PCR-only measurements with the current
Protocol 1.2 composed attestation path. Every recorded round verifies the TDX
DCAP quote and nonce, the signed vTPM PCR-10 quote, the AK-to-RTMR3 binding,
the RTMR3 IMA replay, the signed PCR-10 prefix, and checkpoint continuity.

## What the three conditions mean

| Dataset | CVM extraction | WEN execution | Wire/replay behavior |
| --- | --- | --- | --- |
| Non-Optimized | Reopen both IMA pseudo-files and reparse/validate the retained prefix on every measured round | Python | Delta-only evidence and incremental replay |
| Optimized (Python) | Keep both pseudo-file descriptors positioned across rounds | Python | Delta-only evidence and incremental replay |
| Optimized (SGX) | Keep both pseudo-file descriptors positioned across rounds | Gramine SGX | Delta-only evidence, incremental replay, and sealed checkpoint |

The non-optimized control deliberately changes only attester extraction. It
does not send the full log and therefore does not confound extraction speedup
with a different communication protocol. Figure 6 compares the same optimized
verifier code in Python and Gramine SGX.

## Experimental controls

Use the same TDX VM image/type, WEN host, repository commit, network path, and
policy options for all three datasets. Reboot the CVM before each dataset. Run
one TDX server process for the complete 24-cell matrix. Do not restart it
between points because the experiment depends on one persistent descriptor
lifecycle.

The server must use `--request-driven-runtime` for these measurements. This is
a benchmark-only scheduling mode: descriptors remain open across rounds, but
the pending IMA delta is read and extended when the request arrives. Without
it, the normal background watcher may consume the generated update before the
request, moving extraction work outside the measured end-to-end interval.

The default matrix matches the existing paper figures:

- Baselines: `10K, 50K, 100K, 200K`
- Updates: `100, 500, 1K, 5K, 10K, 15K`
- Recorded rows per condition: `24`
- Repetitions per cell: `1`, matching the old data collection

IMA is append-only until reboot. Within one dataset, updates are cumulative.
The CSV records both nominal sizes and observed counts so protocol-induced IMA
entries remain visible.

## 1. Prepare both machines

On the CVM and WEN, use the same branch and commit:

```bash
cd ~/sgx-tdx-composition-protocol
git switch feature/vtpm-rtmr3
git pull --ff-only origin feature/vtpm-rtmr3
git rev-parse HEAD
```

Confirm the two `git rev-parse HEAD` values match.

On the WEN, rebuild the Gramine manifest because the benchmark driver and
common verifier files are trusted enclave inputs:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier
make clean
make all
```

## 2. Start the CVM server for one dataset

Reboot the CVM first. After reconnecting, run:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/tdx-server
sudo -E python3 tdx_attestation_server.py --test --method dcap
sudo -E python3 tdx_attestation_server.py \
  --port 8443 \
  --method dcap \
  --request-driven-runtime
```

The banner must report:

```text
Protocol Version: 1.2
Runtime Evidence: ima-rtmr3-vtpm-v2
IMA Reader:       persistent-fd
Runtime Sync:     request-driven (benchmark)
```

Keep this terminal and server process running throughout that dataset. Open a
second CVM terminal in the same `tdx-server` directory. The WEN driver prints a
CVM command before every baseline and update. Run that command in this second
terminal, wait for it to complete, then press Enter in the WEN terminal.

## 3. Collect the non-optimized Python control

On the WEN:

```bash
export CVM_IP=146.148.46.72
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier
make bench-matrix-non-optimized \
  TDX_HOST="$CVM_IP" \
  TDX_PORT=8443
```

This writes:

```text
../runtime-state/benchmark-results/results_vtpm_non_optimized.csv
```

Each measured request sends the `reset` control command. The agent closes and
reopens its IMA descriptors, performs the full extraction and retained-prefix
validation, and still returns only the checkpoint delta.

## 4. Collect optimized Python

Stop the server, reboot the CVM, and repeat section 2 with a fresh server. Then
run on the WEN:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier
make bench-matrix-python \
  TDX_HOST="$CVM_IP" \
  TDX_PORT=8443
```

This writes:

```text
../runtime-state/benchmark-results/results_vtpm_optimized_python.csv
```

This condition uses the persistent descriptor path and the same composed
runtime verifier as SGX, but runs as ordinary Python. Its checkpoint remains
in process memory because the SGX sealing key is unavailable.

## 5. Collect optimized SGX

Stop the server, reboot the CVM, and repeat section 2 again. Then run on the
WEN:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier
make bench-matrix-sgx \
  TDX_HOST="$CVM_IP" \
  TDX_PORT=8443
```

This writes through the Gramine-mounted runtime-state directory to:

```text
../runtime-state/benchmark-results/results_vtpm_optimized_sgx.csv
```

The optimized SGX condition performs runtime verification inside the enclave
and seals the rolling checkpoint after every successful round.

## 6. Validate the CSVs

Each file must have 25 lines: one header plus 24 measured rows.

```bash
wc -l ../runtime-state/benchmark-results/results_vtpm_*.csv
```

Inspect the protocol and security-result columns:

```bash
python3 - <<'PY'
import csv
from pathlib import Path

root = Path("../runtime-state/benchmark-results")
for path in sorted(root.glob("results_vtpm_*.csv")):
    rows = list(csv.DictReader(path.open()))
    failed = [r for r in rows if r["overall_ok"].lower() != "true"]
    versions = sorted({r["protocol_version"] for r in rows})
    modes = sorted({r["mode"] for r in rows})
    print(path.name, "rows=", len(rows), "failed=", len(failed),
          "version=", versions, "mode=", modes)
PY
```

Expected results are 24 rows, zero failures, and Protocol `1.2` in each file.
For optimized rows, `verification_mode` should be `incremental-delta` after the
unrecorded baseline round. In the SGX file, `checkpoint_sealed` should be true.
The columns `delta_actual`, `agent_delta_entries`, and
`ima_entries_received` expose any extra IMA events caused by protocol tooling.

`--no-verify` disables TLS certificate validation only. It does not disable
TDX DCAP quote verification, vTPM quote verification, nonce checks, AK/RTMR3
binding, RTMR3 replay, or PCR-10 replay. The default evaluation policy does not
require the optional Google AK certificate match or golden MRTD/RTMR0-2 values;
those policy choices are recorded in the CSV.

## 7. Generate the replacement figures

From the repository root:

```bash
python3 research/incremental_attestation/charts_vtpm/generate_vtpm_charts.py \
  --non-optimized research/sgx-tdx-attestation/runtime-state/benchmark-results/results_vtpm_non_optimized.csv \
  --optimized-python research/sgx-tdx-attestation/runtime-state/benchmark-results/results_vtpm_optimized_python.csv \
  --optimized-sgx research/sgx-tdx-attestation/runtime-state/benchmark-results/results_vtpm_optimized_sgx.csv \
  --output-dir research/incremental_attestation/charts_vtpm/generated
```

The output directory contains PDF and PNG versions of:

- `fig1_latency_vs_N`: end-to-end latency versus baseline log size.
- `fig2_latency_vs_delta`: end-to-end latency versus update size.
- `fig3_speedup_heatmap`: non-optimized Python latency divided by optimized
  SGX latency.
- `fig6_sgx_overhead`: optimized Python versus optimized SGX. Panel (a) uses
  composed runtime-verification time; panel (b) uses full end-to-end latency at
  `N=200K`; panel (c) reports SGX runtime-verification overhead over Python.

Do not overwrite `charts_final` until the CSV validation passes and the new
figures have been inspected.

## Raw driver commands

The Makefile targets are wrappers around
`sgx-verifier/benchmark_protocol_matrix.py`. To change the matrix:

```bash
make bench-matrix-sgx \
  TDX_HOST="$CVM_IP" \
  MATRIX_BASELINES=10000,50000,100000,200000 \
  MATRIX_DELTAS=100,500,1000,5000,10000,15000 \
  MATRIX_REPEATS=1
```

Use the same matrix values for all three conditions. The driver performs one
unrecorded full replay at each baseline to establish a valid WEN checkpoint;
only subsequent incremental rounds are written to the CSV.
