# Protocol 1.2 Audit-Mode Experiment

## Question

This experiment measures the end-user serving cost of the two audit formats
after the SGX WEN has already verified the latest CVM evidence during its
periodic protocol-1.2 refresh:

- `ima-audit` (Mode 2) sends the WEN-authenticated composed vTPM/IMA/RTMR
  evidence and command log, but omits the raw TDX quote.
- `full-audit` (Mode 3) sends the same material plus the raw TDX DCAP quote.

The end-user request path does not obtain a new TDX or vTPM quote. It serves a
cached audit snapshot authenticated under the WEN's SGX-derived Ed25519 key.
Consequently, these results measure serialization, enclave copying, TLS
transport, end-user hash validation, and response-signature verification.
They are not measurements of background CVM attestation latency.

## Correct Snapshot Semantics

Protocol 1.2 normally transfers only an IMA delta from CVM to WEN. A table
indexed by accumulated IMA history `N` nevertheless needs a complete snapshot.
For audit modes, the WEN therefore starts from a full, verified response and
appends each subsequently verified delta to an enclave-resident audit archive.
It exports that archive with `ima_start_index=0`. A failed or non-contiguous
delta is never added. Recurring CVM-to-WEN verification remains incremental.

The benchmark client enforces the following before counting a response:

- the WEN Ed25519 signature and key pin verify;
- the TDX verdict is `TRUSTED` and runtime verdict is `CLEAN`;
- the runtime evidence version is `ima-rtmr3-vtpm-v2`;
- the IMA audit snapshot starts at entry zero;
- the runtime-evidence, IMA, command-log, and raw-quote sizes and hashes match;
- Mode 2 contains no raw TDX quote; and
- Mode 3 contains a raw TDX quote.

## Variables and Outputs

Use measured IMA histories of 10K, 50K, and 100K entries. If the current CVM
already exceeds 10K, report the actual count as the first point rather than
calling it 10K. Use one fixed command log for every cell; the recommended
paper configuration is 2,000 JSONL entries. Report its byte size separately so
readers can distinguish IMA scaling from command-history scaling.

For each mode and IMA size, record:

- complete serialized response bytes;
- raw binary-plus-ASCII IMA bytes;
- runtime-evidence bytes;
- command-log bytes and entries;
- exposed raw-quote bytes (zero in Mode 2, approximately 8 KiB in Mode 3);
- successful responses/s;
- median and p99 response latency;
- failure rate, TDX verdict, and runtime verdict; and
- actual IMA entry count observed during the run.

Use five repetitions. Run a one-request, pre-established-connection matrix for
the size table and a closed-loop concurrency sweep at the representative warm
history for serving capacity. Calibrate the 100K cell first because concurrent
large JSON responses consume enclave memory.

## Preparation

The changes are needed on the SGX WEN (`tjws-06`) and load generator
(`tjws-05`). The existing protocol-1.2 TDX agent on the CVM does not require an
audit-specific change.

Generate one fixed command log on `tjws-06`:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/scalability
python3 generate_command_logs.py \
  --entries 2000 \
  --with-transition-log \
  --out-dir ../results/scalability/audit-mode-inputs-p12
make all
```

Record the CVM IMA count:

```bash
sudo cat /sys/kernel/security/integrity/ima/runtime_measurements_count
```

Grow it monotonically when moving to the next history size:

```bash
cd ~/sgx-tdx-composition-protocol
sudo python3 research/incremental_attestation/generate_ima_baseline.py --target 50000
sudo python3 research/incremental_attestation/generate_ima_baseline.py --target 100000
```

Run only one target at a time and record the count after generation. The TDX
protocol server must remain healthy on port 8443.

## Start the SGX WEN

On `tjws-06`, set `MODE` to `ima-audit` for Mode 2 or `full-audit` for Mode 3:

```bash
export CVM_IP=136.111.107.168
export MODE=ima-audit

cd ~/sgx-tdx-composition-protocol/evaluation/scalability
make run-sgx ARGS="--listen-host 0.0.0.0 \
  --port 10443 \
  --listen-backlog 16384 \
  --min-nofile 65536 \
  --evidence-mode $MODE \
  --tls-cert /app/research/sgx-tdx-attestation/certs/scalability/wen-server.crt \
  --tls-key /app/research/sgx-tdx-attestation/certs/scalability/wen-server.key \
  --response-auth ed25519 \
  --require-sgx-signing-key \
  --refresh-backend sgx-verifier \
  --refresh-interval-s 30 \
  --tdx-host $CVM_IP \
  --tdx-port 8443 \
  --tdx-method dcap \
  --tdx-ca-cert /app/research/sgx-tdx-attestation/certs/scalability/ca.crt \
  --command-log-file /app/evaluation/results/scalability/audit-mode-inputs-p12/audit_log.jsonl"
```

Wait for the initial refresh to report `TRUSTED` and for the server to report
that it is listening. Restart this process when changing modes. Audit mode
startup intentionally resets the WEN's protocol checkpoint so the first
response is a complete IMA snapshot from entry zero.

## Run the Load Generator

On `tjws-05`:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/scalability
source ~/sgx-tdx-composition-protocol/.scalability-venv/bin/activate

export WEN_HOST=129.74.154.215
export WEN_PORT=10443
export CVM_IP=136.111.107.168
export MODE=ima-audit
export N=10000
export WEN_KEY_ID=<PINNED_WEN_ED25519_SHA256>
export TLS_DIR="$HOME/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/certs/scalability"
```

Size-table run:

```bash
python3 run_vordr_sweep.py \
  --no-spawn-server \
  --host "$WEN_HOST" --port "$WEN_PORT" \
  --transport tls --client-ca-cert "$TLS_DIR/ca.crt" \
  --server-runtime gramine-sgx \
  --listen-backlog 16384 --server-min-nofile 65536 \
  --response-auth ed25519 \
  --expected-signing-key-sha256 "$WEN_KEY_ID" \
  --require-signing-key-pin \
  --evidence-mode "$MODE" \
  --refresh-backend sgx-verifier --refresh-interval-s 30 \
  --tdx-host "$CVM_IP" --tdx-port 8443 --tdx-method dcap \
  --tdx-ca-cert "$TLS_DIR/ca.crt" \
  --workload-model one-shot --connection-model pre-established \
  --users 1 --duration-s 1 --repetitions 20 \
  --client-warmup-requests 3 \
  --out-dir "../results/scalability/p12-${MODE}-size-N${N}"
```

Representative serving-capacity run (first calibrate with one repetition):

```bash
python3 run_vordr_sweep.py \
  --no-spawn-server \
  --host "$WEN_HOST" --port "$WEN_PORT" \
  --transport tls --client-ca-cert "$TLS_DIR/ca.crt" \
  --server-runtime gramine-sgx \
  --listen-backlog 16384 --server-min-nofile 65536 \
  --response-auth ed25519 \
  --expected-signing-key-sha256 "$WEN_KEY_ID" \
  --require-signing-key-pin \
  --evidence-mode "$MODE" \
  --refresh-backend sgx-verifier --refresh-interval-s 30 \
  --tdx-host "$CVM_IP" --tdx-port 8443 --tdx-method dcap \
  --tdx-ca-cert "$TLS_DIR/ca.crt" \
  --workload-model closed-loop \
  --users 1,2,4,8,16 --duration-s 60 --repetitions 5 \
  --out-dir "../results/scalability/p12-${MODE}-capacity-N${N}"
```

## Generate the Appendix Table

```bash
python3 summarize_audit_modes.py \
  --input ima-audit:10000:../results/scalability/p12-ima-audit-capacity-N10000/vordr_single_wen_summary.csv \
  --input full-audit:10000:../results/scalability/p12-full-audit-capacity-N10000/vordr_single_wen_summary.csv \
  --input ima-audit:50000:../results/scalability/p12-ima-audit-capacity-N50000/vordr_single_wen_summary.csv \
  --input full-audit:50000:../results/scalability/p12-full-audit-capacity-N50000/vordr_single_wen_summary.csv \
  --input ima-audit:100000:../results/scalability/p12-ima-audit-capacity-N100000/vordr_single_wen_summary.csv \
  --input full-audit:100000:../results/scalability/p12-full-audit-capacity-N100000/vordr_single_wen_summary.csv \
  --out-dir ../results/scalability/p12-audit-mode-paper
```

This writes a validated CSV, a LaTeX table, and a short LaTeX discussion. Any
projection (for example, a 1K point that cannot be recreated after the CVM log
has grown) must be fit from the measured 10K/50K/100K wire sizes and explicitly
labeled as projected; it must not be mixed with measured rows without a marker.

Do not add these audit curves directly to the existing linear-scale Cached-RA
capacity panel: their response sizes and throughput differ by orders of
magnitude, which would flatten the audit curves. Use an appendix table or a
separate log-scale panel, and summarize the result in one or two main-text
sentences.
