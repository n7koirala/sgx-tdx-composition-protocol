# Scalability Evaluation

This folder contains a paper-oriented benchmark harness for comparing:

- `Direct DCAP`: every end-user nonce triggers a fresh TDX quote.
- `Vordr (single WEN)`: one background TDX attestation refresh serves many end users.

## Files

- `run_direct_dcap_sweep.py`: reuses `research/tdx-dcap-attestation/dcap_with_library.py` and writes CSV/JSON summaries for the direct fresh-quote baseline.
- `vordr_server.py`: single-WEN service with cached verified TDX state; supports both lightweight and full-evidence responses.
- `vordr_wen.manifest.template` + `Makefile`: Gramine/SGX packaging for running the same WEN service inside an enclave.
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
  --server-runtime python \
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

Protocol 1.2 exposes two explicit audit formats. `ima-audit` (Mode 2) returns
the WEN-authenticated vTPM/IMA/RTMR evidence and command log but deliberately
omits the raw TDX quote. `full-audit` (Mode 3) adds that quote for independent
DCAP verification. Both formats use a start-at-zero audit snapshot accumulated
inside the WEN from already verified deltas; recurring CVM-to-WEN verification
remains incremental. `full` is retained only as a legacy Mode-3 wire alias.

Run Mode 2 or Mode 3 by changing only `--evidence-mode`:

```bash
cd evaluation/scalability
python3 run_vordr_sweep.py \
  --users 1,2,4,8,16 \
  --duration-s 60 \
  --repetitions 5 \
  --evidence-mode ima-audit \
  --server-runtime gramine-sgx \
  --refresh-backend sgx-verifier \
  --tdx-host <TDX_IP> \
  --tdx-port 8443 \
  --command-log-file ../results/scalability/full-evidence-inputs/audit_log.jsonl \
  --out-dir ../results/scalability/audit-mode2-N10000

# Repeat with:
#   --evidence-mode full-audit
#   --out-dir ../results/scalability/audit-mode3-N10000
```

The audit client fails a point if the evidence is not protocol 1.2, if the
snapshot does not begin at entry zero, if any signed size/hash is inconsistent,
if Mode 2 leaks a raw TDX quote, or if Mode 3 omits it. The stream limit is
256 MiB so 50K/100K-entry snapshots can be measured; calibrate concurrency at
the largest snapshot before running the full matrix.

After measuring both modes at each IMA history size, validate the runs and
generate the appendix table and discussion with:

```bash
python3 summarize_audit_modes.py \
  --input ima-audit:10000:../results/scalability/audit-mode2-N10000/vordr_single_wen_summary.csv \
  --input full-audit:10000:../results/scalability/audit-mode3-N10000/vordr_single_wen_summary.csv \
  --out-dir ../results/scalability/audit-mode-summary
```

Repeat `--input` for 50K and 100K runs. The summarizer rejects failed,
untrusted, runtime-unclean, privacy-violating, or malformed rows.

Plotting:

```bash
python3 plot_scalability.py \
  --direct-csv evaluation/results/scalability/direct-dcap-.../direct_dcap_summary.csv \
  --vordr-csv evaluation/results/scalability/vordr-single-wen-.../vordr_single_wen_summary.csv \
  --out-dir evaluation/results/scalability/figures
```

## Interpretation

The direct baseline should be reported as a fresh-quote system: each request forces quote generation. The Vordr benchmark should be reported as a cached-attestation system: the WEN amortizes one background TDX attestation over many end-user responses. The key comparison metric is therefore not just throughput, but also `amplification = successful_end_user_attestations / TDX_refreshes`.

For either audit mode, the CSV reports serialized response size and component
sizes for the runtime evidence, raw IMA representations, command log, and (for
Mode 3) the raw TDX quote. These runs measure serving an evidence snapshot that
the WEN has already verified during its background refresh. They do not generate
a new TDX or vTPM quote per end-user request. Results indexed by total IMA size
`N` are distinct from incremental WEN refresh cost, which is indexed by the
new-entry count `delta n`.

## Measuring the WEN Inside SGX

The default sweep launches the WEN as a normal Python process. To measure the
WEN itself inside an SGX enclave, use the Gramine packaging in this directory
and run the sweep with `--server-runtime gramine-sgx`.

### SGX/WEN machine

Build the enclave package once:

```bash
cd evaluation/scalability
make all
```

Cached-RA sweep with the WEN inside SGX:

```bash
cd evaluation/scalability
python3 run_vordr_sweep.py \
  --users 1,4,16,64,256,512 \
  --duration-s 10 \
  --server-runtime gramine-sgx \
  --refresh-backend sgx-verifier \
  --tdx-host <TDX_IP> \
  --tdx-port 8443 \
  --no-verify-tdx
```

Audit-mode sweep with the WEN inside SGX:

```bash
cd evaluation/scalability
python3 generate_command_logs.py \
  --entries 2000 \
  --with-transition-log \
  --out-dir ../results/scalability/full-evidence-inputs-sgx

python3 run_vordr_sweep.py \
  --users 1,2,4,8,16 \
  --duration-s 60 \
  --repetitions 5 \
  --evidence-mode ima-audit \
  --server-runtime gramine-sgx \
  --refresh-backend sgx-verifier \
  --tdx-host <TDX_IP> \
  --tdx-port 8443 \
  --command-log-file ../results/scalability/full-evidence-inputs-sgx/audit_log.jsonl \
  --out-dir ../results/scalability/ima-audit-N10000

# Restart the WEN and repeat with --evidence-mode full-audit.
```

You can also launch the enclave-resident WEN manually for debugging:

```bash
cd evaluation/scalability
make run-sgx ARGS="--listen-host 127.0.0.1 --port 10443 --refresh-backend sgx-verifier --tdx-host <TDX_IP> --tdx-port 8443 --tdx-method dcap --refresh-interval-s 30 --proof-secret vordr-benchmark-secret"
```

### TDX / CVM machine

Run the TDX attestation server as before. For full-evidence measurements, also
grow the IMA log on the CVM to the target size before starting the SGX-side
sweep. The SGX/WEN machine then connects to that TDX server during each
background refresh epoch.

## Protocol 1.2 Paper-Grade Workloads

`run_vordr_sweep.py` now implements the three complementary workload models
from `evaluation/vTPM-scalablity-plan/README.md`.

### Security and Measurement Rules

- Use `--server-runtime gramine-sgx --response-auth ed25519` for final Vordr data.
- Use `--require-signing-key-pin` with an independently accepted key fingerprint.
- Use verified TLS when the load generator is on a separate machine.
- Keep HMAC and local TCP only as explicitly labeled control measurements.

The `proof_key_id` is SHA-256 over the WEN Ed25519 public key. Under Gramine
SGX, the private key is derived inside the enclave from its MRSIGNER sealing key.

### 1. Build and Local SGX Validation

Run the signer unit tests and rebuild the measured enclave:

```bash
cd ~/sgx-tdx-composition-protocol
python3 evaluation/scalability/test_scale_common.py
make -C evaluation/scalability all
```

Run a short SGX signed-response smoke test:

```bash
python3 evaluation/scalability/run_vordr_sweep.py \
  --workload-model closed-loop \
  --users 1,4,16 \
  --duration-s 10 \
  --repetitions 1 \
  --server-runtime gramine-sgx \
  --refresh-backend synthetic \
  --response-auth ed25519 \
  --out-dir evaluation/results/scalability/vtpm-1.2-sgx-local-smoke
```

Confirm `proof_key_origin=sgx-mrsigner-derived`, zero errors, and one stable
`proof_key_id` across all points before using the real CVM backend.

### 2. Configure TLS and Start the Persistent SGX WEN

The existing repository certificate predates strict hostname checking and has
no SAN. Generate a private experiment CA plus separate WEN and TDX server
certificates. On `tjws-06`:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/scalability
./setup_tls_certs.sh \
  --wen-host 129.74.154.215 \
  --wen-dns tjws-06 \
  --tdx-host 136.111.107.168 \
  --tdx-dns vordr-eval-base

export TLS_DIR="$HOME/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/certs/scalability"
openssl verify -CAfile "$TLS_DIR/ca.crt" \
  "$TLS_DIR/wen-server.crt" "$TLS_DIR/tdx-server.crt"
```

The generated directory is ignored by Git. Keep `ca.key`,
`wen-server.key`, and `tdx-server.key` private. Copy only the CA certificate
and the TDX leaf certificate/key to the CVM:

```bash
export CVM_IP=136.111.107.168
export CVM_USER=nkoirala
export CVM_TLS_DIR="~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/certs/scalability"

ssh "$CVM_USER@$CVM_IP" "mkdir -p $CVM_TLS_DIR && chmod 700 $CVM_TLS_DIR"
scp "$TLS_DIR/ca.crt" "$TLS_DIR/tdx-server.crt" "$TLS_DIR/tdx-server.key" \
  "$CVM_USER@$CVM_IP:$CVM_TLS_DIR/"
ssh "$CVM_USER@$CVM_IP" "chmod 644 $CVM_TLS_DIR/ca.crt $CVM_TLS_DIR/tdx-server.crt; chmod 600 $CVM_TLS_DIR/tdx-server.key"
```

On the CVM, stop the old TDX server and restart protocol 1.2 with the new leaf
certificate:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/tdx-server
sudo -E python3 tdx_attestation_server.py \
  --port 8443 \
  --method dcap \
  --cert ../certs/scalability/tdx-server.crt \
  --key ../certs/scalability/tdx-server.key
```

Back on `tjws-06`, rebuild and start one persistent cached-response WEN
enclave. The WEN verifies the TDX certificate chain and SAN, periodically
verifies the complete protocol-1.2 evidence, and serves only compact,
nonce-bound SGX-signed results to clients:

```bash
# Keep the accept queue and process descriptor limit above the largest burst.
ulimit -n 65536
sudo sysctl -w net.core.somaxconn=16384

cd ~/sgx-tdx-composition-protocol/evaluation/scalability
export CVM_IP=136.111.107.168
make clean all
make run-sgx ARGS="--listen-host 0.0.0.0 \
  --port 10443 \
  --listen-backlog 16384 \
  --evidence-mode light \
  --tls-cert /app/research/sgx-tdx-attestation/certs/scalability/wen-server.crt \
  --tls-key /app/research/sgx-tdx-attestation/certs/scalability/wen-server.key \
  --response-auth ed25519 \
  --require-sgx-signing-key \
  --refresh-backend sgx-verifier \
  --refresh-interval-s 15 \
  --tdx-host $CVM_IP \
  --tdx-port 8443 \
  --tdx-method dcap \
  --tdx-ca-cert /app/research/sgx-tdx-attestation/certs/scalability/ca.crt"
```

Record the startup `key_id`. TLS authenticates the network endpoints and
protects transport; the pinned SGX-derived Ed25519 key authenticates the cached
WEN result. The WEN key still must be associated with an accepted WEN SGX
identity through the protocol's provisioning/attestation procedure rather than
trusted merely because it appeared on the health endpoint.

Before using a separate load generator, validate the cached mode locally on
`tjws-06`. This checks TLS, certificate hostname validation, the SGX-derived
response signature, key pinning, and background protocol-1.2 refreshes. It is a
functional smoke test, not a remote scalability result:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/scalability
export TLS_DIR="$HOME/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/certs/scalability"
export WEN_KEY_ID=<KEY_ID_PRINTED_BY_THE_RUNNING_WEN>

python3 run_vordr_sweep.py \
  --no-spawn-server \
  --host 127.0.0.1 \
  --port 10443 \
  --transport tls \
  --client-ca-cert "$TLS_DIR/ca.crt" \
  --server-runtime gramine-sgx \
  --response-auth ed25519 \
  --expected-signing-key-sha256 "$WEN_KEY_ID" \
  --require-signing-key-pin \
  --evidence-mode light \
  --workload-model closed-loop \
  --users 1,16 \
  --duration-s 35 \
  --repetitions 1 \
  --refresh-interval-s 15 \
  --load-generator-location "Notre Dame, IN (co-located with WEN)" \
  --wen-location "Notre Dame, IN" \
  --wen-hardware "Intel Xeon Gold 5412U, 24 cores/48 threads, 377 GiB RAM" \
  --out-dir ../results/scalability/vtpm-1.2-cached-local-tls-smoke
```

### 3. Remote TLS Smoke Test and Key Pin

On a separate load-generator machine, run a short pinned-key smoke test:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/scalability
export WEN_HOST=<WEN_DNS_OR_IP_IN_CERT_SAN>
export WEN_KEY_ID=<KEY_ID_FROM_ACCEPTED_WEN_IDENTITY>
python3 run_vordr_sweep.py \
  --no-spawn-server \
  --host "$WEN_HOST" \
  --port 10443 \
  --listen-backlog 16384 \
  --transport tls \
  --client-ca-cert <WEN_CA_CERT> \
  --server-runtime gramine-sgx \
  --response-auth ed25519 \
  --expected-signing-key-sha256 "$WEN_KEY_ID" \
  --require-signing-key-pin \
  --workload-model closed-loop \
  --users 1,16 \
  --duration-s 35 \
  --repetitions 1 \
  --refresh-interval-s 15 \
  --loadgen-wen-rtt-ms <MEASURED_MEDIAN_RTT_MS> \
  --loadgen-wen-rtt-method "ping median, 20 samples" \
  --wen-cvm-rtt-ms <MEASURED_MEDIAN_RTT_MS> \
  --wen-cvm-rtt-method "ping median, 20 samples" \
  --load-generator-location "<zone/host>" \
  --wen-location "<zone/host>" \
  --cvm-location "<GCP zone>" \
  --out-dir ../results/scalability/vtpm-1.2-remote-tls-smoke
```

Verify zero errors, a stable pinned key, CA/hostname verification in
`run_metadata.json`, and enough client CPU/network headroom before calibration.

### 4. Final Closed-Loop Matrix

Measure signed delegated-response capacity versus concurrent request streams:

```bash
python3 run_vordr_sweep.py \
  --no-spawn-server \
  --host "$WEN_HOST" \
  --port 10443 \
  --listen-backlog 16384 \
  --transport tls \
  --client-ca-cert <WEN_CA_CERT> \
  --server-runtime gramine-sgx \
  --response-auth ed25519 \
  --expected-signing-key-sha256 "$WEN_KEY_ID" \
  --require-signing-key-pin \
  --refresh-interval-s 15 \
  --workload-model closed-loop \
  --users 1,2,4,8,16,32,64,128,256 \
  --duration-s 180 \
  --repetitions 5 \
  --out-dir ../results/scalability/vtpm-1.2-closed-loop-sgx
```

### 5. Final One-Shot Population Matrix

Measure simultaneous one-request clients with pre-established TLS sessions:

```bash
python3 run_vordr_sweep.py \
  --no-spawn-server \
  --host "$WEN_HOST" \
  --port 10443 \
  --listen-backlog 16384 \
  --transport tls \
  --client-ca-cert <WEN_CA_CERT> \
  --server-runtime gramine-sgx \
  --response-auth ed25519 \
  --expected-signing-key-sha256 "$WEN_KEY_ID" \
  --require-signing-key-pin \
  --workload-model one-shot \
  --connection-model pre-established \
  --users 1,16,64,256,1000,5000,10000 \
  --repetitions 5 \
  --client-ready-timeout-s 180 \
  --out-dir ../results/scalability/vtpm-1.2-burst-pre-tls-sgx
```

Repeat with `--connection-model new` and a different output directory to include
TLS connection establishment in the synchronized burst makespan.

### 6. Final Open-Loop Matrix

Measure sustainable capacity with Poisson arrivals independent of completion:

```bash
python3 run_vordr_sweep.py \
  --no-spawn-server \
  --host "$WEN_HOST" \
  --port 10443 \
  --listen-backlog 16384 \
  --transport tls \
  --client-ca-cert <WEN_CA_CERT> \
  --server-runtime gramine-sgx \
  --response-auth ed25519 \
  --expected-signing-key-sha256 "$WEN_KEY_ID" \
  --require-signing-key-pin \
  --workload-model open-loop \
  --arrival-process poisson \
  --connections 128 \
  --offered-rates 1000,2500,5000,7500,9000,10000,11000,12500 \
  --duration-s 300 \
  --open-loop-drain-s 60 \
  --repetitions 5 \
  --random-seed 2027 \
  --out-dir ../results/scalability/vtpm-1.2-open-loop-sgx
```

### 7. Calibration and Result Validation

Before the five-repetition runs:

- run each model for 30 seconds with one repetition;
- verify the load generator retains at least 50% CPU and network headroom;
- record WEN/CVM machine types and software versions using the metadata flags;
- confirm `drain_timed_out=false`, zero request failures, and stable key identity;
- define the open-loop SLO before inspecting final results.

Every result directory contains:

- `vordr_single_wen_summary.csv`: one row per point and repetition;
- `raw/<point>.json.gz`: one gzip-compressed raw sample file per point and
  repetition;
- `run_metadata.json`: Git, protocol, SGX identity, TLS, placement, and versions;
- `server-*.log`: one WEN log per locally spawned point.

Each compressed raw file is written atomically as soon as its point completes,
and that point is then released from client memory. `run_metadata.json` records
the relative filename and compressed size for every completed point, allowing
interrupted matrices to retain all completed results without one growing
matrix-wide JSON object.

Key fields include actual one-shot makespan, offered and achieved rates, p99.9,
connection and service time, generator queue delay and maximum depth, signature
generation/verification time, refresh overlap, staleness, response bytes, peak
connections, refresh count, and responses served per composed CVM refresh.

The client performs verified warm-up responses before resetting measurement
counters so cryptography/module initialization is outside the timed interval.

In both audit modes, the WEN accumulates only runtime deltas that its protocol-1.2
SGX verifier accepted and exports them as a complete start-at-zero audit
snapshot. The canonical SHA-256 digest of that object is covered by each
nonce-bound WEN Ed25519 signature. The load generator verifies that signature
and checks the runtime evidence, binary/ASCII IMA representations, and command
log against the signed digests before counting a response as successful. In
`ima-audit`, it additionally rejects any response containing a raw TDX quote;
in `full-audit`, it requires the quote and verifies its digest and size. The
legacy `full` alias also carries redundant bare IMA/PCR fields and should not be
used for new measurements.
