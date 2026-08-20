# Protocol 1.2 Security-Event Evaluation

This harness evaluates whether Vordr distinguishes cryptographically valid but
unauthorized runtime changes from authorized activity and from tampered or
replayed evidence. All attack artifacts are harmless canaries with unique paths,
inodes, names, and digests for each trial.

## What Is Tested

Each scenario runs three trials in this order:

1. `no-update`: negative control with normal service activity and no intentional
   software change.
2. `authorized-package`: a harmless package whose path and digest have a signed
   authorization record before installation.
3. `shared-library-replacement`: atomic replacement of a protected canary
   library followed by executable mapping of the replacement.
4. `kernel-module-insertion`: insertion and removal of a harmless, uniquely
   named module that only emits a kernel-log marker.
5. `unauthorized-package`: direct installation and execution of a harmless
   package without an authorization record.
6. `binary-replacement`: atomic replacement and execution of a protected
   canary binary.

The expected distinction is:

| Evidence | Authorization/policy | Result |
|---|---|---|
| Authentic authorized event | Match | `VALID`, `COMPLIANT` |
| Authentic unauthorized event | No match or digest transition | `VALID`, `VIOLATION` |
| Altered or replayed response | Irrelevant | `INVALID`/rejected |

Mode 2 does not expose the raw TDX quote. The end-user auditor independently
checks the WEN Ed25519 response proof, complete audit-bundle hashes and sizes,
binary/ASCII IMA consistency, the vTPM signature and nonce, and the signed
PCR-10 prefix. It relies on the measured SGX WEN's signed `TRUSTED/CLEAN`
summary for the TDX quote and RTMR3 verification that the WEN performed during
the background refresh.

## Safety and Isolation

The CVM helper only creates experiment artifacts under a campaign-specific
subdirectory of `/opt/vordr-security-events`, plus uniquely named harmless
executables under `/usr/local/bin`. The module has no hooks or behavior beyond
loading, logging one marker, and unloading. Do not run this evaluation on a
production CVM.

The first invocation of an attack trial creates a record and subsequent
invocations are rejected. Use a new campaign ID rather than reusing artifacts.

## One-Time Checks

Run on both machines after pulling the same commit:

```bash
cd ~/sgx-tdx-composition-protocol
git status --short
git rev-parse HEAD
```

On the CVM, install build dependencies before creating the experiment baseline:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  "linux-headers-$(uname -r)" \
  kmod \
  jq

cd ~/sgx-tdx-composition-protocol
sudo python3 evaluation/security_events/cvm_security_events.py preflight |
  python3 -m json.tool
```

Expected preflight properties are `ima_policy_boot=tcb`,
`module_sig_enforce=N`, and lockdown `[none]`.

## 1. Choose a Campaign ID

Use exactly the same value on the CVM and tjws-06:

```bash
export CAMPAIGN="security-p12-$(date -u +%Y%m%dT%H%M%SZ)"
echo "$CAMPAIGN"
```

Copy the printed value to the other terminal and export it there rather than
running the date command independently.

## 2. Prepare the CVM

Keep the protocol 1.2 TDX agent running on port 8443. Confirm it before
preparation:

```bash
sudo systemctl status vordr-tdx-agent.service --no-pager || true
sudo ss -ltnp | grep ':8443'
```

Prepare three unique artifacts for every scenario:

```bash
cd ~/sgx-tdx-composition-protocol
sudo python3 evaluation/security_events/cvm_security_events.py prepare \
  --campaign "$CAMPAIGN" \
  --trials 3 |
  sudo tee "/tmp/${CAMPAIGN}-prepare.json" |
  python3 -m json.tool

export CVM_STATE="/opt/vordr-security-events/$CAMPAIGN/state.json"
sudo test -r "$CVM_STATE" && echo "CVM experiment state: OK"
sudo cat "$CVM_STATE" | python3 -m json.tool | head -n 40
```

Preparation compiles and executes only the approved baseline canaries. It also
builds, but does not install or load, the attack variants.

## 3. Initialize the Authorization Log on tjws-06

```bash
cd ~/sgx-tdx-composition-protocol
export SECURITY_ROOT="$PWD/evaluation/results/security-events/$CAMPAIGN"
mkdir -p "$SECURITY_ROOT"

python3 evaluation/security_events/audit_security_events.py init-auth \
  --private-key "$SECURITY_ROOT/authorization-private.pem" \
  --public-key "$SECURITY_ROOT/authorization-public.pem" \
  --command-log "$SECURITY_ROOT/authorization.jsonl"
```

The private key and JSONL log are ignored by the repository's global Git rules.
The Mode 2 response authenticates the command-log hash, while the auditor also
verifies every record's Ed25519 signature and hash-chain continuity.

## 4. Restart the SGX WEN in Mode 2

Stop the existing light-mode WEN. Rebuild because the audit bundle now preserves
the WEN-to-CVM nonce used by the exported vTPM quote:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/scalability
make clean
make all
```

Then run the WEN in a dedicated terminal:

```bash
export CVM_IP=136.111.107.168
export TLS_DIR="$HOME/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/certs/scalability"
export ENCLAVE_COMMAND_LOG="/app/evaluation/results/security-events/$CAMPAIGN/authorization.jsonl"

make run-sgx ARGS="--listen-host 0.0.0.0 \
  --port 10443 \
  --evidence-mode ima-audit \
  --command-log-file $ENCLAVE_COMMAND_LOG \
  --tls-cert /app/research/sgx-tdx-attestation/certs/scalability/wen-server.crt \
  --tls-key /app/research/sgx-tdx-attestation/certs/scalability/wen-server.key \
  --response-auth ed25519 \
  --require-sgx-signing-key \
  --refresh-backend sgx-verifier \
  --refresh-interval-s 30 \
  --tdx-host $CVM_IP \
  --tdx-port 8443 \
  --tdx-method dcap \
  --tdx-ca-cert /app/research/sgx-tdx-attestation/certs/scalability/ca.crt"
```

Wait for the first `TRUSTED` refresh and copy the printed `key_id`. The key ID
should remain the same if the existing SGX signing key and controller ID are
unchanged.

## 5. Run the Three-Trial Campaign from tjws-06

Set the key ID printed by the WEN:

```bash
cd ~/sgx-tdx-composition-protocol
export WEN_KEY_ID="<KEY_ID_PRINTED_BY_WEN>"
export CVM_STATE="/opt/vordr-security-events/$CAMPAIGN/state.json"
export SECURITY_ROOT="$PWD/evaluation/results/security-events/$CAMPAIGN"
```

Run all controls and attack classes:

```bash
python3 evaluation/security_events/audit_security_events.py run-campaign \
  --project braided-hangout-472219-a5 \
  --zone us-central1-a \
  --instance vordr-eval-base \
  --remote-repo /home/nkoirala/sgx-tdx-composition-protocol \
  --remote-state "$CVM_STATE" \
  --wen-host 129.74.154.215 \
  --wen-port 10443 \
  --ca-cert research/sgx-tdx-attestation/certs/scalability/ca.crt \
  --expected-wen-key-sha256 "$WEN_KEY_ID" \
  --auth-private-key "$SECURITY_ROOT/authorization-private.pem" \
  --auth-public-key "$SECURITY_ROOT/authorization-public.pem" \
  --command-log "$SECURITY_ROOT/authorization.jsonl" \
  --trials 3 \
  --attestation-period-s 30 \
  --refresh-timeout-s 75 \
  --out-dir "$SECURITY_ROOT/results"
```

The driver intentionally runs controls first so the clean and authorized cases
are measured before any policy violation. It waits for a new WEN refresh after
each trigger and, if necessary, waits for a second refresh before declaring the
target event missing.

Successful completion prints:

```text
Completed 18 trials: passed=18, failed=0
```

Check the results:

```bash
column -s, -t \
  "$SECURITY_ROOT/results/security_event_results.csv" |
  less -S

jq '[.[] | select(.trial_pass != true)]' \
  "$SECURITY_ROOT/results/security_event_results.json"
```

The second command must return `[]`.

## 6. Run Replay and Omission Fault Tests

Use any saved valid response, preferably a malicious-library trial:

```bash
python3 evaluation/security_events/audit_security_events.py fault-test \
  --response "$SECURITY_ROOT/results/responses/shared-library-replacement-trial-1.json.gz" \
  --out "$SECURITY_ROOT/results/fault_injection_results.json"
```

This verifies rejection of an old response under a fresh nonce, an attempted
nonce rewrite, and deletion of one IMA entry from both log representations.

## Result Files

- `security_event_results.csv`: paper-table input.
- `security_event_results.json`: complete per-trial findings and timing.
- `responses/*.json.gz`: exact Mode 2 evidence returned for each trial.
- `fault_injection_results.json`: replay and omission results.
- `campaign_metadata.json`: machines, period, WEN identity, and campaign scope.
- `cvm_state.json`: artifact paths and reference/candidate digests.

Report both WEN detection latency and end-user observation latency. With a
30-second attestation period, detection should normally occur in the first
refresh after the trigger, but the measured values rather than the nominal
period must be used in the paper.

## Interpretation Limits

The experiment demonstrates detection at policy-selected IMA hooks. A write
that is never executed, executable-mapped, module-loaded, or otherwise selected
by the active policy is outside this claim. It also demonstrates stale response
and delta tampering rejection. It does not, by itself, establish rollback
freshness for a host-restored but otherwise valid SGX-sealed checkpoint; that
requires a client-held checkpoint head or external monotonic witness.
