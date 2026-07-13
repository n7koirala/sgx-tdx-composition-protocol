# vTPM PCR-10 and RTMR[3] Production Integration

This document describes the integration of the tested
`research/ima_rtmr3_test` mechanism into the main hierarchical protocol in
`research/sgx-tdx-attestation`. The integrated protocol version is `1.1`.

The implementation is intended for the DCAP path. The CVM returns one composed
evidence object containing a fresh TDX quote, a fresh vTPM quote over SHA-256
PCR-10, the IMA measurement data needed to replay both anchors, and metadata
that binds all components to the same request. The WEN verifies the composed
predicate inside a Gramine SGX enclave.

## What Changed

### Shared protocol and evidence code

- `common/protocol.py`
  - Changes the wire protocol version to `1.1`.
  - Adds `runtime_evidence` to `AttestationResponse`.
  - Adds composed runtime checks and details to `VerificationResult`.
  - Adds the runtime verdict, IMA count, and individual runtime checks to the
    controller token returned to end users.
- `common/ima_rtmr3.py`
  - Parses the binary IMA measurement list exactly.
  - Defines the canonical SHA-384 mapping used for RTMR[3].
  - Replays SHA-1 and SHA-256 PCR-10, including IMA violation events.
  - Finds the IMA prefix corresponding to the PCR-10 value signed by gotpm.
- `common/vtpm_quote.py`
  - Loads the GCP-provisioned AK through gotpm, with a tpm2-tools persistent
    handle fallback.
  - Produces a nonce-bound quote over SHA-256 PCR-10.
  - Parses gotpm textproto byte fields without changing their bytes.
  - Verifies AK signatures, nonce binding, PCR selection, and PCR composite
    digest in Python on the WEN.
  - Optionally checks whether a supplied leaf certificate contains the same
    public key as the quoted AK.
- `common/runtime_agent.py`
  - Binds `SHA384(ak_pub)` into RTMR[3] before replaying IMA.
  - Replays the existing IMA log at startup and extends new entries while the
    server runs.
  - Collects aligned vTPM, IMA, and TDX evidence for each request.
  - Sends a full IMA history on the first round and only the new wire delta on
    later rounds.
- `common/runtime_verifier.py`
  - Reconstructs incremental IMA deltas against enclave-held verified state.
  - Checks the complete composed runtime predicate.
  - Enforces optional golden boot and AK certificate policies.
- `common/test_runtime_composition.py`
  - Tests a valid composed chain, tampered ASCII evidence, protocol
    serialization, valid incremental continuation, and delta-gap rejection.

### CVM server

`tdx-server/tdx_attestation_server.py` now starts `RuntimeEvidenceAgent` by
default when both conditions are true:

```text
method == dcap
enable_ima == true
```

The agent is initialized before the server accepts requests. Its startup
ordering is:

```text
read current RTMR3 as startup base
  -> extend SHA384(ak_pub)
  -> parse the complete existing binary IMA log
  -> extend every parsed event into RTMR3
  -> start the incremental watcher
```

The old top-level `ima_log` and `pcr10` response fields remain for wire
compatibility and diagnostics. The WEN trust decision uses
`runtime_evidence`, not those bare debug values.

### WEN verifier and controller

- `sgx-verifier/sgx_tdx_verifier.py` requires composed runtime evidence by
  default in DCAP mode. A failed runtime check changes the entire result to
  `UNTRUSTED`.
- A persistent `SGXTDXVerifier` keeps only successfully verified IMA history.
  It requests subsequent deltas using that verified entry count. A malformed,
  skipped, or duplicated delta is rejected before state advances.
- `sgx-verifier/sgx_controller.py` reuses one persistent verifier across
  refresh rounds, so controller traffic remains incremental.
- `end-user/end_user_client.py` reports the cached runtime verdict, verified
  IMA count, and failed check names.
- `sgx-verifier/Makefile` defaults to DCAP and includes the new common modules
  in the Gramine manifest dependencies.

## Cryptographic Construction

Let:

```text
R0 = RTMR3 value immediately before this agent starts
A  = SHA384(ak_pub)
C(e) = canonical serialization of one binary IMA event
D(e) = SHA384(C(e))
```

The AK bind step is:

```text
R1 = SHA384(R0 || A)
```

Each IMA event then updates RTMR[3] as:

```text
R(i+1) = SHA384(R(i) || D(event_i))
```

The exact canonical serialization is:

```text
"IMA-RTMR3-CANON-v1\0"
|| LE32(pcr_index)
|| LE32(len(template_hash)) || template_hash
|| LE32(len(template_name)) || template_name
|| LE32(len(template_data)) || template_data
```

The full template data is hashed. A SHA-1/SHA-256 IMA template hash is not
padded to 48 bytes and is not directly used as the RTMR extend input.

The verifier recomputes the same sequence and requires:

```text
replayed RTMR3 == RTMR3 in the nonce-bound TDX quote
```

## Evidence Collection Ordering

gotpm itself causes IMA measurements. Its signed PCR-10 usually corresponds to
a prefix of the final IMA log, not the final entry after gotpm exits. The
collector therefore uses this ordering:

```text
WEN generates nonce N
       |
       v
CVM obtains vTPM AK quote over SHA-256 PCR-10 with qualifyingData N
       |
       v
CVM synchronizes every newly visible IMA event into RTMR3
       |
       v
CVM finds the exact IMA prefix that replays to signed PCR-10
       |
       v
CVM obtains a TDX DCAP quote with N in report_data
       |
       v
CVM returns TDX quote + vTPM quote + IMA evidence + anchor metadata
```

The prefix rule is deliberate. It does not discard later entries:

- The signed vTPM PCR-10 is checked against the exact earlier prefix.
- The quoted RTMR[3] is checked against the complete IMA list in the response.
- Entries produced after the vTPM quote therefore remain covered by RTMR[3].
- Entries arriving after the TDX quote are reported as post-quote drift and
  are included in the next round.

IMA violation rows have an all-zero logged template hash. PCR replay consumes
them as `0xff` repeated to the selected bank width. They are never skipped.

## Incremental Transfer

The first request from one `SGXTDXVerifier` uses `ima_offset = 0`. The CVM
sends the complete binary and ASCII IMA histories. After a successful composed
verification, the enclave records:

```text
verified binary history
verified ASCII history
verified total entry count
```

The next request sends that count as `ima_offset`. The CVM returns:

```text
ima_start_index = previous verified total
ima_entry_count = current total
ima_binary_log_b64 = binary events [start, total)
ima_ascii_log_b64 = ASCII lines [start, total)
```

Inside SGX, the WEN requires `ima_start_index` to equal both of its prior
history counts. It appends the delta, validates the declared total, performs
the full cryptographic verification, and only then commits the new history.
If the CVM cannot honor an offset, it sends a full snapshot with start index
zero, which the WEN verifies as a replacement history.

## WEN Verification Predicate

A DCAP round is trusted only when every required check passes:

1. The TDX quote signature verifies and its `report_data` binds the WEN nonce.
2. Binary and ASCII IMA lists have equal counts and template hashes.
3. The vTPM quote signature verifies under the transmitted `ak_pub`.
4. The vTPM quote qualifying data binds the same WEN nonce.
5. The signed PCR selection/composite is valid and contains SHA-256 PCR-10.
6. `SHA384(ak_pub)` equals both AK bind fields in the evidence.
7. `base -> SHA384(ak_pub)` equals the reported post-AK RTMR3 value.
8. Replaying all IMA events from that post-AK value equals quoted RTMR[3].
9. Signed PCR-10 equals replay of an exact prefix of the same binary IMA list.
10. The agent-reported prefix count equals the independently found count.
11. The anchored count and quoted RTMR3 metadata cover the complete list.
12. Golden boot and AK certificate policies pass when those policies are
    enabled.

## Policy Modes and Claims

### Default mechanics mode

The default is:

```text
--expected-rtmr3-base auto
no --require-golden
no --require-ak-cert
```

This mode validates the cryptographic composition and is suitable for
development testing. It accepts the RTMR3 startup base reported by the agent,
reports MRTD/RTMR0-2 without enforcing expected values, and does not fail when
the GCP AK certificate cannot be matched.

It proves that the same fresh response contains:

- A valid nonce-bound TDX quote.
- A full IMA list that replays to quoted RTMR[3] from the accepted base.
- An AK identity included in that RTMR3 chain.
- A valid nonce-bound AK signature over PCR-10.
- A signed PCR-10 value that replays from a prefix of the same IMA list.

It does not independently prove that an agent-reported nonzero RTMR3 base was
approved, that MRTD/RTMR0-2 are approved, or that the AK chains to a Google
root.

### Strict boot policy

Supply a trusted golden file and use `--require-golden`. The file can pin:

```json
{
  "mrtd": "<96 hex characters>",
  "rtmr0": "<96 hex characters>",
  "rtmr1": "<96 hex characters>",
  "rtmr2": "<96 hex characters>",
  "rtmr3_base": "<96 hex characters>"
}
```

With these values provisioned independently, a passing result additionally
proves that the quoted TD boot measurements and RTMR3 startup base match the
approved policy.

`--save-golden` is a trust-on-first-use convenience. Review and provision the
result out of band. For a production enclave, put the final golden file in
`sgx.trusted_files` before regenerating and signing the Gramine manifest. The
current certificate directory is allowed but not measured, so a golden file
left there is not enclave-pinned.

### AK certificate policy

`--require-ak-cert` requires the certificate public key to equal the AK public
key. This is a leaf key-binding check only. The current implementation does
not validate a complete certificate chain, revocation status, or Google root
policy. Do not claim full Google PKI provenance until that chain validation is
implemented.

## CVM Prerequisites

Run these checks on the TDX CVM:

```bash
test -c /dev/tdx_guest
test -r /sys/kernel/security/integrity/ima/binary_runtime_measurements
test -r /sys/kernel/security/integrity/ima/ascii_runtime_measurements
sudo test -w /sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384
python3 -c "import cryptography; print(cryptography.__version__)"
sudo gotpm attest --key AK --nonce "$(openssl rand -hex 20)" --format textproto >/tmp/gotpm-attest.txt
```

The server also needs `libtdx_attest.so`, the existing TLS certificates, and
root permission to read/extend the IMA/RTMR interfaces.

The gotpm installation used during prototype testing was:

```bash
git clone https://github.com/google/go-tpm-tools.git
cd go-tpm-tools/cmd
go build -o /tmp/gotpm ./gotpm
sudo install -m 0755 /tmp/gotpm /usr/local/bin/gotpm
which gotpm
gotpm --help | head
```

Use `sudo -E` when environment overrides such as `GCP_AK_NAME`,
`GCP_AK_HANDLE`, or `GCP_AK_CERT_NV` must survive sudo.

## Clean-Boot Requirement

TDX RTMRs cannot be reset during a TD boot. Each server start extends the AK
and complete current IMA list into the current RTMR[3]. Do not stop and restart
the server on the same boot for a clean policy test, because that extends the
same logical startup sequence again from a later base.

For repeatable tests:

1. Reboot or launch a fresh CVM.
2. Do not run an RTMR probe that extends RTMR[3].
3. Start the main TDX server once.
4. Use a pre-approved zero or golden RTMR3 base when the image guarantees it.

## Test Procedure

### 1. Update both machines

Use the same commit on the CVM and WEN. The shared protocol is version `1.1`,
and old main-protocol code does not understand the composed evidence object.

### 2. CVM self-test

On the TDX CVM:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/tdx-server
sudo -E python3 tdx_attestation_server.py --test --method dcap
```

Expected checks include the TDX guest device, `libtdx_attest`, binary IMA log,
RTMR[3], and GCP vTPM AK.

### 3. Start the production TDX server

Use the already allowed port `8443`:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/tdx-server
sudo -E python3 tdx_attestation_server.py --port 8443 --method dcap
```

Expected startup output includes:

```text
[RTMR3] AK bound: SHA384(ak_pub)=...
[RTMR3] startup anchored N entries in ... ms
Runtime Evidence: ima-rtmr3-vtpm-v1
Waiting for attestation challenges from SGX enclave...
```

Do not pass `--enable-ima false`; the enclave requires composed runtime
evidence by default.

### 4. Build the WEN enclave

On the Intel SGX machine:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier
python3 -c "import cryptography; print(cryptography.__version__)"
make clean
make all METHOD=dcap
```

Rebuild after changing any file in `sgx-verifier/` or `common/`; those files
are trusted and measured into the Gramine enclave.

### 5. Initial SGX smoke test

This command still runs the WEN inside Intel SGX but disables only TLS server
certificate validation for the first connectivity test:

```bash
export CVM_IP=<TDX_CVM_IP>
gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --method dcap \
  --no-verify \
  --expected-rtmr3-base auto \
  --verbose
```

The program should print `Running inside Gramine SGX enclave`, a trusted boot
verdict, `Runtime Verdict: CLEAN`, and check marks for all composed runtime
checks.

### 6. SGX test with the existing TLS/mTLS files

If the existing CA, server certificate, and SGX client certificate are valid
for the CVM address:

```bash
make run-sgx \
  TDX_HOST="$CVM_IP" \
  TDX_PORT=8443 \
  METHOD=dcap \
  RUNTIME_ARGS="--expected-rtmr3-base auto"
```

Start the CVM server with `--require-client-cert` only for this single-shot
path, because it supplies `sgx_client.crt` and `sgx_client.key`.

### 7. Long-running incremental WEN controller inside SGX

Start the CVM server without `--require-client-cert`, then run:

```bash
make run-controller \
  TDX_HOST="$CVM_IP" \
  TDX_PORT=8443 \
  METHOD=dcap \
  CONTROLLER_ID=ctrl-1 \
  CONTROLLER_PORT=9001 \
  REFRESH_INTERVAL=30 \
  RUNTIME_ARGS="--expected-rtmr3-base auto"
```

The first refresh transfers the full log. Later server logs should report a
nonzero start index and only new entries sent. Every successful controller
refresh advances the enclave-held history.

### 8. Generate and observe incremental IMA events

In another CVM terminal:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/tdx-server
sudo python3 generate_ima_entries.py --count 10
```

At the next refresh, the CVM should extend the new entries into RTMR[3], and
the WEN should remain `TRUSTED` and `CLEAN` with a larger IMA entry count.

### 9. Query the SGX controller

On an end-user machine that can reach the SGX host:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/end-user
python3 end_user_client.py \
  --controller-host <SGX_HOST_IP> \
  --controller-port 9001 \
  --no-verify
```

The token should report `tdx_verified`, the composed runtime verdict, total
verified IMA entries, and individual runtime checks.

### 10. Enforce golden boot values

Capture only from a manually approved clean CVM:

```bash
gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
  --tdx-host "$CVM_IP" --tdx-port 8443 --method dcap --no-verify \
  --expected-rtmr3-base auto \
  --save-golden /app/certs/golden_boot.json
```

Review and provision that file, rebuild the enclave if it is moved into
trusted files, and enforce it:

```bash
gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
  --tdx-host "$CVM_IP" --tdx-port 8443 --method dcap --no-verify \
  --golden-file /app/certs/golden_boot.json \
  --require-golden \
  --expected-rtmr3-base auto
```

When a golden file contains `rtmr3_base`, `auto` uses that pinned value rather
than agent metadata.

## Expected Result

A successful single-shot or controller refresh has:

```text
TDX quote signature       OK
TDX nonce binding         OK
binary/ASCII IMA          OK
vTPM signature            OK
vTPM nonce                OK
AK bind consistency       OK
AK RTMR step              OK
full RTMR3 replay         OK
signed PCR10 prefix       OK
prefix count              OK
golden/AK policy          OK or explicitly not required
overall verdict           TRUSTED / CLEAN
```

## Remaining Limitations

- RTMR[3] completeness is agent-mediated because the upstream CVM kernel does
  not extend RTMR[3] from the IMA measurement path.
- PCR-10 completeness remains kernel-enforced, but the vTPM is a virtual trust
  component supplied by the cloud platform.
- The local TDX quote verifier still lacks complete Intel collateral, PCK,
  CRL, and TCB policy validation.
- AK leaf key matching is implemented; full Google certificate-chain and
  revocation validation is not.
- `auto` startup-base mode is not a substitute for a trusted RTMR3 base.
- The Gramine manifest currently runs with `sgx.debug = true`; this is a
  research configuration, not a production enclave policy.
- The controller-to-TDX path does not currently present the SGX mTLS client
  certificate, so use the non-client-authenticated CVM listener for the
  long-running controller or extend that path before requiring mTLS.
