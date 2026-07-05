# IMA -> RTMR[3] Test Harness

This folder is an isolated prototype for agent-mediated IMA anchoring into
TDX RTMR[3]. It does not modify the working hierarchical or incremental
protocol files.

## Design

The CVM agent reads the kernel binary IMA measurement list, binds the
GCP-provisioned vTPM AK into RTMR[3], extends RTMR[3] with the IMA chain, then
returns a nonce-bound DCAP quote, the binary IMA log, and a nonce-bound vTPM
quote over PCR-10 to the WEN verifier.

The verifier checks five things:

1. The TDX quote is valid and binds the WEN nonce.
2. The quoted RTMR[3] equals replay(firmware base -> SHA384(ak_pub) -> binary IMA log).
3. The vTPM quote is valid, fresh, signed by the AK, and covers SHA-256 PCR-10.
4. The AK hashed into RTMR[3] is the same AK that signed the PCR-10 quote.
5. MRTD and RTMR[0..2] equal golden boot values when a golden file is provided.

## Canonical IMA Event Mapping

Each binary IMA event is parsed as:

```text
LE32(pcr_index)
template_hash[20]
LE32(template_name_len)
template_name[template_name_len]
LE32(template_data_len)
template_data[template_data_len]
```

The RTMR[3] extend input for one event is:

```text
SHA384(
  "IMA-RTMR3-CANON-v1\0"
  || LE32(pcr_index)
  || LE32(len(template_hash)) || template_hash
  || LE32(len(template_name)) || template_name
  || LE32(len(template_data)) || template_data
)
```

The RTMR[3] chain is:

```text
new_rtmr3 = SHA384(old_rtmr3 || event_extend_input)
```

This intentionally does not extend the IMA template hash directly. The digest
is over canonicalized binary event contents, including the full template data.

Before replaying IMA entries, the agent first extends `SHA384(ak_pub)` into
RTMR[3], where `ak_pub` is the marshalled TPM2B_PUBLIC for the GCP-provisioned
AK. The verifier uses the same transmitted `ak_pub` bytes to recompute that
extend step and verifies that this is also the key that signed the vTPM PCR-10
quote.

## vTPM AK And Tooling Requirements

CVM side requirements:

- Preferred on GCP: `gotpm` installed and `sudo gotpm attest --key AK --nonce <hex> --format textproto` working.
- Optional fallback: GCP-provisioned AK available at `GCP_AK_HANDLE` (default `0x810000801`) with `tpm2-tools`.
- Google AK certificate readable from gotpm output or from `GCP_AK_CERT_NV` (default `0x1c10000`).

WEN side requirements:

- For gotpm evidence, no TPM device and no `tpm2_checkquote` are required; the verifier checks the TPM quote/signature in Python.
- Python `cryptography` installed so the verifier can check the AK signature and, when present, the Google leaf certificate key binding.
- `tpm2_checkquote` is only needed if the CVM uses the optional tpm2-tools evidence path.

If the AK is provisioned at a different persistent handle, set:

```bash
export GCP_AK_HANDLE=<handle>
```

If gotpm uses a different key name, set:

```bash
export GCP_AK_NAME=<name>
```

If the certificate is at a different NV index for the tpm2-tools fallback, set:

```bash
export GCP_AK_CERT_NV=<nv-index>
```

## Important Test Semantics

RTMRs cannot be reset inside a live TD. The startup behavior intentionally
replays the whole existing IMA log into the current RTMR[3]. If you restart the
agent on the same CVM boot, the same IMA entries are extended again.

For a clean security-style test, use a freshly launched or rebooted CVM and a
known RTMR[3] base. For a mechanics test after running `rtmr_probe.sh`, use the
verifier default `--expected-rtmr3-base auto`; it uses the startup base reported
by the agent and verifies that the quote matches the replay from that base.

## CVM Side

Use port `8443`, which is the existing working firewall path. Stop the older TDX server on `8443` before starting this RTMR3 test agent.

```bash
cd ~/sgx-tdx-composition-protocol/research/ima_rtmr3_test
sudo python3 cvm_rtmr3_agent.py --test
```

Start the agent:

```bash
sudo python3 cvm_rtmr3_agent.py --port 8443 --method dcap
```

Expected startup behavior:

```text
[RTMR3] AK bound: SHA384(ak_pub)=...
[RTMR3] startup anchored N entries in ... ms
[RTMR3] base   : ...
[RTMR3] after AK: ...
[RTMR3] current: ...
Waiting for WEN verifier requests...
```

If the WEN is outside the CVM network, open firewall port `8443` from the WEN
machine to this CVM.

## WEN Side, Pure Python Smoke Test

```bash
cd /home/nkoirala/sgx-tdx-composition-protocol/research/ima_rtmr3_test
export CVM_IP=<cvm-ip>

python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --no-verify
```

Expected result:

```text
Quote verdict:      TRUSTED
AK bind field:      OK
AK RTMR step:       OK
RTMR3 check:        OK
Signature/nonce:    OK
PCR10 signed:       OK
Overall:            OK
```

`Cert binds AK` is reported separately. It is not enforced by default because
gotpm/GCP certificate output can require additional chain decoding. To make it
a hard policy check, add `--require-ak-cert`.

## Create And Use A Golden Boot File

First run after launching a known-good CVM:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --no-verify \
  --save-golden golden_boot.json
```

Then enforce MRTD/RTMR[0..2] checks:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --no-verify \
  --golden-file golden_boot.json \
  --require-golden
```

For a strict RTMR[3] base check on a clean CVM, replace the default auto base:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --no-verify \
  --expected-rtmr3-base zero \
  --golden-file golden_boot.json \
  --require-golden
```

Use `zero` only if RTMR[3] is actually zero before the agent starts. If
`rtmr_probe.sh` already extended RTMR[3], use `auto` for this prototype test.

## Test New IMA Entries

In another terminal on the CVM:

```bash
cd ~/sgx-tdx-composition-protocol/research/ima_rtmr3_test
sudo python3 generate_ima_events.py --count 10 --label rtmr3
```

The agent should print that it extended new entries. Then rerun on WEN:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --no-verify \
  --golden-file golden_boot.json \
  --require-golden
```

The RTMR[3] value should change, but the check should still pass.

## WEN Side, SGX Enclave

Build the isolated SGX verifier:

```bash
cd /home/nkoirala/sgx-tdx-composition-protocol/research/ima_rtmr3_test/sgx-verifier
make clean
make all
```

Run without a golden file:

```bash
gramine-sgx ./verifier /app/wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --no-verify
```

Run with the golden file saved at
`research/ima_rtmr3_test/golden_boot.json`:

```bash
gramine-sgx ./verifier /app/wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 8443 \
  --no-verify \
  --golden-file /app/golden_boot.json \
  --require-golden
```

For production-grade SGX measurement, freeze the golden file before signing
and move it from `sgx.allowed_files` to `sgx.trusted_files` in the manifest.
For this prototype it is left as an allowed test input.

## Files

```text
cvm_rtmr3_agent.py       CVM-side RTMR[3] anchor and attestation server
wen_rtmr3_verifier.py    WEN verifier for quote, RTMR[3], PCR-10, golden boot
ima_rtmr3_common.py      Binary IMA parser and canonical replay logic
vtpm_quote.py            vTPM AK loading, PCR-10 quote generation, verification
generate_ima_events.py   CVM workload helper for appending IMA entries
sgx-verifier/            Isolated Gramine SGX wrapper for the WEN verifier
```
