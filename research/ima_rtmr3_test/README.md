# IMA -> RTMR[3] Test Harness

This folder is an isolated prototype for agent-mediated IMA anchoring into
TDX RTMR[3]. It does not modify the working hierarchical or incremental
protocol files.

## Design

The CVM agent reads the kernel binary IMA measurement list, extends RTMR[3],
then returns a nonce-bound DCAP quote plus the binary IMA log and PCR-10 value
to the WEN verifier.

The verifier checks three things:

1. The quoted RTMR[3] equals replay(binary IMA log).
2. MRTD and RTMR[0..2] equal golden boot values when a golden file is provided.
3. PCR-10 SHA-1 replay from the same binary IMA log equals the vTPM PCR-10 value.

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

## Important Test Semantics

RTMRs cannot be reset inside a live TD. The startup behavior intentionally
replays the whole existing IMA log into the current RTMR[3]. If you restart the
agent on the same CVM boot, the same IMA entries are extended again.

For a clean security-style test, use a freshly launched or rebooted CVM and a
known RTMR[3] base. For a mechanics test after running `rtmr_probe.sh`, use the
verifier default `--expected-rtmr3-base auto`; it uses the startup base reported
by the agent and verifies that the quote matches the replay from that base.

## CVM Side

Use a separate port, `9443`, so this can run alongside the existing TDX server
on `8443`.

```bash
cd ~/sgx-tdx-composition-protocol/research/ima_rtmr3_test
sudo python3 cvm_rtmr3_agent.py --test
```

Start the agent:

```bash
sudo python3 cvm_rtmr3_agent.py --port 9443 --method dcap
```

Expected startup behavior:

```text
[RTMR3] startup replay anchored N entries in ... ms
[RTMR3] base   : ...
[RTMR3] current: ...
Waiting for WEN verifier requests...
```

If the WEN is outside the CVM network, open firewall port `9443` from the WEN
machine to this CVM.

## WEN Side, Pure Python Smoke Test

```bash
cd /home/nkoirala/sgx-tdx-composition-protocol/research/ima_rtmr3_test
export CVM_IP=<cvm-ip>

python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 9443 \
  --no-verify
```

Expected result:

```text
Quote verdict:      TRUSTED
RTMR3 check:        OK
PCR10 check:        OK
Overall:            OK
```

## Create And Use A Golden Boot File

First run after launching a known-good CVM:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 9443 \
  --no-verify \
  --save-golden golden_boot.json
```

Then enforce MRTD/RTMR[0..2] checks:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 9443 \
  --no-verify \
  --golden-file golden_boot.json \
  --require-golden
```

For a strict RTMR[3] base check on a clean CVM, replace the default auto base:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 9443 \
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
  --tdx-port 9443 \
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
  --tdx-port 9443 \
  --no-verify
```

Run with the golden file saved at
`research/ima_rtmr3_test/golden_boot.json`:

```bash
gramine-sgx ./verifier /app/wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --tdx-port 9443 \
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
generate_ima_events.py   CVM workload helper for appending IMA entries
sgx-verifier/            Isolated Gramine SGX wrapper for the WEN verifier
```
