# IMA -> RTMR[3] Prototype Debugging Notes

This document records what did not work during the TDX CVM to SGX WEN
attestation experiments, what we tried, what the actual issue was, and what
ended up working.

The final working prototype lives in:

- `research/ima_rtmr3_test/cvm_rtmr3_agent.py`
- `research/ima_rtmr3_test/wen_rtmr3_verifier.py`
- `research/ima_rtmr3_test/ima_rtmr3_common.py`
- `research/ima_rtmr3_test/diagnose_pcr10.py`

The final successful WEN result had:

```text
Quote verdict:      TRUSTED
Quote signature:    OK
Nonce binding:      OK
RTMR3 check:        OK
Snapshot stable:    OK
SHA-1 check:        OK
SHA-256 check:      OK
PCR10 check:        OK
Overall:            OK
```

## Final Design That Worked

The working design keeps both anchors:

1. Agent-mediated RTMR[3] anchor:
   - The CVM agent reads the kernel IMA binary measurement log.
   - It extends each IMA entry into TDX RTMR[3].
   - The WEN verifier replays the presented IMA binary log and compares the
     result to the quoted RTMR[3] value from the TDX quote.

2. PCR-10 defense-in-depth:
   - The WEN verifier also replays the same IMA evidence into PCR-10 SHA-1
     and SHA-256 candidate values.
   - It compares those replayed values against the PCR-10 values reported by
     the CVM agent.

The RTMR[3] mapping intentionally does not pad or directly reuse the IMA
template hash. RTMR extends are SHA-384, while normal IMA template hashes are
usually SHA-1/SHA-256. The working design extends:

```text
SHA384(canonical_serialization(ima_binary_entry))
```

The canonical serialization is:

```text
"IMA-RTMR3-CANON-v1\0"
|| LE32(pcr_index)
|| LE32(len(template_hash)) || template_hash
|| LE32(len(template_name)) || template_name
|| LE32(len(template_data)) || template_data
```

The RTMR chain is:

```text
new_rtmr3 = SHA384(old_rtmr3 || event_digest)
```

This is implemented in `ima_rtmr3_common.py`.

## Issue 1: The GCP CVM Kernel Does Not Provide Upstream IMA -> RTMR Support

What did not work:

- The original desired design was kernel-enforced IMA anchoring directly into a
  TDX RTMR.
- On the tested Google Cloud TDX CVM image, the RTMRs were readable and
  runtime-extendable, but the kernel did not have upstream IMA -> RTMR
  anchoring logic.

What we checked:

- RTMR access was validated separately with the runtime RTMR probe script.
- The VM exposed writable TDX guest RTMR measurement attributes, including
  RTMR[3].
- Existing IMA -> PCR-10 kernel behavior was working.

What ended up working:

- We built an isolated user-space agent under `research/ima_rtmr3_test`.
- The agent tails the kernel IMA log and extends RTMR[3] itself.
- This gives a hardware-rooted RTMR[3] append-only anchor, but the completeness
  is agent-mediated rather than kernel-enforced.
- PCR-10 remains as an additional kernel-enforced completeness check.

Important limitation:

- This prototype is not the same as upstream kernel IMA -> RTMR anchoring.
- If the agent is not started early enough, entries measured before the agent
  starts must be replayed from the existing IMA log. That is why the agent
  performs a startup replay from entry 0.

## Issue 2: vTPM Quote Over PCR-10 Was Not Implemented

What did not work:

- We checked whether the existing protocol transferred a vTPM quote over
  PCR-10 to the WEN.
- It did not. The earlier code read and replayed PCR-10, but did not transfer
  a vTPM quote to cryptographically bind PCR-10 to the VM's vTPM.

What we tried:

- We inspected the TDX-side protocol code and WEN-side logic.
- We confirmed that the runtime IMA log and PCR-10 value were being used, but
  no vTPM quote object over PCR-10 was sent to the WEN.

What ended up working for this prototype:

- RTMR[3] is the primary hardware-quoted runtime anchor.
- PCR-10 is treated as defense-in-depth in the current test harness.
- The WEN checks that the presented IMA log replays to the reported PCR-10
  values.

Important limitation:

- In this prototype, the PCR-10 values are still agent-reported values, not
  independently vTPM-quoted values.
- For a stronger final protocol, add a real vTPM quote over PCR-10 and bind it
  to the same WEN challenge or to the TDX quote challenge.

## Issue 3: Python Package Invocation Failed For Commissioning Client

What did not work:

Running the commissioning client as a module from inside the package directory
failed:

```text
/usr/bin/python3: Error while finding module specification for
'commissioning_phase.asp_client' (ModuleNotFoundError: No module named
'commissioning_phase')
```

What was wrong:

- Python could not resolve `commissioning_phase` as a top-level package from
  that working directory.
- This was an invocation/path issue, not an attestation failure.

What ended up working:

- Run the module from the repository parent/root where
  `commissioning_phase` is importable.
- Alternatively set `PYTHONPATH` to the repository root before invoking the
  module.

This issue was separate from the RTMR[3] prototype, but it blocked the earlier
CVM launch flow.

## Issue 4: Reference Manifest Rejected Legitimate CVM Boot Measurements

What did not work:

- During commissioning Phase C', the IMA verifier rejected the CVM boot because
  files measured during boot were not present in `reference_manifest.json`.
- The failures appeared as:

```text
MANIFEST VIOLATION! 36 unexpected file(s) detected
MANIFEST VIOLATION! 26 unexpected file(s) detected
MANIFEST VIOLATION! 16 unexpected file(s) detected
MANIFEST VIOLATION! 6 unexpected file(s) detected
```

Examples included:

- `/usr/bin/systemctl`
- `/usr/sbin/sshd`
- `/usr/lib/x86_64-linux-gnu/libcrypto.so.3`
- `/usr/bin/bash`
- `/usr/bin/tar`
- `/usr/bin/udevadm`
- several systemd, OpenSSL, libcurl, libxml, Perl, and shared-library files

What we tried:

- We repeatedly ran the commissioning flow and collected the exact unexpected
  file paths and SHA-256 hashes from the logs.
- We updated `commissioning_phase/reference_manifest.json` to include the
  measured hashes.

What was wrong:

- The manifest was incomplete for the actual Google Cloud CVM image and boot
  path being tested.
- The PCR-10 replay itself was succeeding, but the reference allowlist did not
  contain all legitimate measured files.

What ended up working:

- After adding the missing file hashes to the manifest, Phase C' passed and
  the CVM launch succeeded.

Important caveat:

- Adding hashes makes the manifest match this image and package state.
- It is not a general policy decision that all of those files should always be
  trusted on every image. The manifest should be regenerated or reviewed when
  the base image or package versions change.

## Issue 5: The Test Server Hung From The WEN Side On Port 9443

What did not work:

- The first RTMR[3] test agent used port `9443`.
- The WEN verifier hung while connecting:

```text
tls.connect((host, port))
KeyboardInterrupt
```

What we tried:

- We first treated it as a possible verifier or TLS issue.
- The CVM agent was running, but the WEN could not establish a connection.

What was wrong:

- The likely problem was GCP firewall reachability. The earlier working TDX
  server used port `8443`, while `9443` did not appear reachable from the WEN.

What ended up working:

- We moved the RTMR[3] test agent to port `8443`.
- This reused the existing firewall path and avoided adding new GCP firewall
  rules.

Working CVM command:

```bash
cd ~/sgx-tdx-composition-protocol/research/ima_rtmr3_test
sudo python3 cvm_rtmr3_agent.py --port 8443 --method dcap
```

Working WEN command:

```bash
cd ~/sgx-tdx-composition-protocol/research/ima_rtmr3_test
python3 wen_rtmr3_verifier.py --tdx-host "$CVM_IP" --no-verify
```

## Issue 6: RTMR[3] Worked, But PCR-10 Initially Mismatched

What did not work:

- After the first working WEN connection, RTMR[3] replay matched the quote, but
  PCR-10 did not match:

```text
RTMR3 check:      OK
PCR10 check:      MISMATCH
Overall:          FAIL
```

Example:

```text
Expected PCR10:   c52f4c5f2590be961ad42b817108665957808a60
Claimed PCR10:    77ca1018640968926d5bbe50da7f13f320dcf685
```

What we tried:

- We compared the number of IMA entries parsed from the binary log with the
  kernel runtime measurement count.
- We added JSON output and inspected:

```text
anchored_count
ima_count_kernel
ima_entries
rtmr3_match
pcr10_match
expected_pcr10
claimed_pcr10
```

What was wrong:

- The IMA log can grow while the agent is collecting evidence.
- The agent was sometimes reading:
  - one version of the IMA binary log,
  - a later PCR-10 value,
  - and a different runtime measurement count.
- That creates a time-of-check/time-of-use snapshot race.

What ended up working:

- The CVM agent now collects a stable snapshot.
- It checks that:
  - binary IMA entry count,
  - ASCII IMA entry count,
  - kernel runtime measurement count before collection,
  - and kernel runtime measurement count after collection
  all agree.
- If the values do not agree, the agent retries.

Expected healthy log:

```text
[SNAPSHOT] unstable (...); retrying
```

followed by WEN output:

```text
Snapshot stable:  OK (attempt=2, entries=3956, before=3956, after=3956)
```

The unstable snapshot message is not a failure. It means the race was detected
and the agent retried.

## Issue 7: Binary And ASCII Logs Needed To Be Compared

What did not work:

- Early PCR-10 mismatches could have been caused by a parser bug, ASCII/binary
  disagreement, or an incomplete log.

What we tried:

- We updated the agent to send both:
  - `/sys/kernel/security/integrity/ima/binary_runtime_measurements`
  - `/sys/kernel/security/integrity/ima/ascii_runtime_measurements`
- The WEN verifier compares binary and ASCII counts.
- It also checks whether the template hashes from binary entries match the
  hashes in the ASCII log.

What ended up working:

The WEN verifier now reports:

```text
IMA entries:      3,956 binary, 3,956 ASCII
Binary/ASCII ct:  OK
Binary/ASCII dig: OK
```

This ruled out a binary parser error for the final tests.

## Issue 8: PCR-10 Replay Still Failed After Stable Snapshots

What did not work:

- Even with stable snapshots and binary/ASCII agreement, PCR-10 still failed:

```text
SHA-1 check:      MISMATCH
SHA-256 check:    MISMATCH
PCR10 check:      MISMATCH
```

What we tried:

- We added `diagnose_pcr10.py`.
- It checks:
  - binary entry count,
  - ASCII entry count,
  - kernel runtime count before and after,
  - binary/ASCII hash agreement,
  - whether `sha1(template_data)` equals the logged template hash,
  - several PCR replay candidate formulas.

The diagnostic showed:

```text
binary_entries        = 39009
ascii_entries         = 39009
kernel_count_before   = 39009
kernel_count_after    = 39009
binary_ascii_hashes   = MATCH
zero_hash_violations = 8
sha1(template_data)   = 39001/39001 comparable entries match
```

What this proved:

- The log was complete.
- The binary and ASCII views agreed.
- The parser was not corrupting the log.
- Almost every non-violation entry matched `sha1(template_data)`.
- The remaining entries were special all-zero template-hash entries.

## Issue 9: All-Zero IMA Template Hashes Were Handled Wrong

What did not work:

- The replay code initially treated every all-zero logged template hash like a
  normal digest, or tested variants that skipped those entries.
- Both choices failed.

The diagnostic showed the key pattern:

```text
logged_sha1   = 0000000000000000000000000000000000000000
computed_sha1 = <nonzero sha1(template_data)>
```

What was wrong:

- All-zero IMA template hashes are IMA violation entries.
- They commonly appear for time-of-measurement/time-of-use or open-writers
  cases.
- The kernel does not replay them as normal zero digests and they should not be
  skipped.

What we tried:

- Normal SHA-1 replay from the logged template hash.
- SHA-256 replay from `SHA256(template_data)`.
- Skipping zero-hash entries.
- Replaying SHA-256 using the ASCII SHA-1 template-hash column.

What failed:

- Skipping zero-hash violation entries failed.
- Replaying SHA-256 from the ASCII SHA-1 hash column failed.
- Treating zeros as ordinary zero digests failed.

What ended up working:

- For an all-zero SHA-1 template hash, extend an all-ones digest of the PCR
  bank width:

```text
SHA-1 bank:    0xff * 20
SHA-256 bank:  0xff * 32
```

The working logic is:

```python
if entry.template_hash == b"\x00" * 20:
    digest = b"\xff" * digest_len
else:
    digest = normal_entry_digest
```

For SHA-1:

```text
normal_entry_digest = logged SHA-1 template hash
```

For SHA-256:

```text
normal_entry_digest = SHA256(template_data)
```

After this fix, the diagnostic showed:

```text
sha1_ascii_match       = True
sha1_binary_match      = True
sha256_binary_match    = True
diagnosis = PCR replay formula works for at least one bank
```

And the WEN verifier showed:

```text
SHA-1 check:      OK
SHA-256 check:    OK
PCR10 check:      OK
Overall:          OK
```

## Issue 10: ASCII IMA Log Cannot Reconstruct SHA-256 PCR Replay By Itself

What did not work:

- One diagnostic candidate tried to replay the SHA-256 PCR bank from the ASCII
  log's SHA-1 template hash column.

What was wrong:

- The ASCII IMA log carries the SHA-1 template hash column.
- It does not contain enough information to reconstruct the SHA-256 bank for
  normal entries.
- The SHA-256 PCR bank needs `SHA256(template_data)`, which requires the binary
  IMA log's full template data.

What ended up working:

- SHA-1 PCR replay can use either:
  - the ASCII log's SHA-1 template hash column, or
  - the binary log's `template_hash`.
- SHA-256 PCR replay must use the binary log and compute:

```text
SHA256(template_data)
```

except for all-zero violation entries, which extend `0xff * 32`.

## Issue 11: RTMR[3] Cannot Be Reset Inside A Running TD

What did not work:

- Restarting the agent on the same CVM boot is not equivalent to a clean test.
- RTMR[3] cannot be reset to zero from inside the live TD.

What was wrong:

- RTMRs are extend-only registers.
- If the agent replays the same IMA log again on the same boot, it extends
  those entries again.

What ended up working:

- For a strict security-style test:
  - use a freshly launched or rebooted CVM,
  - start the agent once,
  - use the known RTMR[3] base.
- For a mechanics test:
  - allow the verifier to use the agent-reported startup base with
    `--expected-rtmr3-base auto`.

Current prototype behavior:

- The agent prints the startup base and current RTMR[3]:

```text
[RTMR3] base   : ...
[RTMR3] current: ...
```

- The verifier replays from that base when using the default automatic base
  behavior.

## Issue 12: Agent Startup Can Look Slow With Large IMA Logs

What did not work:

- On a CVM with tens of thousands of IMA entries, starting
  `cvm_rtmr3_agent.py` appeared to take too long.

What was happening:

- The agent intentionally replays the entire existing IMA log into RTMR[3] on
  startup.
- It then tails new entries and extends them as they arrive.

What ended up working:

- For the final clean test, the CVM had a smaller startup log and replayed
  quickly:

```text
[RTMR3] startup replay anchored 3,944 entries in 61.8 ms
```

Operational guidance:

- If the agent is already running, do not restart it just to test WEN-side PCR
  replay changes.
- Restarting the agent on the same boot can also duplicate RTMR[3] extends
  unless the verifier accounts for the new startup base.
- For clean tests, reboot/relaunch the CVM and start the agent once.

## Issue 13: Golden Boot Measurements Were Not Enforced Yet

What did not work:

- The WEN output reported:

```text
Golden file:      not provided; MRTD/RTMR0-2 are reported only
```

What this means:

- The quote, nonce, RTMR[3], and PCR-10 checks passed.
- But the verifier did not enforce a policy over MRTD and RTMR[0..2].

What ended up working for the runtime prototype:

- We treated MRTD and RTMR[0..2] as reported values while testing the runtime
  RTMR[3] and PCR-10 logic.

Next step for a stricter protocol:

1. Save golden boot measurements from a known-good CVM:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --no-verify \
  --save-golden golden_boot.json
```

2. Enforce them:

```bash
python3 wen_rtmr3_verifier.py \
  --tdx-host "$CVM_IP" \
  --no-verify \
  --golden-file golden_boot.json \
  --require-golden
```

## Summary Of What Finally Worked

The working recipe is:

1. Use the isolated prototype under `research/ima_rtmr3_test`.
2. Run the CVM agent on port `8443`, not `9443`.
3. Let the CVM agent replay the existing IMA binary log into RTMR[3].
4. Let the CVM agent tail new IMA entries and extend RTMR[3].
5. Have the WEN verifier request a nonce-bound TDX quote.
6. Verify the TDX quote signature and nonce binding.
7. Replay the binary IMA log through the canonical SHA-384 mapping.
8. Compare replayed RTMR[3] against quoted RTMR[3].
9. Collect a stable snapshot by retrying if IMA counts change during evidence
   collection.
10. Compare binary and ASCII IMA log counts and hashes.
11. Replay PCR-10 SHA-1 from the ASCII or binary SHA-1 template hashes.
12. Replay PCR-10 SHA-256 from binary `template_data`.
13. For all-zero IMA violation template hashes, extend `0xff * digest_len`
   instead of zero or skipping.
14. Confirm:

```text
RTMR3 check:      OK
Snapshot stable:  OK
SHA-1 check:      OK
SHA-256 check:    OK
PCR10 check:      OK
Overall:          OK
```

## Current Remaining Gaps

The prototype is now working, but these are still important if this becomes
part of the main protocol:

1. Add a real vTPM quote over PCR-10, or otherwise clearly state that PCR-10 is
   only an agent-reported defense-in-depth value in the current prototype.
2. Enforce golden MRTD and RTMR[0..2] values with `--require-golden`.
3. Decide how early the RTMR[3] agent must start in production.
4. Avoid restarting the agent repeatedly on the same TD boot unless the
   verifier intentionally handles the nonzero RTMR[3] startup base.
5. Move the validated logic from the isolated test harness into the original
   incremental attestation protocol only after the golden/vTPM policy choices
   are finalized.

