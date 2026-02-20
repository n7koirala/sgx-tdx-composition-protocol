# DCAP Research Findings — GCP TDX VM

Observations and discoveries from implementing DCAP-based TDX attestation on a Google Cloud Platform Confidential VM (TDX).

## Environment

- **VM**: GCP C3 Confidential VM (Intel TDX)
- **OS**: Ubuntu 24.04.3 LTS (Noble Numbat)
- **Kernel**: 6.14.0-1020-gcp
- **TDX Device**: `/dev/tdx_guest` (char device 10,121, root-only `crw-------`)

## Key Findings

### 1. configfs-tsm Works Without QGS Installation

**Discovery**: On GCP TDX VMs with kernel 6.14, the `configfs-tsm` interface generates full TDX quotes **without installing Intel's DCAP packages** (no `tdx-qgs`, `libsgx-dcap-ql`, etc.).

This was unexpected. During initial testing, we assumed QGS was required because the [Intel documentation](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html) describes QGS as a necessary host-side service. However, GCP's custom kernel 6.14 has this functionality built-in.

**Evidence**:
```
$ ls /sys/kernel/config/tsm/report/
(empty directory — ready for use)

$ systemctl status qgsd
Unit qgsd.service could not be found.

$ dpkg -l | grep -E "sgx|dcap|tdx"
(no packages installed)
```

Yet, writing to `inblob` and reading `outblob` produces a valid 8000-byte TDX v4 Quote in ~42ms.

**Implication**: GCP handles the Quoting Enclave infrastructure at the hypervisor/VMM level, making it transparent to the guest. The `setup_dcap.sh` script (to install QGS) is **not needed on GCP**.

### 2. Initial configfs-tsm Test Hang

During early testing, a configfs-tsm test command hung indefinitely when reading `outblob`. This occurred before the Python implementation was complete. The likely cause was either:

- The test was running without proper `inblob` being written first
- A race condition in the kernel module

The Python implementation with proper sequencing (mkdir → write inblob → read outblob → rmdir) and a SIGALRM timeout works reliably.

### 3. TDREPORT Struct Layout — 128-Byte Reserved Padding

**Bug Found and Fixed**: The Intel TDX Module v1.5 ABI specification defines the TDREPORT (1024 bytes) as three sections:

| Section | Offset | Size |
|---------|--------|------|
| REPORTMACSTRUCT | 0 | 256 bytes |
| TEE_TCB_INFO | 256 | 256 bytes |
| TDINFO | 512 | 512 bytes |

The TEE_TCB_INFO section has **128 bytes of reserved padding** between `seam_attributes` (offset 376) and the start of TDINFO (offset 512). Our initial parser missed this padding, causing all TDINFO fields (MRTD, RTMRs, td_attributes, xfam) to be read at incorrect offsets.

**Symptom**: MRTD showed all zeros, while the actual MRTD value appeared in the MROWNER field position.

**Fix**: Added `skip(128)` after reading `seam_attributes` in the TDREPORT parser.

### 4. GCP Quote Format — No Embedded PCK Certificate Chain

Standard Intel DCAP quotes embed the full PCK certificate chain (PEM format) in the quote's certification data section (type 5). On GCP, the quote instead contains:

- **QE Auth Data**: 7086 bytes
- **Certification Data Type**: 0 (not type 5 / PCK chain)
- **No PEM certificates** in the quote

This means the PCK certificate chain must be obtained separately (from GCP's attestation infrastructure or Intel PCS) rather than extracted from the quote itself.

**Impact on verification**: The ECDSA signature verification still works because the attestation key is in the quote. The PCK chain verification step is skipped (noted as a warning).

### 5. Quote Generation Performance

| Method | Output | Time | Notes |
|--------|--------|------|-------|
| configfs-tsm | Full Quote (8000B) | ~42ms | Includes QE signing |
| ioctl | TDREPORT (1024B) | <0.1ms | Just TDX hardware call |
| trustauthority-cli | JWT Token | ~1-2s | ITA cloud call included |

DCAP quote generation is **~25x faster** than ITA, and the quote can be verified locally in ~14ms.

### 6. FMSPC Discovery Gap

The FMSPC (Family-Model-Stepping-Platform-CustomSKU) uniquely identifies the platform's Intel PCK certificate. On GCP:

- The PCK cert chain is not in the quote (see finding #4)
- Therefore, FMSPC cannot be auto-extracted from the quote
- We default to `00806F050000`, which may not match the actual platform
- This causes TCB Info matching to show "OutOfDate" (wrong TCB levels)

**Workaround**: The correct FMSPC could be obtained via:
1. Intel's Platform Registration API
2. GCP's confidential computing metadata service
3. Manual extraction from a PCK certificate (if obtainable separately)

### 7. Intel PCS API Quirks

| Issue | Resolution |
|-------|-----------|
| Root CA CRL endpoint (`/rootcacrl`) returns 404 | Use Intel's CRL distribution point URL instead: `certificates.trustedservices.intel.com/IntelSGXRootCA.der` |
| TDX-specific TCB Info endpoint | Use `/tdx/certification/v4/tcb` (not `/sgx/...`) |
| Issuer chain in response headers | URL-encoded PEM in `SGX-TCB-Info-Issuer-Chain` header |

### 8. Attestation Key Stability

Across multiple quote generations, the **attestation key remains the same**:

```
Att Key (x): e0cd61413e5e30a342ce4d173ea9be2bc0c6bce3ea93a91cfe27662cee64143f
Att Key (y): 19d6c6fdf3e19fc8936911dc2c167a5c282dc81ee3a515f5c1560f61e293d10e
```

This is expected — the QE uses the same ECDSA key pair for signing until it is re-provisioned. This key is certified by the PCK certificate chain.

### 9. Measurement Values

Consistent across all tests (as expected — the VM image hasn't changed):

| Measurement | Value | Notes |
|------------|-------|-------|
| **MRTD** | `a5844e88897b70c3...37288694` | Matches ITA-based attestation |
| **RTMR[0]** | `cdd12631746b633b...6a2292c7` | Firmware measurements |
| **RTMR[1]** | `160767baf7423a37...5f3a7c13` | OS kernel measurements |
| **RTMR[2]** | `4e1d7c0083277d4b...f534b902` | Application measurements |
| **RTMR[3]** | `000000...` (all zeros) | Unused |
| **MRSEAM** | `489e585f1c54bc5a...5819e72` | Intel TDX module |

## Security Considerations

### What DCAP Verifies Locally

1. ✅ **ECDSA-P256 signature** — proves the quote was generated by a genuine QE
2. ✅ **Nonce binding** — proves freshness (no replay)
3. ⚠️ **PCK chain** — not verifiable on GCP (no cert in quote)
4. ⚠️ **TCB status** — requires correct FMSPC for accurate evaluation
5. ✅ **Measurements** — MRTD, RTMRs, MRSEAM are always available

### What DCAP Does NOT Verify (vs ITA)

- ITA performs **JWT signature verification** using Intel's signing key
- ITA applies Intel's **appraisal policies** (TCB thresholds, debug mode rejection)
- ITA validates the **full PCK chain** server-side with access to all provisioning data

DCAP verification is as strong as ITA for the cryptographic checks, but may miss policy-level checks that ITA applies.

### Platform Linkability

DCAP quotes inherit the same linkability issue as ITA-based attestation:
- The **attestation key** is stable per-QE and can be used to link quotes
- The **FMSPC** (when available) identifies the physical platform
- Multiple quotes from the same VM share identical MRTD + attestation key

This is the same linkability concern documented in `PCK_LINKABILITY_ANALYSIS.md`.

## Recommendations

1. **For GCP TDX**: Use configfs-tsm directly — no Intel DCAP packages needed
2. **For bare-metal TDX**: Install QGS via `setup_dcap.sh` for full quote generation
3. **FMSPC**: Investigate GCP's metadata service or `gce-tdx-guest-attestation` for correct FMSPC
4. **Production**: Combine DCAP with SGX-TDX composition to break platform linkability
5. **TCB freshness**: Refresh collateral cache periodically (current: 24h, recommend: 1 week for research)
