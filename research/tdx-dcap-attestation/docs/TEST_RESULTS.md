# DCAP Attestation Test Results

Test results from running DCAP-based TDX attestation on GCP TDX VM.

**Date**: February 20, 2026  
**VM**: `tdx-research-vm.c.braided-hangout-472219-a5.internal`  
**Kernel**: 6.14.0-1020-gcp

## Test 1: TDREPORT Generation (ioctl)

**Command**:
```bash
sudo python3 dcap_attestation.py --report-only --verbose
```

**Result**: ✅ PASS

| Field | Value |
|-------|-------|
| Generation time | <0.1ms |
| MRTD | `a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694` |
| RTMR[0] | `cdd12631746b633b87592779e3118c959c8d9e306792ba9ad960fa5eec05f286d765bcbeecf397ec57cc3c626a2292c7` |
| RTMR[1] | `160767baf7423a37bcfbc903877d36c174831818b56aed335b99495a583b1dfa31eaef8f04da3f5d8c1e1fcc5f3a7c13` |
| RTMR[2] | `4e1d7c0083277d4b617cee58f0b9d76c4a48ce36b1e25cb6ee22b00bae9c959aec0bf20fd5eede0e4eb83317f534b902` |
| RTMR[3] | `000...000` (all zeros) |
| MRSEAM | `489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72` |
| TD Attributes | `0000001000000000` (debug=False) |
| XFAM | `e700060000000000` |
| CPUSVN | `0808ff1b04ff00060000000000000000` |
| TEE TCB SVN | `0d010800000000000000000000000000` |

**Cross-validation**: MRTD matches ITA-based attestation from `sgx-tdx-attestation` ✅

## Test 2: Full DCAP Quote Generation + Verification

**Command**:
```bash
sudo python3 dcap_attestation.py --verbose
```

**Result**: ✅ PASS (Verdict: TRUSTED)

| Step | Result | Details |
|------|--------|---------|
| Quote Generation | ✅ | 8000 bytes, 42.3ms, via configfs-tsm |
| Quote Parsing | ✅ | Version 4, ECDSA-P256, TEE Type: TDX |
| Collateral Fetch | ✅ | TCB Info, QE Identity, CRLs from Intel PCS |
| ECDSA Signature | ✅ | Valid |
| Nonce Binding | ✅ | Report data matches |
| PCK Cert Chain | ⚠️ | Not embedded in GCP quote format |
| TCB Status | ⚠️ | OutOfDate (FMSPC mismatch) |
| **Verdict** | **TRUSTED** | 14.1ms verification time |

### Quote Header Details

| Field | Value |
|-------|-------|
| Version | 4 |
| Attestation Key Type | ECDSA-P256 |
| TEE Type | TDX (0x81) |
| QE Vendor ID | `939a7233f79c4ca9940a0db3957f0607` |
| Quote Size | 8000 bytes |
| Signature Data Length | 4299 bytes |

### Attestation Key (Stable Across Runs)

| Component | Value |
|-----------|-------|
| x | `e0cd61413e5e30a342ce4d173ea9be2bc0c6bce3ea93a91cfe27662cee64143f` |
| y | `19d6c6fdf3e19fc8936911dc2c167a5c282dc81ee3a515f5c1560f61e293d10e` |

## Test 3: Collateral Caching

| Run | Source | Notes |
|-----|--------|-------|
| First | Intel PCS (fresh) | Downloads TCB Info, QE Identity, CRLs |
| Second | Local cache | Files read from `collateral/` directory |

Cached files in `collateral/`:
- `00806F050000_tcb_info.json` — TCB levels
- `00806F050000_qe_identity.json` — QE identity reference
- `00806F050000_tcb_issuer_chain.pem` — TCB issuer cert chain
- `00806F050000_qe_issuer_chain.pem` — QE issuer cert chain
- `00806F050000_pck.crl` — PCK CRL (DER)
- `00806F050000_root_ca.crl` — Root CA CRL (DER)
- `00806F050000_pck_crl_issuer_chain.pem` — PCK CRL issuer chain

## Performance Summary

| Operation | Time |
|-----------|------|
| TDREPORT generation (ioctl) | <0.1ms |
| Full quote generation (configfs-tsm) | ~42ms |
| Quote parsing | <1ms |
| Collateral fetch (first run) | ~2-5s |
| Collateral load (cached) | <10ms |
| ECDSA verification | ~14ms |
| **Total (cached collateral)** | **~56ms** |
| **Total (fresh collateral)** | **~5s** (one-time) |

Compare: ITA-based attestation via `trustauthority-cli` takes **1-2 seconds per attestation**.
