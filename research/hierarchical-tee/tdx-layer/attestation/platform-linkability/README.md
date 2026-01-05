# Platform Linkability in TDX/DCAP Remote Attestation

This folder documents the privacy vulnerabilities arising from PCK (Platform Configuration Key) 
certificate exposure in Intel's DCAP-based attestation scheme for TDX.

## Contents

1. **[PCK_LINKABILITY_ANALYSIS.md](./PCK_LINKABILITY_ANALYSIS.md)** - Detailed analysis of how PCK certificates enable platform tracking
2. **[TOKEN_FIELDS_REFERENCE.md](./TOKEN_FIELDS_REFERENCE.md)** - Complete reference of all TDX attestation token fields and their privacy implications
3. **[MITIGATION_STRATEGIES.md](./MITIGATION_STRATEGIES.md)** - Potential approaches to preserve platform privacy

## The Core Problem

In Intel DCAP attestation, the **PCK certificate is platform-unique** and its derived identifiers 
are embedded in every attestation quote/token. This enables:

- **Global Linkability**: Any verifier can link multiple attestations to the same physical platform
- **Co-location Detection**: Determine which TDs run on the same host
- **Platform Profiling**: Build usage patterns and track workload migrations

## Quick Reference: Linkable Fields

| Field | Location in Token | Risk Level | Why |
|-------|------------------|------------|-----|
| FMSPC | `tdx_collateral.fmspc` | 🔴 HIGH | Platform family identifier |
| QE ID Hash | `tdx_collateral.qeidhash` | 🔴 HIGH | Platform-specific QE identity |
| TCB Date | `attester_tcb_date` | 🟡 MEDIUM | Reveals patch timeline |
| Advisory IDs | `attester_advisory_ids` | 🟡 MEDIUM | Narrows platform pool |
| SEAM SVN | `tdx_seamsvn` | 🟡 MEDIUM | TDX version linkage |

## Research Goal

Develop privacy-preserving attestation that:
1. ✅ Proves TD integrity (MRTD, RTMRs)
2. ✅ Proves platform security (TCB status)  
3. ❌ Does NOT reveal platform identity (FMSPC, QE hash, etc.)
