# TDX DCAP Attestation

Pure DCAP-based TDX attestation — generates and verifies TDX quotes **locally** without Intel Trust Authority (ITA).


## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    DCAP ATTESTATION FLOW                          │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  [1] Generate Report Data (nonce)                                  │
│       │                                                            │
│       ▼                                                            │
│  [2] TDX Hardware (/dev/tdx_guest)                                 │
│       │ ── configfs-tsm ──► QGS ──► Quoting Enclave ──► Quote     │
│       │    (or ioctl for TDREPORT only)                            │
│       ▼                                                            │
│  [3] Parse Binary Quote                                            │
│       │ Extract: MRTD, RTMRs, report_data, signature, PCK certs   │
│       ▼                                                            │
│  [4] Fetch Collateral (one-time, cached)                           │
│       │ Intel PCS: TCB Info, QE Identity, CRLs                    │
│       ▼                                                            │
│  [5] Verify Quote (ALL LOCAL)                                      │
│       ├── ECDSA-P256 signature verification                       │
│       ├── PCK certificate chain (PCK → Platform CA → Intel Root)  │
│       ├── CRL checking (not revoked)                              │
│       ├── TCB status (UpToDate, OutOfDate, etc.)                  │
│       └── Nonce binding (report_data matches)                     │
│       ▼                                                            │
│  [6] Verdict: TRUSTED / UNTRUSTED                                  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

## Files

| File | Description |
|------|-------------|
| `dcap_attestation.py` | Main entry point — end-to-end attestation |
| `quote_generator.py` | TDX quote generation (configfs-tsm + ioctl) |
| `quote_parser.py` | Binary TDX quote parser (v4/v5) |
| `collateral_fetcher.py` | Intel PCS collateral fetcher with caching |
| `dcap_verifier.py` | Local DCAP verification (signatures, certs, TCB) |
| `setup_dcap.sh` | Install Intel DCAP packages (QGS) |
| `collateral/` | Cached verification collateral |

## Quick Start

### 1. TDREPORT Only (No setup needed)

```bash
# Generates a TDREPORT showing TDX measurements (no QGS required)
sudo python3 dcap_attestation.py --report-only --verbose
```

### 2. Full DCAP Attestation

```bash
# Install QGS for full quote generation (one-time)
sudo bash setup_dcap.sh

# Run full attestation
sudo python3 dcap_attestation.py --verbose
```

### 3. With Custom Nonce

```bash
# Generate and use a specific nonce
NONCE=$(openssl rand -hex 32)
sudo python3 dcap_attestation.py --report-data $NONCE --verbose
```

### 4. Save and Verify Quotes Offline

```bash
# Generate and save quote
sudo python3 dcap_attestation.py --save-quote quote.bin

# Verify saved quote (can be done on a different machine)
python3 dcap_attestation.py --verify-quote quote.bin --verbose
```

## Prerequisites

- **TDX VM** with `/dev/tdx_guest` available
- **Python 3.10+** with `cryptography`, `requests` packages
- **QGS** (optional, for full quote generation — install via `setup_dcap.sh`)
- **Internet** (one-time, for fetching collateral from Intel PCS)

## Comparison with Existing ITA-Based Attestation

This project sits alongside the existing `sgx-tdx-attestation/` which uses Intel Trust Authority:

```
research/
├── sgx-tdx-attestation/          # ITA-based (trustauthority-cli → Intel cloud)
│   ├── tdx-server/               #   TDX server calls ITA per quote
│   └── sgx-verifier/             #   Verifier trusts ITA's JWT
│
└── tdx-dcap-attestation/         # DCAP-based (this project)
    ├── dcap_attestation.py       #   Generates + verifies quotes locally
    └── collateral/               #   Cached Intel collateral
```
