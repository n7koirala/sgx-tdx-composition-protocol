# SGX-TDX Hierarchical Attestation - Protocol Specification

## Protocol Version: 1.1

This document specifies the message formats and protocol flow for hierarchical TEE attestation.

---

## 1. Transport Layer

### TLS Configuration

| Parameter | Value |
|-----------|-------|
| Protocol | TLS 1.2 or higher |
| Port | 8443 (default) |
| Authentication | Server certificate (client verifies) |
| Cipher Suites | Default system (TLS_AES_256_GCM_SHA384 preferred) |

### Message Framing

Messages are framed with a delimiter:
```
<message_bytes>\n---END---\n
```

Maximum message size: 70 MB (needed for an initial full binary IMA history)

---

## 2. Message Formats

### 2.1 AttestationRequest

Sent from SGX Enclave to TDX Server.

```json
{
    "action": "attest",
    "nonce": "<base64_encoded_32_bytes>",
    "attestation_method": "dcap",
    "ima_offset": 0,
    "protocol_version": "1.1",
    "timestamp": 1704654321.123
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| action | string | Yes | Must be "attest" |
| nonce | string | Yes | Base64-encoded 32-byte random value |
| attestation_method | string | Yes | `ita` or `dcap` |
| ima_offset | integer | No | First IMA entry requested; zero requests a full history |
| protocol_version | string | Yes | Protocol version (`1.1`) |
| timestamp | float | No | Unix timestamp of request |

### 2.2 AttestationResponse

Sent from TDX Server to SGX Enclave.

**Success Response:**
```json
{
    "status": "success",
    "attestation_method": "dcap",
    "nonce_echo": "<original_nonce>",
    "mrtd": "a5844e88897b70c318bef929ef4dfd6c...",
    "raw_quote": "<base64_tdx_quote>",
    "runtime_evidence": {"version": "ima-rtmr3-vtpm-v1", "...": "..."},
    "error": "",
    "protocol_version": "1.1",
    "timestamp": 1704654322.456
}
```

**Error Response:**
```json
{
    "status": "error",
    "token": "",
    "nonce_echo": "",
    "mrtd": "",
    "error": "Token generation failed: API rate limit exceeded",
    "protocol_version": "1.1",
    "timestamp": 1704654322.456
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | string | Yes | "success" or "error" |
| attestation_method | string | Yes | `ita` or `dcap` |
| token | string | ITA | JWT token from Intel Trust Authority |
| raw_quote | string | DCAP | Base64-encoded nonce-bound TDX quote |
| runtime_evidence | object | DCAP | vTPM quote, incremental IMA data, AK bind, and RTMR3 metadata |
| nonce_echo | string | Yes* | Echo of received nonce |
| mrtd | string | No | TD Measurement (for convenience) |
| error | string | Yes* | Error message if status is "error" |
| protocol_version | string | Yes | Protocol version |
| timestamp | float | No | Unix timestamp of response |

*Required when status matches

### 2.3 DCAP Runtime Evidence

In protocol 1.1, `runtime_evidence` is required by the WEN in DCAP mode. It
contains the nonce-bound vTPM PCR-10 quote, exact AK public bytes, binary and
ASCII IMA data, signed-prefix metadata, and RTMR[3] anchor metadata. The exact
schema and predicate are specified in [VTPM_RTMR3_INTEGRATION.md](./VTPM_RTMR3_INTEGRATION.md).

---

## 3. Nonce Specification

### Generation

```python
nonce_bytes = secrets.token_bytes(32)  # 32 cryptographically random bytes
nonce_b64 = base64.b64encode(nonce_bytes).decode('ascii')  # ~44 characters
```

### ITA Binding

The TDX server passes the first 32 characters of the base64 nonce to `trustauthority-cli`:

```bash
trustauthority-cli token --tdx -c config.json -u "<nonce[:32]>"
```

This gets encoded as UTF-8 bytes in the TDX quote's `report_data` field.

### ITA Verification

The SGX enclave verifies nonce binding by checking if `nonce[:32].encode('utf-8')` appears in the decoded `report_data`:

```python
nonce_prefix = expected_nonce[:32]
nonce_prefix_bytes = nonce_prefix.encode('utf-8')
report_data_bytes = bytes.fromhex(report_data)
is_bound = nonce_prefix_bytes in report_data_bytes
```

### DCAP Binding and Verification

The decoded 32-byte nonce is placed in the TDX quote `report_data` and is also
passed as the vTPM quote qualifying data. The WEN independently requires both
nonce checks. A response assembled from a stale TDX quote or stale PCR quote
therefore fails even if the IMA data itself is internally consistent.

---

## 4. JWT Token Structure

The Intel Trust Authority JWT token contains:

### Header
```json
{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "<key_id>"
}
```

### Payload
```json
{
    "iss": "https://portal.trustauthority.intel.com",
    "iat": 1704654321,
    "exp": 1704657921,
    "jti": "<unique_token_id>",
    "tdx": {
        "tdx_mrtd": "<64_hex_chars>",
        "tdx_rtmr0": "<64_hex_chars>",
        "tdx_rtmr1": "<64_hex_chars>",
        "tdx_rtmr2": "<64_hex_chars>",
        "tdx_rtmr3": "<64_hex_chars>",
        "tdx_report_data": "<128_hex_chars>",
        "tdx_mrseam": "<64_hex_chars>",
        "tdx_mrsignerseam": "<64_hex_chars>",
        "tdx_seamsvn": 3,
        "tdx_mrowner": "<64_hex_chars>",
        "tdx_mrownerconfig": "<64_hex_chars>",
        "tdx_xfam": "0xe718060000000000",
        "tdx_is_debuggable": false,
        "attester_tcb_status": "UpToDate",
        "attester_tcb_date": "2024-03-15T00:00:00Z",
        "attester_advisory_ids": []
    }
}
```

---

## 5. ITA Verification Steps

For ITA mode, the SGX enclave performs these verifications in order:

### Step 1: JWT Structure
- Token has exactly 3 parts separated by `.`
- Header and payload are valid JSON

### Step 2: Issuer Verification
```python
issuer = payload['iss']
assert 'trustauthority.intel.com' in issuer
```

### Step 3: Expiry Verification
```python
exp = payload['exp']
assert exp > time.time()
```

### Step 4: Nonce Binding Verification
```python
report_data = payload['tdx']['tdx_report_data']
assert verify_nonce_binding(expected_nonce, report_data)
```

### Step 5: Policy Checks (Optional)
```python
# Example: reject debuggable TDs
assert payload['tdx']['tdx_is_debuggable'] == False

# Example: accept only specific MRTD
assert payload['tdx']['tdx_mrtd'] in TRUSTED_MRTD_LIST
```

### DCAP Composed Verification

For DCAP mode, the WEN requires all of the following:

1. TDX quote signature and nonce binding.
2. Binary/ASCII IMA consistency.
3. vTPM AK signature, nonce, PCR selection, and PCR composite validity.
4. Consistency between the AK that signs PCR-10 and the AK hash in RTMR[3].
5. Full IMA replay to the RTMR[3] in the TDX quote.
6. IMA-prefix replay to the PCR-10 in the vTPM quote.
7. Incremental offset/count continuity against enclave-held verified state.
8. Golden boot and AK certificate policies when configured.

Any required failure changes the complete DCAP verdict to `UNTRUSTED`.

---

## 6. Error Codes

| Error | Description | Action |
|-------|-------------|--------|
| `Connection refused` | TDX server not running | Start TDX server |
| `TLS error` | Certificate mismatch | Regenerate certificates |
| `Token generation failed` | Intel API error | Check API key |
| `Nonce not properly bound` | Replay attack or bug | Retry with new nonce |
| `Token expired` | Stale token | Request new attestation |
| `Invalid issuer` | Forged token | Reject attestation |

---

## 7. Security Considerations

### Replay Protection
- Each attestation uses a fresh 32-byte nonce
- Tokens are valid for ~1 hour (Intel default)
- Nonce must be bound in report_data

### Man-in-the-Middle Protection
- TLS encrypts all communication
- Server certificate prevents impersonation
- CA certificate must be pre-deployed to SGX enclave

### Token Forgery Protection
- Intel Trust Authority signs all tokens
- (Research only: signature not cryptographically verified)
- Issuer check provides basic protection

### Denial of Service
- TLS connection timeout: 30 seconds
- Message size limit: 70 MB
- No rate limiting in current implementation
