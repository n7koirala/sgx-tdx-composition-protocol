# TDX Attestation API Reference

## Module: `tdx_remote_attestation.py`

### Class: `TDXAttestor`

Main class for generating TDX attestations.

#### Constructor

```python
TDXAttestor(config_path: str = None)
```

**Parameters:**
- `config_path` (str, optional): Path to Intel Trust Authority config JSON. Defaults to `~/config.json`

**Raises:**
- `RuntimeError`: If TDX device not found or trustauthority-cli not installed
- `RuntimeError`: If config file not found

**Example:**
```python
attestor = TDXAttestor()
# or
attestor = TDXAttestor(config_path="/path/to/config.json")
```

---

#### Method: `get_evidence()`

Generate TDX evidence (quote) without Intel TA verification.

```python
get_evidence(user_data: str = None) -> TDXEvidence
```

**Parameters:**
- `user_data` (str, optional): Base64-encoded user data to include in quote

**Returns:**
- `TDXEvidence`: Object containing the raw quote

**Example:**
```python
evidence = attestor.get_evidence()
print(f"Quote: {evidence.quote[:100]}...")
```

---

#### Method: `get_attestation_token()`

Get verified attestation token from Intel Trust Authority.

```python
get_attestation_token(user_data: str = None, request_id: str = None) -> TDXAttestationToken
```

**Parameters:**
- `user_data` (str, optional): Base64-encoded user data to include
- `request_id` (str, optional): Request ID for tracking

**Returns:**
- `TDXAttestationToken`: Parsed JWT token with TDX claims

**Raises:**
- `RuntimeError`: If token generation fails (network error, rate limit, etc.)

**Example:**
```python
token = attestor.get_attestation_token()
print(f"MRTD: {token.mrtd}")
print(f"Valid: {token.is_valid()}")
```

---

#### Method: `get_binding_data()`

Get TDX attestation with binding data for SGX composition.

```python
get_binding_data(sgx_mrenclave: str = None) -> Tuple[str, TDXAttestationToken]
```

**Parameters:**
- `sgx_mrenclave` (str, optional): SGX enclave measurement to bind to

**Returns:**
- `Tuple[str, TDXAttestationToken]`: (binding_hash, token)

**⚠️ Note:** This makes an additional call to Intel TA, which may hit rate limits.

**Example:**
```python
binding_hash, token = attestor.get_binding_data(
    sgx_mrenclave="05b8e0fe8118ceb23099e92fb9be99d1..."
)
```

---

#### Method: `parse_token()`

Parse a JWT attestation token string.

```python
parse_token(token: str) -> TDXAttestationToken
```

**Parameters:**
- `token` (str): Raw JWT token string

**Returns:**
- `TDXAttestationToken`: Parsed token object

---

#### Method: `verify_token_locally()`

Perform basic local verification of token.

```python
verify_token_locally(token: TDXAttestationToken) -> Tuple[bool, str]
```

**Parameters:**
- `token`: TDXAttestationToken to verify

**Returns:**
- `Tuple[bool, str]`: (is_valid, message)

**Note:** This only checks structure and expiry. Full verification requires checking Intel's signature.

---

### Class: `TDXAttestationToken`

Parsed TDX attestation token (JWT from Intel Trust Authority).

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `raw_token` | str | Full JWT string |
| `header` | Dict | JWT header |
| `payload` | Dict | JWT payload with all claims |
| `signature` | str | JWT signature (base64) |
| `mrtd` | str | TD Measurement |
| `rtmrs` | Dict[str, str] | Runtime measurements (rtmr0-3) |
| `report_data` | str | User-provided report data |
| `tcb_status` | str | TCB status (UpToDate, OutOfDate, etc.) |
| `is_debuggable` | bool | Whether TD is debuggable |

#### Methods

```python
# Get key measurements for SGX binding
measurements = token.get_measurements()
# Returns: {'mrtd': '...', 'report_data': '...', 'rtmr0': '...', ...}

# Check if token is valid (not expired)
if token.is_valid():
    print("Token is valid")

# Convert to dictionary
token_dict = token.to_dict()
```

---

### Class: `TDXEvidence`

Raw TDX evidence structure.

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `quote` | str | Base64-encoded TDX quote |
| `verifier_nonce` | Dict | Nonce from Intel TA |
| `raw_json` | Dict | Full JSON response |
| `timestamp` | str | Generation timestamp |

---

## Module: `tdx_verifier_service.py`

### Class: `TDXTokenVerifier`

Verifies TDX attestation tokens.

#### Methods

```python
verifier = TDXTokenVerifier()

# Add trusted MRTD values for policy enforcement
verifier.add_trusted_mrtd("a5844e88897b70c318bef929ef4dfd6c...")

# Verify a token
verified, result = verifier.verify(token_string)

# Extract binding data
binding_data = verifier.extract_binding_data(token_string)
```

---

### Class: `TDXVerifierService`

Network service for TDX attestation verification.

#### Constructor

```python
TDXVerifierService(port: int = 9999)
```

#### Methods

```python
service = TDXVerifierService(port=9999)
service.run()  # Starts listening for connections
```

---

## CLI Reference

### trustauthority-cli

#### Generate Evidence

```bash
sudo trustauthority-cli evidence --tdx -c ~/config.json [options]
```

Options:
- `--ccel`: Include Confidential Computing Event Logs
- `-u, --user-data <base64>`: Include user data
- `--no-verifier-nonce`: Don't include ITA nonce

#### Generate Token

```bash
sudo trustauthority-cli token --tdx -c ~/config.json [options]
```

Options:
- `-u, --user-data <base64>`: Include user data
- `-r, --request-id <id>`: Request ID for tracking
- `-a, --token-signing-alg <alg>`: PS384 or RS256

---

## Data Structures

### Config File Format

```json
{
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "<your-api-key>"
}
```

### JWT Token Structure

```
Header.Payload.Signature
```

**Header:**
```json
{
  "alg": "PS384",
  "jku": "https://portal.trustauthority.intel.com/certs",
  "kid": "...",
  "typ": "JWT"
}
```

**Payload (key fields):**
```json
{
  "tdx": {
    "tdx_mrtd": "...",
    "tdx_rtmr0": "...",
    "tdx_rtmr1": "...",
    "tdx_rtmr2": "...",
    "tdx_rtmr3": "...",
    "tdx_report_data": "...",
    "attester_tcb_status": "OutOfDate",
    "tdx_is_debuggable": false
  },
  "exp": 1767203604,
  "iat": 1767203304,
  "iss": "https://portal.trustauthority.intel.com"
}
```

### Verification Response

```json
{
  "verified": true,
  "timestamp": "2025-12-31T18:00:00",
  "verdict": "TRUSTED",
  "tdx": {
    "mrtd": "...",
    "tcb_status": "OutOfDate",
    "is_debuggable": false
  },
  "verification_time_ms": 0.5,
  "checks": {
    "jwt_format": true,
    "issuer": true,
    "expiry": true,
    "tdx_claims": true
  }
}
```
