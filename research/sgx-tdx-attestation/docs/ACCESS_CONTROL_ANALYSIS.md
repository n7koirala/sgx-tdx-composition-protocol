# Access Control Analysis: SGX-Only TDX VM Access

## Current State vs. Required State

| Feature | Status | Implementation |
|---------|--------|----------------|
| RA restricted to SGX only | ✅ Implemented | `--require-client-cert` flag on TDX server |
| Client authentication | ✅ Implemented | mTLS with SGX client certificate |
| SSH through SGX only | ⚠️ Via firewall | GCP firewall rule restricts to SGX IP |
| IP whitelist | ⚠️ Optional | GCP firewall provides this layer |

---

## Issue 1: Remote Attestation Open to Anyone

### Current Vulnerable Code

[tdx_attestation_server.py#L230-234](file:///home/nkoirala/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/tdx-server/tdx_attestation_server.py#L230-234):
```python
server_socket.bind(('0.0.0.0', self.port))  # Accepts connections from ANY IP
server_socket.listen(5)
```

[protocol.py#L314-329](file:///home/nkoirala/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/common/protocol.py#L314-329):
```python
def create_tls_context_server(cert_file: str, key_file: str):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    # ⚠️ NO CLIENT CERTIFICATE VERIFICATION
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
```

### Solution: Mutual TLS (mTLS) with SGX Client Certificate

**Concept**: Only clients presenting a valid certificate signed by our CA can connect. The SGX enclave will have the only valid client certificate.

#### Step 1: Generate Client Certificate for SGX Enclave

Add to `certs/generate_certs.sh`:
```bash
# Generate SGX client certificate
echo "[5/6] Generating SGX client private key..."
openssl genrsa -out sgx_client.key 2048

echo "[6/6] Generating SGX client certificate..."
openssl req -new -key sgx_client.key -out sgx_client.csr \
    -subj "/C=US/ST=Research/L=Lab/O=Hierarchical-TEE/OU=SGX-Controller/CN=sgx-controller"

openssl x509 -req -in sgx_client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out sgx_client.crt -days $VALIDITY

rm -f sgx_client.csr
chmod 600 sgx_client.key
chmod 644 sgx_client.crt

echo "  sgx_client.crt - SGX client certificate"
echo "  sgx_client.key - SGX client private key (bundle into enclave)"
```

#### Step 2: Update TDX Server for mTLS

Replace `create_tls_context_server` in `protocol.py`:
```python
def create_tls_context_server(cert_file: str, key_file: str, 
                               ca_cert_file: str = None,
                               require_client_cert: bool = False):
    """
    Create TLS context for server with optional client auth.
    """
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # CRITICAL: Require client certificate
    if require_client_cert and ca_cert_file:
        context.load_verify_locations(ca_cert_file)
        context.verify_mode = ssl.CERT_REQUIRED  # Client MUST present valid cert
    
    return context
```

#### Step 3: Update SGX Client to Present Certificate

Update `create_tls_context_client` in `protocol.py`:
```python
def create_tls_context_client(ca_cert_file: str = None, 
                               client_cert_file: str = None,
                               client_key_file: str = None,
                               verify: bool = True):
    """
    Create TLS context for SGX client with mutual authentication.
    """
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # Verify server certificate
    if verify and ca_cert_file:
        context.load_verify_locations(ca_cert_file)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    
    # Present client certificate (for mTLS)
    if client_cert_file and client_key_file:
        context.load_cert_chain(client_cert_file, client_key_file)
    
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
```

#### Step 4: Optional - Add IP Whitelist as Defense in Depth

```python
class TDXAttestationServer:
    def __init__(self, ..., allowed_ips: list = None):
        self.allowed_ips = allowed_ips or []
    
    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple):
        # Check IP whitelist
        if self.allowed_ips and addr[0] not in self.allowed_ips:
            print(f"[BLOCKED] Connection from unauthorized IP: {addr[0]}")
            client_socket.close()
            return
        
        # ... rest of handler
```

---

## Issue 2: SSH Access Through SGX Only

### Approaches

#### Option A: SSH Proxy in SGX Enclave (Recommended)

The SGX enclave acts as an SSH jump host/bastion:

```
┌────────────────────────────────────────────────────────────────┐
│  SSH Proxy Architecture                                        │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [Admin]                                                        │
│     │                                                           │
│     │ 1. Connect to SGX enclave (authenticated)                 │
│     ▼                                                           │
│  [SGX Enclave]                                                  │
│     │                                                           │
│     │ • Verify admin credentials                                │
│     │ • Check authorization policy                              │
│     │ • Log all commands                                        │
│     │                                                           │
│     │ 2. Forward SSH to TDX (internal only)                     │
│     ▼                                                           │
│  [TDX VM]                                                       │
│     • SSH only listens on internal interface                    │
│     • Only accepts connections from SGX                         │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

**Implementation Steps**:

1. **Configure TDX SSH to internal only**:
   ```bash
   # On TDX VM: /etc/ssh/sshd_config
   ListenAddress 10.0.0.2  # Internal interface only
   # OR: bind to a specific private network
   ```

2. **Add SSH proxy to SGX enclave**:
   ```python
   # New module: sgx-verifier/ssh_proxy.py
   import paramiko
   
   class SGXSSHProxy:
       def __init__(self, tdx_host: str, tdx_ssh_port: int = 22):
           self.tdx_host = tdx_host
           self.tdx_ssh_port = tdx_ssh_port
           self.authorized_keys = {}  # Load from sealed storage
       
       def proxy_session(self, admin_auth_token: str):
           """Proxy an authenticated SSH session to TDX"""
           if not self.verify_admin(admin_auth_token):
               raise PermissionError("Not authorized")
           
           # Create SSH connection to TDX
           client = paramiko.SSHClient()
           client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
           client.connect(
               self.tdx_host, 
               port=self.tdx_ssh_port,
               key_filename='/sealed/tdx_admin_key'  # Key sealed in enclave
           )
           return client
   ```

3. **Network isolation (iptables on TDX)**:
   ```bash
   # Block SSH from everywhere except SGX IP
   iptables -A INPUT -p tcp --dport 22 -s <SGX_IP> -j ACCEPT
   iptables -A INPUT -p tcp --dport 22 -j DROP
   ```

#### Option B: SSH Jump Host Configuration (Simpler)

Use SSH's ProxyJump feature with SGX as the jump host:

```bash
# Admin's ~/.ssh/config
Host tdx-vm
    HostName <TDX_INTERNAL_IP>
    User admin
    ProxyJump sgx-controller
    
Host sgx-controller
    HostName <SGX_PUBLIC_IP>
    User sgx-admin
    IdentityFile ~/.ssh/sgx_key
```

**Limitation**: Requires SSH server in SGX enclave (heavier footprint).

#### Option C: No SSH at All (Most Secure)

If the goal is maximum security:
1. **No SSH on TDX VM** - disable completely
2. **Pre-bake all packages** in the VM image
3. **Changes require new image + re-attestation**

```bash
# On TDX VM
systemctl disable ssh
systemctl stop ssh
```

---

## Recommended Implementation Priority

### Phase 1: Immediate (mTLS for Attestation)

1. Generate SGX client certificate
2. Update `create_tls_context_server` for mTLS
3. Update SGX verifier to present client cert
4. Add IP whitelist as backup

### Phase 2: Network Isolation

1. Configure TDX SSH to internal interface only
2. Add iptables rules on TDX VM
3. Test connectivity only from SGX

### Phase 3: SSH Proxy (If Runtime Admin Needed)

1. Implement SSH proxy module in SGX enclave
2. Seal admin credentials in enclave storage
3. Add command logging/auditing

---

## Security Properties After Implementation

| Property | Status |
|----------|--------|
| RA only from SGX | ✅ mTLS + IP whitelist |
| SSH only from SGX | ✅ Network isolation + iptables |
| Admin auth in SGX | ✅ Credentials sealed in enclave |
| Audit logging | ✅ All admin commands logged |
| No external network access | ✅ Firewall configuration |
