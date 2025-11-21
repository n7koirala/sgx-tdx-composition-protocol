# Hierarchical TEE Architecture for Cloud Attestation
## Solving Platform Linkability with SGX + TDX Composition

### Architecture Overview
- **Inner Layer (SGX)**: Application-level confidential computing
- **Outer Layer (TDX)**: VM-level isolation and memory encryption  
- **Composition Protocol**: Linkability prevention mechanism

### Current Status
- [x] TDX environment configured and verified
- [ ] SGX environment setup (bare metal)
- [ ] Composition protocol implementation
- [ ] Attestation verification logic
- [ ] Performance benchmarking

### Research Goals
1. Enable hierarchical attestation: SGX enclave → TDX VM → Cloud verifier
2. Prevent platform linkability across attestations
3. Maintain security guarantees of both TEE layers
4. Minimize performance overhead

### Evidence Collection Status
- TDX Evidence: ✓ Collected (see tdx-layer/evidence/)
- SGX Evidence: Pending bare metal setup
