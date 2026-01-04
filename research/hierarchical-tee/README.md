# Hierarchical TEE Architecture for Cloud Attestation
## Solving Platform Linkability with SGX + TDX Composition

### Architecture Overview
- **Inner Layer (SGX)**: Application-level confidential computing
- **Outer Layer (TDX)**: VM-level isolation and memory encryption  
- **Composition Protocol**: Linkability prevention mechanism


### Research Goals
1. Enable hierarchical attestation: End users → SGX enclave → TDX VM 
2. Prevent platform linkability across attestations
3. Maintain security guarantees of both TEE layers
4. Minimize performance overhead

### Remote Attestation Status
- TDX: ✓ Completed on Google Cloud Machine (see tdx-layer/attestation/)
- SGX: ✓ Completed using Gramine (see sgx_machine_code/gramine_attestation/)

### Current Development Status
- [x] TDX environment configured and verified
- [x] SGX environment setup (bare metal)
- [x] Attestation verification logic (on individual platforms)
- [ ] Composition protocol implementation - TO DO
- [ ] Performance benchmarking - TO DO
