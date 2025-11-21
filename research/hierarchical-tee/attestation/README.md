# Hierarchical TEE Attestation Framework

## Architecture
- **Layer 1 (Inner)**: SGX Enclaves - Application-level isolation
- **Layer 2 (Outer)**: TDX VMs - VM-level isolation
- **Linkability Prevention**: Your novel protocol

## Evidence Collection
1. SGX Quote generation (from enclave)
2. TDX Report generation (from VM)
3. Hierarchical composition with unlinkability

## Next Steps
1. Implement SGX enclave for inner layer
2. Collect TDX evidence for outer layer
3. Build composition protocol
4. Implement verification logic
