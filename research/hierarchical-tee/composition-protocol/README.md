# Attestation Composition Protocol

## Protocol Flow
1. **SGX Layer**: Generate enclave quote with application measurements
2. **TDX Layer**: Generate TD report with VM measurements  
3. **Composition**: Bind SGX quote to TDX report with unlinkability
4. **Verification**: Hierarchical verification with privacy preservation

## Linkability Prevention Mechanism
[Your novel contribution here]

## Implementation Status
- [ ] SGX quote handling
- [x] TDX report generation
- [ ] Composition algorithm
- [ ] Anonymization/unlinkability mechanism
- [ ] Verification logic
