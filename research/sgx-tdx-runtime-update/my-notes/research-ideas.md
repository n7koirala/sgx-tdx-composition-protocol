# Research Ideas and Novel Contributions

## Core Research Question

> How can multiple SGX controllers securely and scalably manage runtime updates for Confidential VMs (CVMs) while maintaining verifiable state transitions?

---

## Novel Contribution: Differential Attestation

### The Gap in Existing Work

Current attestation answers: **"What is the state?"**

We propose attestation that answers: **"How did the state get here, and who authorized each transition?"**

### Key Insight

In a privacy-preserving proxy model (SGX verifies TDX on behalf of users):
- Users trust SGX code (attested)
- SGX must verify not just TDX current state, but the *transition chain*
- This enables detecting unauthorized commands even after execution

### Formalization

For a CVM $v$, the attestation includes:

$$
\mathcal{A}_v = \langle \text{RTMR}_n, \{e_i\}_{i=0}^{n}, \sigma_{\text{SGX}} \rangle
$$

Where each entry $e_i$ contains:
$$
e_i = \langle \text{seq}_i, h_{i-1}, \text{cmd}_i, \sigma_{\text{ASP}}, \text{ctrl}_i, t_i \rangle
$$

---

## Publication-Worthy Ideas

### Idea 1: Transitive Trust Composition
- First formal protocol for composed attestation (SGX → TDX)
- Cryptographically bind controller actions to CVM state changes

### Idea 2: Threshold-Authorized Updates
- k-of-n authorization before CVM updates
- Policy language for complex authorization rules

### Idea 3: BFT-TEE Orchestration
- Byzantine fault tolerance among SGX controllers
- Attestation-gated consensus membership

### Idea 4: Stateless TEE Controllers
- All state externalized, verified via Merkle proofs
- Horizontal scaling of controllers

---
