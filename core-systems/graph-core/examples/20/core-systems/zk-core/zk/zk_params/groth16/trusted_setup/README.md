# Trusted Setup for Groth16 zk-SNARKs

## Overview

This directory contains all files and documentation related to the trusted setup phase required for the Groth16 zero-knowledge succinct non-interactive argument of knowledge (zk-SNARK) protocol.

The trusted setup generates public parameters (common reference string) that are essential for both proving and verifying zk-proofs securely. The process must be performed securely and transparently to prevent any malicious party from creating fraudulent proofs.

## Setup Phases

1. **Powers of Tau Ceremony**
   - Produces a universal, multi-purpose parameter file (`powers_of_tau.ptau`).
   - Can be reused across different circuits on the same elliptic curve.
   - Requires multiple independent contributors for security (to avoid toxic waste).
   - Powers of Tau is curve-specific.

2. **Circuit-specific Setup**
   - Utilizes the universal Powers of Tau output to generate circuit-specific proving and verifying keys (`final_zkey.zkey`).
   - Includes contribution phases to add entropy, further enhancing security.
   - Final parameters include proving and verifying keys.

## File Descriptions

- `powers_of_tau.ptau`  
  Universal parameters generated via Powers of Tau ceremony.

- `final_zkey.zkey`  
  Circuit-specific final proving key after all contributions.

- `verifier.sol`  
  Solidity smart contract for on-chain verification of zk-proofs generated with these parameters.

## Security Considerations

- **Transparency:** Each contribution must be publicly auditable.
- **Toxic Waste:** Proper destruction of secret entropy is crucial to avoid trusted setup compromise.
- **Multi-party Computation:** Recommended to use MPC ceremonies involving multiple independent parties.
- **Verification:** All participants should verify intermediate and final parameters for integrity.

## Usage Instructions

1. **Perform Powers of Tau Ceremony**  
   Follow established MPC protocols and document contributions.

2. **Generate Circuit-specific Keys**  
   Use zk-SNARK toolkits (e.g., `snarkjs`, `circom`) to produce `.zkey` files from `powers_of_tau.ptau`.

3. **Deploy Verifier Contract**  
   Use `verifier.sol` for on-chain proof verification, ensuring compatibility with generated parameters.

4. **Audit and Verify**  
   Regularly audit all setup phases and verify contract compatibility.

## References

- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [Powers of Tau MPC](https://github.com/iden3/powersoftau)
- [SnarkJS Documentation](https://github.com/iden3/snarkjs)

## Contact

For questions or contribution requests, please contact the zk-team@yourdomain.com.

---

_Last updated: 2025-07-17_
