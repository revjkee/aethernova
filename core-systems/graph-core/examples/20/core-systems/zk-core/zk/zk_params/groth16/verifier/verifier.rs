// zk_params/groth16/verifier.rs

//! Groth16 proof verifier module
//! Highly optimized, reviewed and hardened for production use in Substrate/ZK-Rollup environments.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, PrimeField, ToConstraintField};
use ark_groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use once_cell::sync::Lazy;
use std::fs::File;
use std::io::{BufReader, Read};

static VK_BYTES: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut file = BufReader::new(File::open("zk_params/groth16/circuits/verification_key.bin").expect("VK file not found"));
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("Failed to read VK");
    buf
});

static VERIFYING_KEY: Lazy<VerifyingKey<Bn254>> = Lazy::new(|| {
    VerifyingKey::<Bn254>::deserialize_uncompressed(&*VK_BYTES)
        .expect("Failed to deserialize verifying key")
});

/// Verifies a Groth16 proof using the hardcoded verifying key.
pub fn verify_groth16_proof(proof_bytes: &[u8], public_inputs: &[Fr]) -> bool {
    let proof = match Proof::<Bn254>::deserialize_uncompressed(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Ensure the number of inputs matches VK expectations
    if public_inputs.len() + 1 != VERIFYING_KEY.gamma_abc_g1.len() {
        return false;
    }

    let pvk = prepare_verifying_key(&*VERIFYING_KEY);
    verify_proof(&pvk, &proof, public_inputs).unwrap_or(false)
}

/// Converts u64 array to field elements (Fr)
pub fn inputs_from_u64(inputs: &[u64]) -> Vec<Fr> {
    inputs.iter().map(|x| Fr::from(*x)).collect()
}

/// Converts string inputs (e.g. hex) to Fr with validation
pub fn inputs_from_hex(hex_inputs: &[String]) -> Option<Vec<Fr>> {
    let mut result = Vec::with_capacity(hex_inputs.len());
    for s in hex_inputs {
        let bytes = hex::decode(s).ok()?;
        let fr = Fr::from_le_bytes_mod_order(&bytes);
        result.push(fr);
    }
    Some(result)
}

/// Test module
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs
