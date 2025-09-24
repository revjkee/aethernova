// hr_ai/governance/zk_voting/proofs/semaphore_vote.circom
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/semaphore/circuits/MerkleTreeVerifier.circom";

template SemaphoreVote(depth) {
    // Inputs
    signal input identity_nullifier;
    signal input identity_trapdoor;
    signal input merkle_path_elements[depth];
    signal input merkle_path_index[depth];
    signal input external_nullifier;
    signal input signal_hash;

    // Public inputs
    signal input merkle_root;
    signal input nullifier_hash;

    // Internal variables
    signal private_identity_commitment;
    signal computed_root;
    signal computed_nullifier;

    // Step 1: Generate identity commitment
    component hash_identity = Poseidon(2);
    hash_identity.inputs[0] <== identity_nullifier;
    hash_identity.inputs[1] <== identity_trapdoor;
    private_identity_commitment <== hash_identity.out;

    // Step 2: Verify Merkle proof
    component merkle = MerkleTreeVerifier(depth);
    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== merkle_path_elements[i];
        merkle.pathIndex[i] <== merkle_path_index[i];
    }
    merkle.leaf <== private_identity_commitment;
    computed_root <== merkle.root;

    // Ensure root matches public Merkle root
    computed_root === merkle_root;

    // Step 3: Generate nullifier hash
    component hash_nullifier = Poseidon(2);
    hash_nullifier.inputs[0] <== identity_nullifier;
    hash_nullifier.inputs[1] <== external_nullifier;
    computed_nullifier <== hash_nullifier.out;

    // Check nullifier matches public input
    computed_nullifier === nullifier_hash;

    // Step 4: Bind signal to proof (optional anti-replay)
    // This step assumes `signal_hash` is already Poseidon-hashed off-chain
    // but can be made part of the circuit if necessary
}

component main = SemaphoreVote(20);
