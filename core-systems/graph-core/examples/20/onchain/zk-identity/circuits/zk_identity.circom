// zk-identity/circuits/zk_identity.circom
pragma circom 2.1.6;

include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "circomlib/mux1.circom";
include "circomlib/merkleTree.circom";

template ZkIdentity(nLevels) {
    // Public inputs
    signal input root;                   // Merkle Root
    signal input externalNullifier;     // Prevents double-use of same signal
    signal input signalHash;            // Hash of the message/command

    // Private inputs
    signal input identityNullifier;     // Unique user nullifier
    signal input identityTrapdoor;      // Entropy/secret
    signal input pathElements[nLevels]; // Merkle path
    signal input pathIndices[nLevels];  // Merkle proof positions (0/1)

    // === Derived signals ===

    // Step 1: Compute identityCommitment = Poseidon(identityNullifier, identityTrapdoor)
    component hasher = Poseidon(2);
    hasher.inputs[0] <== identityNullifier;
    hasher.inputs[1] <== identityTrapdoor;
    signal identityCommitment;
    identityCommitment <== hasher.out;

    // Step 2: Verify Merkle Inclusion
    component tree = MerkleTreeVerifier(nLevels);
    for (var i = 0; i < nLevels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    tree.leaf <== identityCommitment;
    signal computedRoot;
    computedRoot <== tree.root;
    computedRoot === root;

    // Step 3: Compute nullifierHash = Poseidon(externalNullifier, identityNullifier)
    component nullHash = Poseidon(2);
    nullHash.inputs[0] <== externalNullifier;
    nullHash.inputs[1] <== identityNullifier;
    signal nullifierHash;
    nullifierHash <== nullHash.out;

    // Step 4: Generate signalHash verification (can be Poseidon or EdDSA-preimage)
    signal _signalHash;
    _signalHash <== signalHash; // Must match expected externally

    // === Outputs (Public signals) ===
    signal output out_root;
    signal output out_nullifierHash;
    signal output out_signalHash;

    out_root <== root;
    out_nullifierHash <== nullifierHash;
    out_signalHash <== signalHash;
}

component main = ZkIdentity(20);
