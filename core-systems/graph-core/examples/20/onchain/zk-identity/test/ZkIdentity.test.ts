import { expect } from "chai";
import { ethers } from "hardhat";
import { ZkIdentity, VerifierGroth16, VerifierPlonk } from "../typechain-types";
import { generateIdentityCommitment, createProof } from "./utils";
import { poseidonHash } from "./utils";
import { deployContracts } from "./Fixtures";

describe("ZkIdentity Full Flow", function () {
  let zkIdentity: ZkIdentity;
  let grothVerifier: VerifierGroth16;
  let plonkVerifier: VerifierPlonk;

  let identityCommitment: bigint;
  let nullifierHash: bigint;
  let merkleRoot: bigint;
  let proofGroth: any;
  let proofPlonk: any;

  before(async () => {
    // Deploy contracts (Groth16 + Plonk)
    ({ zkIdentity, grothVerifier, plonkVerifier } = await deployContracts());

    // Simulate identity registration
    const trapdoor = BigInt("0x" + crypto.randomUUID().replace(/-/g, "").slice(0, 62));
    const nullifier = BigInt("0x" + crypto.randomUUID().replace(/-/g, "").slice(0, 62));
    identityCommitment = poseidonHash([trapdoor, nullifier]);

    // Register onchain
    await zkIdentity.register(identityCommitment);

    // Update Merkle root
    merkleRoot = await zkIdentity.getRoot();

    // Generate proof for Groth16
    proofGroth = await createProof("groth16", trapdoor, nullifier, merkleRoot);

    // Generate proof for Plonk
    proofPlonk = await createProof("plonk", trapdoor, nullifier, merkleRoot);

    // Save nullifierHash for uniqueness check
    nullifierHash = poseidonHash([nullifier]);
  });

  it("should verify Groth16 proof and mark nullifier used", async () => {
    const tx = await zkIdentity.verifyAndExecute(proofGroth.proof, proofGroth.publicSignals, "groth16");
    await tx.wait();

    const used = await zkIdentity.isNullifierUsed(nullifierHash);
    expect(used).to.equal(true);
  });

  it("should reject reused Groth16 proof (nullifier already used)", async () => {
    await expect(
      zkIdentity.verifyAndExecute(proofGroth.proof, proofGroth.publicSignals, "groth16")
    ).to.be.revertedWith("Nullifier already used");
  });

  it("should verify Plonk proof for fresh identity", async () => {
    const newTrapdoor = BigInt("0x" + crypto.randomUUID().replace(/-/g, "").slice(0, 62));
    const newNullifier = BigInt("0x" + crypto.randomUUID().replace(/-/g, "").slice(0, 62));
    const newCommitment = poseidonHash([newTrapdoor, newNullifier]);

    await zkIdentity.register(newCommitment);
    const newRoot = await zkIdentity.getRoot();
    const newProof = await createProof("plonk", newTrapdoor, newNullifier, newRoot);

    const tx = await zkIdentity.verifyAndExecute(newProof.proof, newProof.publicSignals, "plonk");
    await tx.wait();
  });

  it("should fail for invalid proof data", async () => {
    const invalidSignals = proofGroth.publicSignals.slice();
    invalidSignals[1] = "123456789"; // corrupt signal

    await expect(
      zkIdentity.verifyAndExecute(proofGroth.proof, invalidSignals, "groth16")
    ).to.be.revertedWith("Invalid proof");
  });

  it("should reject unknown verifier type", async () => {
    await expect(
      zkIdentity.verifyAndExecute(proofGroth.proof, proofGroth.publicSignals, "halo2")
    ).to.be.revertedWith("Verifier not supported");
  });
});
