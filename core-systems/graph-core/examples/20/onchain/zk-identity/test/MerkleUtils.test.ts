import { expect } from "chai";
import { PoseidonHasher } from "../utils/hasher";
import { MerkleTree } from "../utils/merkleTree";
import { ZERO_VALUE, TREE_DEPTH } from "../circuits/circuit_constants.json";
import { generateIdentityCommitment } from "../utils";
import { BigNumberish } from "ethers";

describe("MerkleUtils — Industrial Grade Test Suite", () => {
  let tree: MerkleTree;
  let hasher: PoseidonHasher;
  let testCommitments: BigNumberish[] = [];

  beforeEach(() => {
    hasher = new PoseidonHasher();
    tree = new MerkleTree(TREE_DEPTH, ZERO_VALUE, hasher);
    testCommitments = Array.from({ length: 4 }, () => generateIdentityCommitment());
  });

  it("should initialize tree with correct root", () => {
    const root = tree.getRoot();
    expect(root).to.be.a("bigint");
    expect(root).to.equal(tree.root);
  });

  it("should insert commitments and update root", () => {
    const initialRoot = tree.getRoot();
    testCommitments.forEach((commitment) => {
      tree.insert(commitment);
    });
    const updatedRoot = tree.getRoot();
    expect(updatedRoot).to.not.equal(initialRoot);
    expect(tree.index).to.equal(testCommitments.length);
  });

  it("should generate valid Merkle path", () => {
    tree.insert(testCommitments[0]);
    const { pathElements, pathIndices } = tree.generateMerkleProof(0);
    expect(pathElements).to.have.lengthOf(TREE_DEPTH);
    expect(pathIndices).to.have.lengthOf(TREE_DEPTH);
  });

  it("should reject invalid index for proof", () => {
    expect(() => tree.generateMerkleProof(99)).to.throw("Leaf index out of range");
  });

  it("should support full tree insertion", () => {
    for (let i = 0; i < 2 ** TREE_DEPTH; i++) {
      tree.insert(generateIdentityCommitment());
    }
    expect(() => tree.insert(generateIdentityCommitment())).to.throw("Merkle tree is full");
  });

  it("should verify path consistency for each leaf", () => {
    for (let i = 0; i < 4; i++) {
      tree.insert(testCommitments[i]);
      const { pathElements, pathIndices } = tree.generateMerkleProof(i);
      const leaf = testCommitments[i];
      const root = tree.root;

      const computed = hasher.hashPath(pathElements, pathIndices, leaf);
      expect(computed).to.equal(root);
    }
  });

  it("should match root recomputed externally", () => {
    testCommitments.forEach((c) => tree.insert(c));
    const snapshot = tree.clone();
    const recomputedRoot = snapshot.computeRootFromLeaves();
    expect(recomputedRoot).to.equal(tree.root);
  });

  it("should produce identical roots on identical insertions", () => {
    const treeA = new MerkleTree(TREE_DEPTH, ZERO_VALUE, hasher);
    const treeB = new MerkleTree(TREE_DEPTH, ZERO_VALUE, hasher);
    testCommitments.forEach((c) => {
      treeA.insert(c);
      treeB.insert(c);
    });
    expect(treeA.getRoot()).to.equal(treeB.getRoot());
  });
});
