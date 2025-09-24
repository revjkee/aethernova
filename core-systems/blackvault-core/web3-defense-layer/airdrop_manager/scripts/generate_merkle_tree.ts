import fs from "fs";
import path from "path";
import { keccak256 } from "ethers/lib/utils";
import { MerkleTree } from "merkletreejs";

// === Types ===
type ClaimEntry = {
  address: string;
  amount: string; // in wei
};

// === Load Eligible Addresses ===
const inputPath = path.resolve(__dirname, "../data/eligible_snapshot.json");
if (!fs.existsSync(inputPath)) throw new Error("❌ eligible_snapshot.json not found.");

const eligible: ClaimEntry[] = JSON.parse(fs.readFileSync(inputPath, "utf8"));
if (!Array.isArray(eligible) || eligible.length === 0) throw new Error("❌ No eligible entries loaded.");

// === Hash Leaf Generator ===
const hashLeaf = ({ address, amount }: ClaimEntry): Buffer => {
  return Buffer.from(keccak256(Buffer.concat([
    Buffer.from(address.slice(2).padStart(40, "0"), "hex"),
    Buffer.from(BigInt(amount).toString(16).padStart(64, "0"), "hex")
  ])).slice(2), "hex");
};

// === Merkle Tree Construction ===
const leaves = eligible.map(hashLeaf);
const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });
const merkleRoot = tree.getHexRoot();

console.log("✅ Merkle Root:", merkleRoot);

// === Index Claims by Address ===
const claims = eligible.reduce((acc, entry, idx) => {
  const leaf = hashLeaf(entry);
  const proof = tree.getHexProof(leaf);

  acc[entry.address.toLowerCase()] = {
    index: idx,
    amount: entry.amount,
    proof,
  };

  return acc;
}, {} as Record<string, { index: number; amount: string; proof: string[] }>);

// === Export Output ===
const outputPath = path.resolve(__dirname, "../data/claims_round1.json");
fs.writeFileSync(outputPath, JSON.stringify({ merkleRoot, tokenAddress: "", claims }, null, 2));

console.log(`🧾 claims_round1.json generated with ${Object.keys(claims).length} entries`);
