import { ethers, network, run } from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
  console.log(`\n🚀 Starting deployment on ${network.name}...`);

  const [deployer] = await ethers.getSigners();
  console.log(`🧠 Deployer: ${deployer.address}`);

  // === Load Merkle Root and metadata ===
  const merkleDataPath = path.resolve(__dirname, "../data/claims_round1.json");
  const { merkleRoot, tokenAddress } = JSON.parse(fs.readFileSync(merkleDataPath, "utf8"));
  if (!merkleRoot || !tokenAddress) throw new Error("❌ Merkle root or tokenAddress missing in claims_round1.json");

  console.log(`🌳 Merkle Root: ${merkleRoot}`);
  console.log(`🪙 Token Address: ${tokenAddress}`);

  // === Deploy Merkle Distributor ===
  const MerkleDistributor = await ethers.getContractFactory("MerkleDistributor");
  const merkleDistributor = await MerkleDistributor.deploy(tokenAddress, merkleRoot);
  await merkleDistributor.deployed();
  console.log(`✅ MerkleDistributor deployed at: ${merkleDistributor.address}`);

  // === Deploy Participation Oracle ===
  const ParticipationOracle = await ethers.getContractFactory("ParticipationOracle");
  const oracle = await ParticipationOracle.deploy();
  await oracle.deployed();
  console.log(`✅ ParticipationOracle deployed at: ${oracle.address}`);

  // === Deploy AirdropManager and initialize ===
  const AirdropManager = await ethers.getContractFactory("AirdropManager");
  const airdropManager = await AirdropManager.deploy(merkleDistributor.address, oracle.address);
  await airdropManager.deployed();
  console.log(`✅ AirdropManager deployed at: ${airdropManager.address}`);

  // === Grant Permissions ===
  await merkleDistributor.setAirdropManager(airdropManager.address);
  console.log("🔐 MerkleDistributor linked to AirdropManager");

  // === Verify Contracts (if supported) ===
  if (network.name !== "hardhat") {
    try {
      await run("verify:verify", {
        address: merkleDistributor.address,
        constructorArguments: [tokenAddress, merkleRoot],
      });
      await run("verify:verify", {
        address: oracle.address,
        constructorArguments: [],
      });
      await run("verify:verify", {
        address: airdropManager.address,
        constructorArguments: [merkleDistributor.address, oracle.address],
      });
    } catch (err) {
      console.warn("⚠️ Verification skipped or failed:", err.message);
    }
  }

  console.log("✅ All contracts deployed and initialized successfully");
}

main().catch((error) => {
  console.error("❌ Deployment failed:", error);
  process.exit(1);
});
