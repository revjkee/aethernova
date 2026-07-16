import { ethers } from "ethers";
import fs from "fs";
import path from "path";
import { MerkleTree } from "merkletreejs";
import { keccak256 } from "ethers/lib/utils";

// === Конфигурация сети и провайдера ===
const provider = new ethers.providers.JsonRpcProvider("http://localhost:8545"); // или mainnet fork
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY || "", provider);
const airdropManagerAddress = "0xYourAirdropManagerAddressHere"; // замените

// === ABI (только необходимые методы) ===
const ABI = [
  "function isClaimed(uint256 index) view returns (bool)",
  "function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof)"
];
const contract = new ethers.Contract(airdropManagerAddress, ABI, wallet);

// === Загрузка данных ===
const dataPath = path.resolve(__dirname, "../data/claims_round1.json");
const { claims, merkleRoot } = JSON.parse(fs.readFileSync(dataPath, "utf8"));

// === Подготовка и тест каждой заявки ===
const runSimulations = async () => {
  const errors: string[] = [];
  const successes: string[] = [];

  for (const [address, claimData] of Object.entries(claims)) {
    const { index, amount, proof } = claimData;

    try {
      const isAlreadyClaimed = await contract.isClaimed(index);
      if (isAlreadyClaimed) {
        errors.push(`${address} already claimed`);
        continue;
      }

      // Simulate claim (estimateGas as dry-run)
      const tx = await contract.callStatic.claim(index, address, amount, proof);
      successes.push(`${address} passed simulation`);
    } catch (err) {
      errors.push(`${address} failed: ${(err as Error).message}`);
    }
  }

  console.log("✅ Simulation complete");
  console.log("🟩 Successes:", successes.length);
  console.log("🟥 Failures:", errors.length);

  if (errors.length > 0) {
    const errorLogPath = path.resolve(__dirname, "../logs/claim_errors.log");
    fs.mkdirSync(path.dirname(errorLogPath), { recursive: true });
    fs.writeFileSync(errorLogPath, errors.join("\n"), "utf8");
    console.log(`❗ Ошибки записаны в: ${errorLogPath}`);
  }
};

runSimulations().catch((e) => {
  console.error("💥 Simulation failed:", e);
  process.exit(1);
});
