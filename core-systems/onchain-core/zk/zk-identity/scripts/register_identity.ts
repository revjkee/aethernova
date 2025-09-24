import { ethers } from "hardhat";
import fs from "fs";
import path from "path";
import chalk from "chalk";
import { poseidonHash } from "../test/utils"; // или import from dedicated ZK lib
import { ZkIdentity } from "../typechain-types";

const log = (msg: string) => console.log(chalk.green("[REGISTER]"), msg);
const error = (msg: string) => console.error(chalk.red("[ERROR]"), msg);

const OUTPUT_FILE = path.resolve(__dirname, "../identities/local_identities.json");

// === Генерация BigInt из UUID (с обрезкой до 31 байта) ===
function generateBigIntFromUUID(): bigint {
  const hex = crypto.randomUUID().replace(/-/g, "").slice(0, 62);
  return BigInt("0x" + hex);
}

// === Сохранение identity в локальный файл ===
function storeIdentity(identity: any) {
  let existing: any[] = [];

  if (fs.existsSync(OUTPUT_FILE)) {
    const raw = fs.readFileSync(OUTPUT_FILE, "utf8");
    existing = JSON.parse(raw);
  }

  existing.push(identity);
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(existing, null, 2));
  log(`Identity stored in: ${OUTPUT_FILE}`);
}

// === Регистрация нового identity ===
async function main() {
  const [deployer] = await ethers.getSigners();
  log(`Using deployer: ${deployer.address}`);

  const zkIdentity = await ethers.getContract<ZkIdentity>("ZkIdentity");

  const trapdoor = generateBigIntFromUUID();
  const nullifier = generateBigIntFromUUID();
  const commitment = poseidonHash([trapdoor, nullifier]);

  log(`Generated Identity:
    Trapdoor: ${trapdoor}
    Nullifier: ${nullifier}
    Commitment: ${commitment}
  `);

  // Отправка на контракт
  const tx = await zkIdentity.register(commitment);
  await tx.wait();
  log("Identity successfully registered on-chain.");

  // Сохраняем локально
  storeIdentity({
    trapdoor: trapdoor.toString(),
    nullifier: nullifier.toString(),
    commitment: commitment.toString(),
    timestamp: new Date().toISOString()
  });
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    error(err.message);
    process.exit(1);
  });
