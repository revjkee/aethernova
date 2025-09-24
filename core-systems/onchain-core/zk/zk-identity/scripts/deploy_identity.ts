import { ethers } from "hardhat";
import fs from "fs";
import path from "path";
import chalk from "chalk";

// === Логи ===
const log = (msg: string) => console.log(chalk.blue("[DEPLOY]"), msg);
const error = (msg: string) => console.error(chalk.red("[ERROR]"), msg);

// === Конфигурация сети ===
const OUTPUT_DIR = path.resolve(__dirname, "../deployments");
const NETWORK = process.env.HARDHAT_NETWORK || "localhost";

// === Деплой одного контракта ===
async function deployContract(name: string, ...args: any[]) {
  const Factory = await ethers.getContractFactory(name);
  const contract = await Factory.deploy(...args);
  await contract.deployed();
  log(`${name} deployed at ${contract.address}`);
  return contract;
}

// === Главный деплой ===
async function main() {
  log(`Deploying ZkIdentity stack to: ${NETWORK}`);

  const [deployer] = await ethers.getSigners();
  log(`Using deployer: ${deployer.address}`);

  // === Шаг 1: Верификаторы ===
  const grothVerifier = await deployContract("VerifierGroth16");
  const plonkVerifier = await deployContract("VerifierPlonk");

  // === Шаг 2: ZkIdentity — с верификаторами ===
  const zkIdentity = await deployContract("ZkIdentity", grothVerifier.address, plonkVerifier.address);

  // === Сохранение адресов ===
  const result = {
    network: NETWORK,
    timestamp: new Date().toISOString(),
    contracts: {
      ZkIdentity: zkIdentity.address,
      VerifierGroth16: grothVerifier.address,
      VerifierPlonk: plonkVerifier.address
    }
  };

  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR);
  }

  fs.writeFileSync(path.join(OUTPUT_DIR, `${NETWORK}.json`), JSON.stringify(result, null, 2));
  log(`Deployment saved to deployments/${NETWORK}.json`);
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    error(err.message);
    process.exit(1);
  });
