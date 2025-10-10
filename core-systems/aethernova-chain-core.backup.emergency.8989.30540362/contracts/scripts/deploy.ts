/* eslint-disable no-console */
/**
 * Industrial-grade deploy script for Hardhat + ethers (v6-compatible).
 *
 * Features:
 * - Args from ENV or JSON file.
 * - EIP-1559 fee overrides via ENV.
 * - Idempotent: optionally skip if already deployed.
 * - Waits for N confirmations.
 * - Optional Etherscan verification.
 * - Persists deployment info under deployments/<network>.json
 */

import hre from "hardhat";
import { ethers } from "hardhat";
import fs from "node:fs/promises";
import path from "node:path";

type Address = string;

type DeployRecord = {
  contract: string;
  address: Address;
  txHash: string;
  blockNumber: number;
  deployer: Address;
  network: string;
  chainId: number;
  args: unknown[];
  timestamp: string;
  verification?: {
    verified: boolean;
    runAt?: string;
    error?: string;
  };
};

type DeploymentFile = {
  network: string;
  chainId: number;
  records: DeployRecord[];
};

type EnvCfg = {
  CONTRACT: string;               // required
  ARGS?: string;                  // JSON array string
  ARGS_FILE?: string;             // path to JSON array
  CONFIRMATIONS?: string;         // integer
  SKIP_IF_DEPLOYED?: string;      // "true"/"false"
  MAX_FEE_PER_GAS_GWEI?: string;  // e.g. "50"
  MAX_PRIORITY_FEE_PER_GAS_GWEI?: string; // e.g. "2"
  NONCE?: string;                 // optional explicit nonce
  GAS_LIMIT?: string;             // optional gas limit
  BROADCAST?: string;             // "true" to actually send tx (vs. dry-run not supported here)
  TAG?: string;                   // logical tag/name variant
};

function getEnv(): EnvCfg {
  return {
    CONTRACT: process.env.CONTRACT || "",
    ARGS: process.env.ARGS,
    ARGS_FILE: process.env.ARGS_FILE,
    CONFIRMATIONS: process.env.CONFIRMATIONS,
    SKIP_IF_DEPLOYED: process.env.SKIP_IF_DEPLOYED,
    MAX_FEE_PER_GAS_GWEI: process.env.MAX_FEE_PER_GAS_GWEI,
    MAX_PRIORITY_FEE_PER_GAS_GWEI: process.env.MAX_PRIORITY_FEE_PER_GAS_GWEI,
    NONCE: process.env.NONCE,
    GAS_LIMIT: process.env.GAS_LIMIT,
    BROADCAST: process.env.BROADCAST,
    TAG: process.env.TAG,
  };
}

function parseBool(v: string | undefined, dflt = false): boolean {
  if (v === undefined) return dflt;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

function parseIntSafe(v: string | undefined, dflt: number): number {
  if (!v) return dflt;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : dflt;
}

function gweiToWeiBigInt(v?: string): bigint | undefined {
  if (!v) return undefined;
  if (!/^\d+(\.\d+)?$/.test(v)) throw new Error(`Invalid gwei value: ${v}`);
  // Support integer or decimal gwei
  const [intPart, fracPart = ""] = v.split(".");
  const fracPadded = (fracPart + "0".repeat(9)).slice(0, 9); // 9 decimals in gwei->wei
  const weiStr = `${intPart}${fracPadded}`;
  return BigInt(weiStr);
}

async function loadArgs(env: EnvCfg): Promise<unknown[]> {
  if (env.ARGS && env.ARGS.trim().length > 0) {
    const parsed = JSON.parse(env.ARGS);
    if (!Array.isArray(parsed)) throw new Error("ARGS must be a JSON array");
    return parsed;
  }
  if (env.ARGS_FILE) {
    const p = path.resolve(env.ARGS_FILE);
    const buf = await fs.readFile(p, "utf8");
    const parsed = JSON.parse(buf);
    if (!Array.isArray(parsed)) throw new Error("ARGS_FILE must contain a JSON array");
    return parsed;
  }
  return [];
}

async function ensureDir(p: string) {
  await fs.mkdir(p, { recursive: true });
}

async function loadDeploymentFile(filePath: string, network: string, chainId: number): Promise<DeploymentFile> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as DeploymentFile;
    if (!parsed.records) parsed.records = [];
    return parsed;
  } catch {
    return { network, chainId, records: [] };
  }
}

async function saveDeploymentFile(filePath: string, data: DeploymentFile): Promise<void> {
  const text = JSON.stringify(data, null, 2);
  await fs.writeFile(filePath, `${text}\n`, "utf8");
}

function findExisting(df: DeploymentFile, contract: string, tag?: string): DeployRecord | undefined {
  const key = tag ? `${contract}:${tag}` : contract;
  return df.records.find(r => r.contract === key);
}

async function tryVerify(address: string, constructorArguments: unknown[]): Promise<{ ok: boolean; error?: string }> {
  try {
    // Requires @nomicfoundation/hardhat-verify or similar plugin configured
    await hre.run("verify:verify", { address, constructorArguments });
    return { ok: true };
  } catch (e: any) {
    const msg = String(e?.message || e);
    // Common benign cases include "Already Verified"
    const ok = /Already Verified|Contract source code already verified/i.test(msg);
    return { ok, error: ok ? undefined : msg };
  }
}

async function main() {
  const env = getEnv();
  if (!env.CONTRACT) {
    throw new Error("CONTRACT env var is required (contract name as in artifacts).");
  }
  const args = await loadArgs(env);
  const confirmations = parseIntSafe(env.CONFIRMATIONS, 2);
  const skipIfDeployed = parseBool(env.SKIP_IF_DEPLOYED, false);
  const tagSuffix = env.TAG ? `:${env.TAG}` : "";

  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const netName = hre.network.name;

  console.log(`Network: ${netName} (chainId=${chainId})`);
  console.log(`Deployer: ${await deployer.getAddress()}`);
  console.log(`Contract: ${env.CONTRACT}${tagSuffix}`);
  console.log(`Args: ${JSON.stringify(args)}`);
  console.log(`Confirmations: ${confirmations}`);

  const outDir = path.resolve("deployments");
  await ensureDir(outDir);
  const outFile = path.join(outDir, `${netName}.json`);
  const df = await loadDeploymentFile(outFile, netName, chainId);

  const existing = findExisting(df, env.CONTRACT, env.TAG);
  if (existing && skipIfDeployed) {
    console.log(`Already deployed at ${existing.address}, skipping (SKIP_IF_DEPLOYED=true).`);
    process.exit(0);
  }

  // Gas overrides (EIP-1559)
  const feeData = await ethers.provider.getFeeData();
  let maxFeePerGas = gweiToWeiBigInt(env.MAX_FEE_PER_GAS_GWEI) ?? (feeData.maxFeePerGas ?? undefined);
  let maxPriorityFeePerGas =
    gweiToWeiBigInt(env.MAX_PRIORITY_FEE_PER_GAS_GWEI) ?? (feeData.maxPriorityFeePerGas ?? undefined);

  const gasLimit = env.GAS_LIMIT ? BigInt(env.GAS_LIMIT) : undefined;
  const nonce = env.NONCE ? Number.parseInt(env.NONCE, 10) : undefined;

  // Prepare factory
  const factory = await ethers.getContractFactory(env.CONTRACT);

  const deployOverrides: Record<string, unknown> = {};
  if (typeof nonce === "number" && Number.isFinite(nonce)) deployOverrides.nonce = nonce;
  if (typeof gasLimit === "bigint") deployOverrides.gasLimit = gasLimit;
  if (typeof maxFeePerGas === "bigint") deployOverrides.maxFeePerGas = maxFeePerGas;
  if (typeof maxPriorityFeePerGas === "bigint") deployOverrides.maxPriorityFeePerGas = maxPriorityFeePerGas;

  console.log(
    `Fees: maxFeePerGas=${maxFeePerGas ? `${maxFeePerGas} wei` : "auto"}, maxPriorityFeePerGas=${maxPriorityFeePerGas ? `${maxPriorityFeePerGas} wei` : "auto"}, gasLimit=${gasLimit ? gasLimit.toString() : "auto"}`
  );

  // Deploy
  console.log("Sending deployment transaction...");
  const contract = await factory.deploy(...args, deployOverrides);
  const tx = contract.deploymentTransaction();
  if (!tx) throw new Error("No deployment transaction found.");

  console.log(`Tx hash: ${tx.hash}`);
  await contract.waitForDeployment();
  const deployedAddress = await contract.getAddress();
  const receipt = await tx.wait(confirmations);
  if (!receipt) throw new Error("No receipt obtained.");

  console.log(`Deployed at: ${deployedAddress} (block ${receipt.blockNumber})`);

  // Persist
  const record: DeployRecord = {
    contract: env.TAG ? `${env.CONTRACT}:${env.TAG}` : env.CONTRACT,
    address: deployedAddress,
    txHash: tx.hash,
    blockNumber: Number(receipt.blockNumber),
    deployer: await deployer.getAddress(),
    network: netName,
    chainId,
    args,
    timestamp: new Date().toISOString(),
  };

  // Verify (best-effort)
  if (confirmations > 0) {
    console.log("Attempting verification...");
    const v = await tryVerify(deployedAddress, args);
    record.verification = {
      verified: v.ok,
      runAt: new Date().toISOString(),
      error: v.error,
    };
    if (v.ok) {
      console.log("Verification: OK");
    } else {
      console.log(`Verification: FAILED${v.error ? ` (${v.error})` : ""}`);
    }
  }

  // Update file (replace existing record for same key if present)
  const key = record.contract;
  const others = df.records.filter(r => r.contract !== key);
  df.records = [...others, record];
  await saveDeploymentFile(outFile, df);
  console.log(`Saved deployment record to ${outFile}`);
}

main()
  .then(() => {
    console.log("Done.");
    process.exit(0);
  })
  .catch((err) => {
    console.error("Deployment failed:", err?.message || err);
    process.exit(1);
  });
