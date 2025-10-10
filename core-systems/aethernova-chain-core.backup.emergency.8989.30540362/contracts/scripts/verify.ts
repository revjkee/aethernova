// aethernova-chain-core/contracts/scripts/verify.ts
//
// Production-grade верификатор контрактов для Hardhat.
// Запуск:
//   npx hardhat run contracts/scripts/verify.ts --network <network> \
//     --address 0x... \
//     [--contract contracts/Path.sol:ContractName] \
//     [--args-json '[1,"hello",["0x..","0x.."]]'] \
//     [--args-file ./constructor-args.ts] \
//     [--libraries-json '{"LibA":"0x..","LibB":"0x.."}'] \
//     [--min-conf 5] [--max-retries 6] [--base-delay-ms 4000]
//
// Требования:
//   - Плагин @nomicfoundation/hardhat-verify в проекте (см. доки). :contentReference[oaicite:1]{index=1}
//   - API-ключи в hardhat.config.{js,ts} (etherscan.apiKey / blockscout и т.п.). :contentReference[oaicite:2]{index=2}

import hre from "hardhat";
import { ethers } from "hardhat";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

type VerifyArgs = {
  address: string;
  contract?: string; // fully qualified name, например "contracts/My.sol:My"
  constructorArguments?: any[];
  libraries?: Record<string, string>;
};

function parseCli(): {
  address: string;
  contract?: string;
  argsJson?: string;
  argsFile?: string;
  librariesJson?: string;
  minConf: number;
  maxRetries: number;
  baseDelayMs: number;
} {
  const argv = require("minimist")(process.argv.slice(2));
  const address = (argv.address || argv.a || "").toString();
  if (!address) throw new Error("--address обязателен");
  return {
    address,
    contract: argv.contract || argv.c,
    argsJson: argv["args-json"],
    argsFile: argv["args-file"],
    librariesJson: argv["libraries-json"],
    minConf: Number(argv["min-conf"] ?? process.env.VERIFY_MIN_CONF ?? 5),
    maxRetries: Number(argv["max-retries"] ?? process.env.VERIFY_MAX_RETRIES ?? 6),
    // Базовая задержка между запросами ниже общедоступных лимитов Etherscan (>= 5 req/s). :contentReference[oaicite:3]{index=3}
    baseDelayMs: Number(argv["base-delay-ms"] ?? process.env.VERIFY_BASE_DELAY_MS ?? 4000),
  };
}

async function loadArgsFromFile(p: string): Promise<any[]> {
  const abs = resolve(p);
  // Hardhat регистрирует ts-node, поэтому dynamic import для TS/JS работает. :contentReference[oaicite:4]{index=4}
  const mod = await import(pathToFileURL(abs).toString());
  // поддержка default и именованного экспорта
  const val = (mod.default ?? mod.constructorArgs ?? mod.args) as any;
  if (!Array.isArray(val)) {
    throw new Error(`Файл ${p} должен экспортировать массив (default/constructorArgs/args)`);
  }
  return val;
}

function parseLibraries(json?: string): Record<string, string> | undefined {
  if (!json) return undefined;
  const obj = JSON.parse(json);
  if (obj && typeof obj === "object") return obj as Record<string, string>;
  throw new Error("--libraries-json должен быть объектом {LibName: address}");
}

async function waitForOnChainCode(addr: string, minConf: number): Promise<void> {
  const provider = ethers.provider;
  // Проверяем наличие байткода и достаточное число подтверждений
  // (частый ответ Etherscan/Polygonscan — “address does not have bytecode”, нужно подождать индексирования). :contentReference[oaicite:5]{index=5}
  const receipt = await provider.getTransactionReceipt(addr).catch(() => null);
  // addr — это адрес контракта, поэтому receipt может быть null; проверим код напрямую:
  for (;;) {
    const code = await provider.getCode(addr);
    if (code && code !== "0x") break;
    await new Promise((r) => setTimeout(r, 3000));
  }
  // Ждём N подтверждений блока, чтобы эксплорер успел проиндексировать. Рекомендация — подождать несколько подтверждений. :contentReference[oaicite:6]{index=6}
  const latest = await provider.getBlockNumber();
  const deployBlock = await (async () => {
    // эвристика: попытка найти номер блока по последним событиям getCode не даёт txHash,
    // поэтому ждём просто minConf блоков от текущего.
    return latest;
  })();
  const target = deployBlock + minConf;
  while ((await provider.getBlockNumber()) < target) {
    await new Promise((r) => setTimeout(r, 1000));
  }
}

function isAlreadyVerifiedError(e: unknown): boolean {
  const msg = (e as any)?.message?.toString()?.toLowerCase() ?? "";
  return (
    msg.includes("already verified") ||
    msg.includes("source code already verified") ||
    msg.includes("contract source code already verified")
  );
}

function isBackendNotReadyError(e: unknown): boolean {
  const msg = (e as any)?.message?.toString()?.toLowerCase() ?? "";
  // Классические ответы Etherscan-совместимых API при ранней попытке
  return (
    msg.includes("does not have bytecode") ||
    msg.includes("unable to verify") ||
    msg.includes("pending in queue") ||
    msg.includes("notok")
  );
}

async function verifyOnce(args: VerifyArgs): Promise<void> {
  // Официальный способ — запуск задачи verify:verify из HRE. :contentReference[oaicite:7]{index=7}
  await hre.run("verify:verify", args);
}

async function main() {
  const cli = parseCli();

  // Загружаем constructor args
  let constructorArguments: any[] | undefined = undefined;
  if (cli.argsJson && cli.argsFile) {
    throw new Error("Укажите либо --args-json, либо --args-file, но не оба");
  }
  if (cli.argsJson) {
    const parsed = JSON.parse(cli.argsJson);
    if (!Array.isArray(parsed)) throw new Error("--args-json должен быть массивом");
    constructorArguments = parsed;
  } else if (cli.argsFile) {
    constructorArguments = await loadArgsFromFile(cli.argsFile);
  }

  const libraries = parseLibraries(cli.librariesJson);

  // Ждём появления кода и minConf подтверждений
  await waitForOnChainCode(cli.address, cli.minConf);

  const args: VerifyArgs = {
    address: cli.address,
    contract: cli.contract,
    constructorArguments,
    libraries,
  };

  // Экспоненциальная задержка (с учётом лимитов Etherscan/Polygonscan/BscScan). :contentReference[oaicite:8]{index=8}
  let attempt = 0;
  for (;;) {
    try {
      attempt++;
      await verifyOnce(args);
      console.log(`OK: verified ${cli.address} on ${hre.network.name}`);
      return;
    } catch (e: any) {
      if (isAlreadyVerifiedError(e)) {
        console.log(`OK: already verified ${cli.address} on ${hre.network.name}`);
        return;
      }
      if (attempt > cli.maxRetries) {
        console.error(`FAILED after ${attempt - 1} retries: ${e?.message ?? e}`);
        throw e;
      }
      const backoff =
        cli.baseDelayMs * Math.pow(2, attempt - 1) + Math.floor(Math.random() * 500);
      const reason = isBackendNotReadyError(e) ? "backend not ready / indexing" : "rate/other";
      console.warn(
        `WARN: verify attempt ${attempt} failed (${reason}), retrying in ${backoff} ms...`,
      );
      await new Promise((r) => setTimeout(r, backoff));
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
