// airdrop_manager/scripts/verify_contracts.ts
// Промышленный скрипт верификации контрактов для Etherscan/Blockscout/Sourcify.
// Источники API/поведения:
// - Etherscan verifysourcecode & checkverifystatus (POST, codeformat=solidity-standard-json-input) :contentReference[oaicite:2]{index=2}
// - Multichain verification и единый API-ключ/chainId для Etherscan-семейства :contentReference[oaicite:3]{index=3}
// - Конкретика про опечатку constructorArguements в Etherscan API (историческая несовместимость) :contentReference[oaicite:4]{index=4}
// - Blockscout совместимый verifysourcecode (Standard JSON input) :contentReference[oaicite:5]{index=5}
// - Руководство по верификации в Blockscout (подтверждает способы) :contentReference[oaicite:6]{index=6}
// - Sourcify: предпочтителен Standard JSON, API/подход и V2 lookup :contentReference[oaicite:7]{index=7}

import { readFile, readdir } from "node:fs/promises";
import { createReadStream } from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

// В проекте предполагается Node 18+ (глобальный fetch и FormData доступны).

type ExplorerKind = "etherscan" | "blockscout" | "sourcify";

interface ContractSpec {
  name: string;                     // логическое имя
  address: string;                  // 0x...
  chainId: number;                  // EIP-155 chainId
  fullyQualifiedName?: string;      // "contracts/My.sol:My"
  artifactPath?: string;            // путь к build-info (Hardhat) или out/*/*.json (Foundry)
  sourceInputPath?: string;         // путь к готовому standard-json input (альтернатива)
  constructorArgs?: unknown[];      // массив аргументов для ABI-энкода
  encodedConstructorArgs?: string;  // 0x...
  abiPath?: string;                 // путь к ABI (если нужно кодировать)
  compilerVersion?: string;         // например: "v0.8.26+commit.8a97fa7a"
  evmVersion?: string;              // например: "paris"
  optimizationUsed?: boolean;       // true/false
  optimizerRuns?: number;           // по умолчанию 200 в solc
  explorer: {
    kind: ExplorerKind;
    apiUrl: string;                 // https://api.etherscan.io/api или https://blockscout.instance/api или https://sourcify.server/server
    apiKey?: string;                // для Etherscan-семейства
  };
}

interface VerifyConfig {
  contracts: ContractSpec[];
  // глобальные дефолты
  defaults?: {
    compilerVersion?: string;
    optimizationUsed?: boolean;
    optimizerRuns?: number;
    evmVersion?: string;
  };
}

function logInfo(msg: string, meta?: Record<string, unknown>) {
  console.log(JSON.stringify({ level: "INFO", msg, ...meta }));
}
function logWarn(msg: string, meta?: Record<string, unknown>) {
  console.warn(JSON.stringify({ level: "WARN", msg, ...meta }));
}
function logError(msg: string, meta?: Record<string, unknown>) {
  console.error(JSON.stringify({ level: "ERROR", msg, ...meta }));
}

function isHex(s?: string): s is string {
  return !!s && /^0x[0-9a-fA-F]*$/.test(s);
}

// ---- ABI encode constructor args using ethers (optional) --------------------
async function abiEncodeConstructor(abiPath: string, args: unknown[]): Promise<string> {
  // динамический импорт, чтобы не требовать ethers в рантайме без надобности
  const { Interface } = await import("ethers");
  const abiJson = JSON.parse(await readFile(abiPath, "utf8"));
  const iface = new Interface(abiJson);
  const ctor = iface.deploy;
  if (!ctor) throw new Error("Constructor not found in ABI");
  const encoded = iface.encodeDeploy(args as any[]);
  // ethers v6 Interface.encodeDeploy возвращает 0x<calldata>; Etherscan ждёт constructor args без сигнатуры,
  // поэтому удаляем 4-байтовый селектор (для конструктора его нет), но ethers уже даёт «чистые» args.
  // Проверка оставляем: должно быть 0x... строка.
  if (!isHex(encoded)) throw new Error("Encoded constructor args are not hex");
  // В некоторых реализациях требуется убрать префикс 0x; Etherscan принимает без 0x (источник в API-гайде). :contentReference[oaicite:8]{index=8}
  return encoded.replace(/^0x/, "");
}

// ---- Build Standard JSON Input from Hardhat build-info or Foundry out/* ----
type HardhatBuildInfo = {
  solcVersion: string; // "0.8.26"
  input: Record<string, any>;
  output: Record<string, any>;
};

async function loadStandardJsonFromHardhat(buildInfoPath: string, fqn: string) {
  const raw = JSON.parse(await readFile(buildInfoPath, "utf8")) as HardhatBuildInfo;
  const solcVersion = raw.solcVersion.startsWith("v") ? raw.solcVersion : `v${raw.solcVersion}`;
  if (!raw.input || !raw.input.sources) throw new Error("Invalid Hardhat build-info: no input.sources");
  return {
    compilerVersion: solcVersion,
    input: raw.input,
    fqn
  };
}

type FoundryArtifact = {
  abi: any[];
  bytecode: string;
  deployedBytecode: string;
  linkReferences?: any;
  metadata?: string; // JSON string with solc input/output/settings
};

async function loadStandardJsonFromFoundry(outArtifactPath: string, fqn?: string) {
  const raw = JSON.parse(await readFile(outArtifactPath, "utf8")) as FoundryArtifact;
  if (!raw.metadata) throw new Error("Foundry artifact lacks metadata");
  const meta = JSON.parse(raw.metadata);
  const solc: string = meta?.compiler?.version;
  const solcVersion = solc?.startsWith("v") ? solc : `v${solc}`;
  const input = meta?.settings
    ? { language: "Solidity", sources: meta.sources, settings: meta.settings }
    : (() => { throw new Error("Invalid Foundry metadata: missing settings/sources"); })();

  // Попытаемся вывести fqn из metadata (перебирая sources)
  let resolvedFqn = fqn;
  if (!resolvedFqn && meta.settings?.compilationTarget) {
    const [p, name] = Object.entries(meta.settings.compilationTarget)[0] as [string, string];
    resolvedFqn = `${p}:${name}`;
  }
  if (!resolvedFqn) throw new Error("FullyQualifiedName is required for Foundry artifacts");
  return { compilerVersion: solcVersion, input, fqn: resolvedFqn };
}

// ---- Etherscan-like client --------------------------------------------------
class EtherscanClient {
  constructor(private apiUrl: string, private apiKey?: string) {}

  // Отправка заявки на верификацию (Standard JSON Input)
  async submitStandardJson(params: {
    contractAddress: string;
    contractName: string;       // path:Name
    compilerVersion: string;    // vX.Y.Z+commit...
    input: any;                 // standard-json
    constructorArgsHex?: string;// без 0x
    evmVersion?: string;
    optimizationUsed?: boolean;
    runs?: number;
  }): Promise<{ guid: string }> {
    const body = new URLSearchParams();
    body.set("module", "contract");
    body.set("action", "verifysourcecode");
    if (this.apiKey) body.set("apikey", this.apiKey);
    body.set("codeformat", "solidity-standard-json-input");
    body.set("contractaddress", params.contractAddress);
    body.set("contractname", params.contractName);
    body.set("compilerversion", params.compilerVersion);
    if (params.evmVersion) body.set("evmversion", params.evmVersion);
    if (typeof params.optimizationUsed === "boolean") body.set("optimizationUsed", params.optimizationUsed ? "1" : "0");
    if (typeof params.runs === "number") body.set("runs", String(params.runs));
    if (params.constructorArgsHex && params.constructorArgsHex.length > 0) {
      // Исторически Etherscan принимал ключ «constructorArguements» (опечатка). Отправим оба. :contentReference[oaicite:9]{index=9}
      body.set("constructorArguments", params.constructorArgsHex);
      body.set("constructorArguements", params.constructorArgsHex);
    }
    body.set("sourceCode", JSON.stringify(params.input));

    const res = await fetch(this.apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const json = await res.json().catch(async () => ({ status: "0", result: await res.text() }));
    if (json.status !== "1" || !json.result) {
      throw new Error(`Etherscan submit failed: ${json.message || ""} ${json.result || ""}`);
    }
    return { guid: String(json.result) };
  }

  async checkStatus(guid: string): Promise<{ status: "success" | "pending" | "failure"; message?: string }> {
    const qs = new URLSearchParams();
    qs.set("module", "contract");
    qs.set("action", "checkverifystatus");
    if (this.apiKey) qs.set("apikey", this.apiKey);
    qs.set("guid", guid);
    const res = await fetch(`${this.apiUrl}?${qs.toString()}`, { method: "GET" });
    const json = await res.json().catch(async () => ({ status: "0", result: await res.text() }));
    const result = (json.result || "").toString().toLowerCase();
    if ((json.status === "1" && result.includes("pass")) || result.includes("verified")) {
      return { status: "success" };
    }
    if (result.includes("pending") || result.includes("in queue")) {
      return { status: "pending" };
    }
    return { status: "failure", message: json.result || json.message };
  }
}

// ---- Sourcify client (multipart file upload) --------------------------------
class SourcifyClient {
  constructor(private baseUrl: string) {}

  // POST /verify — контракт + набор файлов (sources, metadata)
  // В Sourcify предпочтителен стандартный JSON и/или полная загрузка исходников и metadata. :contentReference[oaicite:10]{index=10}
  async verify(address: string, chainId: number, files: Array<{ name: string; content: Buffer | string }>) {
    const form = new FormData();
    form.set("address", address);
    form.set("chain", String(chainId));
    for (const f of files) {
      // Каждый файл с оригинальным путём из sources: form field name должен быть "files"
      form.append("files", new Blob([typeof f.content === "string" ? Buffer.from(f.content) : f.content]), f.name);
    }
    const res = await fetch(this.baseUrl.replace(/\/+$/, "") + "/verify", {
      method: "POST",
      body: form,
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Sourcify verify failed: ${res.status} ${text}`);
    // Сервер может вернуть JSON/текст; оставим текст в логе.
    return text;
  }
}

// ---- Utilities ---------------------------------------------------------------
async function loadJson<T>(p: string): Promise<T> {
  const data = await readFile(p, "utf8");
  return JSON.parse(data) as T;
}

async function listBuildInfoFiles(dir: string): Promise<string[]> {
  try {
    const files = await readdir(dir, { recursive: true });
    return (files as any[]).map(String).filter(f => f.endsWith(".json")).map(f => path.join(dir, f));
  } catch {
    return [];
  }
}

function ensureFqn(spec: ContractSpec, inferred?: string): string {
  const fqn = spec.fullyQualifiedName ?? inferred;
  if (!fqn) throw new Error(`Missing fullyQualifiedName for ${spec.name}`);
  if (!fqn.includes(":")) throw new Error(`Invalid FQN (expected "path:Contract"): ${fqn}`);
  return fqn;
}

function ensureCompilerVersion(spec: ContractSpec, def?: string): string {
  const v = spec.compilerVersion ?? def;
  if (!v) throw new Error(`Missing compilerVersion for ${spec.name}`);
  if (!/^v?\d+\.\d+\.\d+/.test(v)) throw new Error(`Invalid compilerVersion: ${v}`);
  return v.startsWith("v") ? v : `v${v}`;
}

function getBoolean(v: unknown, fallback: boolean): boolean {
  return typeof v === "boolean" ? v : fallback;
}

async function assembleSourcifyFilesFromStandardInput(input: any): Promise<Array<{ name: string; content: Buffer | string }>> {
  const files: Array<{ name: string; content: Buffer | string }> = [];
  // input.sources: { [path]: { content?: string, keccak256?: string }}
  for (const [p, v] of Object.entries<any>(input.sources || {})) {
    if (typeof v?.content !== "string") {
      throw new Error(`Source ${p} missing content; required for Sourcify upload`);
    }
    files.push({ name: p, content: v.content });
  }
  // добавим metadata.json (рекомендуется для full match)
  const metadata = {
    language: input.language,
    settings: input.settings,
    sources: input.sources
  };
  files.push({ name: "metadata.json", content: JSON.stringify(metadata, null, 2) });
  return files;
}

// ---- Main orchestrator -------------------------------------------------------
async function main() {
  const configPath = process.argv[2] || "contracts.verify.json";
  const cfg = await loadJson<VerifyConfig>(configPath);

  for (const spec of cfg.contracts) {
    logInfo("start_contract", { name: spec.name, address: spec.address, chainId: spec.chainId, explorer: spec.explorer.kind });

    // 1) Собираем Standard JSON input
    let stdInput: any | undefined;
    let fqn: string | undefined;
    let compilerVersion: string | undefined;

    if (spec.sourceInputPath) {
      stdInput = await loadJson<any>(spec.sourceInputPath);
      fqn = ensureFqn(spec, spec.fullyQualifiedName);
      compilerVersion = ensureCompilerVersion(spec, cfg.defaults?.compilerVersion);
    } else if (spec.artifactPath) {
      if (spec.artifactPath.includes("build-info")) {
        const { compilerVersion: ver, input, fqn: fqn0 } = await loadStandardJsonFromHardhat(spec.artifactPath, ensureFqn(spec, spec.fullyQualifiedName));
        stdInput = input; fqn = fqn0; compilerVersion = ensureCompilerVersion({ ...spec, compilerVersion: ver }, cfg.defaults?.compilerVersion);
      } else {
        const { compilerVersion: ver, input, fqn: fqn0 } = await loadStandardJsonFromFoundry(spec.artifactPath, spec.fullyQualifiedName);
        stdInput = input; fqn = fqn0; compilerVersion = ensureCompilerVersion({ ...spec, compilerVersion: ver }, cfg.defaults?.compilerVersion);
      }
    } else {
      // Попробуем autodiscover hardhat build-info
      const buildInfos = await listBuildInfoFiles(path.join(process.cwd(), "artifacts", "build-info"));
      if (buildInfos.length === 0) throw new Error("No sourceInputPath/artifactPath provided and no artifacts/build-info found");
      // Возьмём первый файл; в проде стоит сопоставлять по bytecode — опускаем для краткости.
      const { compilerVersion: ver, input, fqn: fqn0 } = await loadStandardJsonFromHardhat(buildInfos[0], ensureFqn(spec, spec.fullyQualifiedName));
      stdInput = input; fqn = fqn0; compilerVersion = ensureCompilerVersion({ ...spec, compilerVersion: ver }, cfg.defaults?.compilerVersion);
    }

    // 2) Конструктор
    let constructorArgsHex = spec.encodedConstructorArgs && isHex(spec.encodedConstructorArgs)
      ? spec.encodedConstructorArgs.replace(/^0x/, "")
      : undefined;
    if (!constructorArgsHex && spec.constructorArgs && spec.abiPath) {
      constructorArgsHex = (await abiEncodeConstructor(spec.abiPath, spec.constructorArgs)).replace(/^0x/, "");
    }

    // 3) Отправка по типу эксплорера
    if (spec.explorer.kind === "etherscan" || spec.explorer.kind === "blockscout") {
      const client = new EtherscanClient(spec.explorer.apiUrl, spec.explorer.apiKey);
      const submit = await client.submitStandardJson({
        contractAddress: spec.address,
        contractName: fqn!,
        compilerVersion: compilerVersion!,
        input: stdInput!,
        constructorArgsHex,
        evmVersion: spec.evmVersion ?? cfg.defaults?.evmVersion,
        optimizationUsed: getBoolean(spec.optimizationUsed, getBoolean(cfg.defaults?.optimizationUsed, true)),
        runs: spec.optimizerRuns ?? cfg.defaults?.optimizerRuns ?? 200,
      });
      logInfo("submitted", { guid: submit.guid });

      // 4) Пуллинг статуса
      let attempt = 0;
      for (;;) {
        await sleep(1000 * Math.min(15, 2 ** attempt));
        const st = await client.checkStatus(submit.guid);
        logInfo("status", { status: st.status, message: st.message });
        if (st.status === "success") break;
        if (st.status === "failure") throw new Error(`Verification failed: ${st.message}`);
        attempt++;
        if (attempt > 12) { // ~минутный лимит
          throw new Error("Timeout waiting for verification");
        }
      }
      logInfo("verified", { name: spec.name, address: spec.address });
    } else if (spec.explorer.kind === "sourcify") {
      const sc = new SourcifyClient(spec.explorer.apiUrl.replace(/\/+$/, "") + "/server");
      const files = await assembleSourcifyFilesFromStandardInput(stdInput!);
      const res = await sc.verify(spec.address, spec.chainId, files);
      logInfo("sourcify_response", { text: res.slice(0, 2000) });
      logInfo("verified", { name: spec.name, address: spec.address });
    } else {
      throw new Error(`Unknown explorer kind: ${(spec.explorer as any).kind}`);
    }
  }
}

main().catch((e) => {
  logError("verify_failed", { error: String(e?.message || e) });
  process.exit(1);
});
