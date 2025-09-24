// filepath: airdrop_manager/scripts/deploy_airdrop.ts
// Usage (examples):
//   ts-node scripts/deploy_airdrop.ts \
//     --network sepolia \
//     --artifact out/Airdrop.sol/Airdrop.json \
//     --args '["0xDistributorAddress","0xMerkleRoot..."]' \
//     --verify
//
// Env (examples):
//   PRIVATE_KEY=0x... (deployer EOA)
//   RPC_MAINNET=... RPC_SEPOLIA=... RPC_BASE=... RPC_ARBITRUM=... RPC_OPTIMISM=... RPC_POLYGON=...
//   ETHERSCAN_API_KEY=...   # also применяется для *Scan (Arbiscan/Polygonscan/Basescan/Optimistic Etherscan)
//   BUILD_INFO_DIR=out/build-info  # при необходимости переопределить
//
// Требования (npm):
//   viem, typescript, ts-node, dotenv

import 'dotenv/config'
import fs from 'fs/promises'
import path from 'path'
import { fileURLToPath } from 'url'

import {
  Address,
  Hex,
  createPublicClient,
  createWalletClient,
  getContractAddress,
  http,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import {
  mainnet,
  sepolia,
  base,
  arbitrum,
  optimism,
  polygon,
  Chain,
} from 'viem/chains'

// ------------------------ CLI args (без внешних зависимостей) ------------------------

type Args = {
  network: string
  artifact: string
  args?: string // JSON-массив аргументов конструктора
  verify?: boolean
}

function parseArgs(argv: string[]): Args {
  const out: Args = { network: process.env.NETWORK || 'sepolia', artifact: '' }
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--network') out.network = argv[++i]
    else if (a === '--artifact') out.artifact = argv[++i]
    else if (a === '--args') out.args = argv[++i]
    else if (a === '--verify') out.verify = true
  }
  if (!out.artifact) {
    out.artifact = 'out/Airdrop.sol/Airdrop.json'
  }
  return out
}

// ------------------------ Helpers: сети, RPC, клиенты ------------------------

const CHAIN_BY_NAME: Record<string, Chain> = {
  mainnet,
  sepolia,
  base,
  arbitrum,
  optimism,
  polygon,
}

const RPC_ENV_BY_CHAIN: Record<string, string> = {
  [mainnet.id]: process.env.RPC_MAINNET || '',
  [sepolia.id]: process.env.RPC_SEPOLIA || '',
  [base.id]: process.env.RPC_BASE || '',
  [arbitrum.id]: process.env.RPC_ARBITRUM || '',
  [optimism.id]: process.env.RPC_OPTIMISM || '',
  [polygon.id]: process.env.RPC_POLYGON || '',
}

function pickChain(name: string): Chain {
  const c = CHAIN_BY_NAME[name.toLowerCase()]
  if (!c) {
    throw new Error(
      `Unknown network '${name}'. Supported: ${Object.keys(CHAIN_BY_NAME).join(', ')}`,
    )
  }
  return c
}

function rpcFor(chain: Chain): string {
  const u = RPC_ENV_BY_CHAIN[chain.id]
  if (!u) throw new Error(`RPC URL env not set for chainId=${chain.id}`)
  return u
}

// ------------------------ Чтение артефакта Foundry ------------------------

type FoundryArtifact = {
  contractName?: string
  abi: any[]
  bytecode?: string | { object?: string }
  deployedBytecode?: string | { object?: string }
  metadata?: string // JSON-строка с compiler.version, sources и т.д. (Sourcify metadata)
}

async function loadArtifact(p: string): Promise<FoundryArtifact> {
  const raw = await fs.readFile(p, 'utf8')
  const j = JSON.parse(raw) as FoundryArtifact
  if (!j.abi) throw new Error(`ABI not found in ${p}`)
  return j
}

function normalizeBytecode(b?: string | { object?: string }): Hex {
  if (!b) throw new Error('Bytecode not present in artifact')
  if (typeof b === 'string') return b as Hex
  if (typeof b.object === 'string') return b.object as Hex
  throw new Error('Unrecognized bytecode shape in artifact')
}

// ------------------------ Поиск build-info для верификации ------------------------

type BuildInfo = {
  input: any // стандартный solc JSON input
  output: any // solc output (contracts map)
  solcVersion?: string
  solc_version?: string
}

async function findLatestBuildInfo(dir: string): Promise<string> {
  const files = await fs.readdir(dir)
  const cand = await Promise.all(
    files
      .filter((f) => f.endsWith('.json'))
      .map(async (f) => {
        const st = await fs.stat(path.join(dir, f))
        return { f, mtime: st.mtimeMs }
      }),
  )
  if (!cand.length) throw new Error(`No build-info json in ${dir}`)
  cand.sort((a, b) => b.mtime - a.mtime)
  return path.join(dir, cand[0].f)
}

async function loadBuildInfoMaybe(dir: string): Promise<BuildInfo | null> {
  try {
    const p = await findLatestBuildInfo(dir)
    const raw = await fs.readFile(p, 'utf8')
    return JSON.parse(raw) as BuildInfo
  } catch {
    return null
  }
}

// ------------------------ Сопоставление контракта для FQN ------------------------

function guessFqnFromBuildInfo(
  buildInfo: BuildInfo,
  artifactAbi: any[],
  artifactName?: string,
): string | null {
  // Перебираем output.contracts[source][name], ищем по совпадению ABI
  const out = buildInfo.output?.contracts ?? {}
  const abiStr = JSON.stringify(artifactAbi)
  for (const source of Object.keys(out)) {
    for (const name of Object.keys(out[source])) {
      const abi = out[source][name]?.abi
      if (abi && JSON.stringify(abi) === abiStr) {
        return `${source}:${name}`
      }
    }
  }
  // Фоллбек: если не нашли, вернём просто имя контракта (Etherscan иногда принимает)
  return artifactName ?? null
}

// ------------------------ Etherscan верификация (standard-json-input) ------------------------

function etherscanApiUrl(chain: Chain): string {
  // Соответствие chain -> *Scan API
  switch (chain.id) {
    case mainnet.id:
      return 'https://api.etherscan.io/api'
    case sepolia.id:
      return 'https://api-sepolia.etherscan.io/api'
    case base.id:
      return 'https://api.basescan.org/api'
    case arbitrum.id:
      return 'https://api.arbiscan.io/api'
    case optimism.id:
      return 'https://api-optimistic.etherscan.io/api'
    case polygon.id:
      return 'https://api.polygonscan.com/api'
    default:
      throw new Error(`No Etherscan-like API mapping for chainId=${chain.id}`)
  }
}

async function verifyOnEtherscan(params: {
  chain: Chain
  address: Address
  buildInfo: BuildInfo
  artifact: FoundryArtifact
  constructorArgsHex?: string // без 0x или с 0x – приведём ниже
  apiKey: string
}) {
  const { chain, address, buildInfo, artifact, constructorArgsHex, apiKey } = params
  // Компилерная версия
  // Etherscan ожидает формат 'vX.Y.Z+commit.HHHHHHHH'
  // Попробуем сначала из build-info, затем из metadata артефакта
  let compilerVersion =
    buildInfo.solcVersion || buildInfo.solc_version || undefined

  if (!compilerVersion && artifact.metadata) {
    try {
      const meta = JSON.parse(artifact.metadata)
      compilerVersion = meta?.compiler?.version
    } catch {
      // ignore
    }
  }
  if (!compilerVersion) {
    throw new Error('Compiler version not found in build-info/metadata')
  }
  if (!compilerVersion.startsWith('v')) compilerVersion = `v${compilerVersion}`

  // FQN
  const fqn = guessFqnFromBuildInfo(buildInfo, artifact.abi, artifact.contractName)
  if (!fqn) throw new Error('Unable to determine contract name/FQN for verification')

  // Стандартный JSON input целиком
  const sourceCode = JSON.stringify(buildInfo.input)

  // Аргументы конструктора: Etherscan ждёт hex без 0x
  const ctor =
    (constructorArgsHex || '').startsWith('0x')
      ? (constructorArgsHex || '').slice(2)
      : constructorArgsHex || ''

  const url = etherscanApiUrl(chain)
  const form = new URLSearchParams({
    module: 'contract',
    action: 'verifysourcecode',
    apikey: apiKey,
    contractaddress: address,
    sourceCode,
    codeformat: 'solidity-standard-json-input',
    contractname: fqn,
    compilerversion: compilerVersion,
    constructorArguments: ctor,
  })

  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  })
  const data = (await resp.json()) as any
  return data
}

// ------------------------ Main ------------------------

async function main() {
  const args = parseArgs(process.argv)
  const chain = pickChain(args.network)
  const rpc = rpcFor(chain)

  const pk = process.env.PRIVATE_KEY
  if (!pk) throw new Error('PRIVATE_KEY env is required')

  const account = privateKeyToAccount(pk as Hex)

  const publicClient = createPublicClient({ chain, transport: http(rpc) })
  const walletClient = createWalletClient({
    chain,
    transport: http(rpc),
    account,
  })

  // Артефакт контракта (Foundry out/*.json)
  const artifact = await loadArtifact(args.artifact)
  const abi = artifact.abi
  const bytecode = normalizeBytecode(artifact.bytecode)

  // Аргументы конструктора
  const ctorArgs: any[] = args.args ? JSON.parse(args.args) : []

  // Нонс для детерминированного расчёта адреса (CREATE)
  // (также пригодится для кросс-проверки с квитанцией)
  // viem: getTransactionCount. :contentReference[oaicite:1]{index=1}
  const nonce = await publicClient.getTransactionCount({
    address: account.address,
    blockTag: 'pending',
  })

  // Оценка EIP-1559 комиссий (maxFeePerGas/maxPriorityFeePerGas). :contentReference[oaicite:2]{index=2}
  const fee = await publicClient.estimateFeesPerGas()

  // Оценка газа под деплой (опционально, Viem сам оценит при deployContract; укажем явно). :contentReference[oaicite:3]{index=3}
  const gas = await publicClient.estimateContractGas({
    abi,
    bytecode,
    args: ctorArgs,
    account: account.address,
  })

  // Деплой контракта: walletClient.deployContract. :contentReference[oaicite:4]{index=4}
  const txHash = await walletClient.deployContract({
    abi,
    bytecode,
    args: ctorArgs,
    account,
    gas,
    maxFeePerGas: fee.maxFeePerGas,
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
  })

  // Ожидаем квитанцию: waitForTransactionReceipt. :contentReference[oaicite:5]{index=5}
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash })

  // Контрактный адрес: из receipt.contractAddress (если предоставлен клиентом)
  // или детерминированно из from+nonce через getContractAddress. :contentReference[oaicite:6]{index=6}
  const predicted = getContractAddress({ from: account.address, nonce })
  const deployedAddress = (receipt as any).contractAddress || predicted

  // Вывод краткого отчёта JSON
  const summary = {
    network: chain.name,
    chainId: chain.id,
    from: account.address,
    txHash,
    blockNumber: receipt.blockNumber,
    contractAddress: deployedAddress,
    gasUsed: receipt.gasUsed,
    effectiveGasPrice: (receipt as any).effectiveGasPrice,
  }
  // Пишем в stdout одной строкой (удобно для CI/парсинга)
  console.log(JSON.stringify(summary, (_, v) => (typeof v === 'bigint' ? v.toString() : v)))

  // Верификация (опционально)
  if (args.verify) {
    const apiKey = process.env.ETHERSCAN_API_KEY
    if (!apiKey) {
      console.error('ETHERSCAN_API_KEY not set, skipping verification')
      return
    }
    // build-info: Foundry сохраняет в out/build-info/*.json. :contentReference[oaicite:7]{index=7}
    const buildInfoDir =
      process.env.BUILD_INFO_DIR ||
      path.join(process.cwd(), 'out', 'build-info')

    const buildInfo = await loadBuildInfoMaybe(buildInfoDir)
    if (!buildInfo) {
      console.error(`No build-info found under ${buildInfoDir}, cannot verify`)
      return
    }

    // Конструкторные аргументы в hex: если нужен — пользователь может передать через ENV/CLI
    // Для простоты оставим пустым — Etherscan принимает пустую строку, если args отсутствуют.
    // В противном случае здесь следует дать уже ABI-энкоденные аргументы.
    const verifyRes = await verifyOnEtherscan({
      chain,
      address: deployedAddress as Address,
      buildInfo,
      artifact,
      constructorArgsHex: process.env.CONSTRUCTOR_ARGS_HEX || '',
      apiKey,
    })

    console.log(JSON.stringify({ etherscanVerify: verifyRes }))
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
