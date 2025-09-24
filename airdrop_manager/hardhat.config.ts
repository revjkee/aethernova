// airdrop_manager/hardhat.config.ts
import * as dotenv from "dotenv";
dotenv.config();

import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";                 // ethers, waffle, chai, network-helpers, verify
import "hardhat-deploy";                                   // namedAccounts, deterministic deploys, tags
import "solidity-coverage";                                // npx hardhat coverage
import "hardhat-gas-reporter";                             // газ-отчёты
// import "@tenderly/hardhat-tenderly";                    // опционально, если нужен Tenderly

// -----------------------------
// ENV helpers
// -----------------------------
const pk = (process.env.PRIVATE_KEY || "").trim();
const pk2 = (process.env.PRIVATE_KEY_2 || "").trim();
const accs = [pk, pk2].filter(Boolean);

function url(name: string, fallback: string = ""): string | undefined {
  const val = (process.env[name] || "").trim();
  return val ? val : fallback || undefined;
}

const GAS = (process.env.GAS_REPORT || "false").toLowerCase() === "true";
const COINMARKETCAP = process.env.COINMARKETCAP || "";
const REPORT_CURRENCY = process.env.REPORT_CURRENCY || "USD";

// -----------------------------
// Common network templates
// -----------------------------
const withAccounts = (rpcUrl?: string) =>
  rpcUrl
    ? { url: rpcUrl, accounts: accs.length ? accs : { mnemonic: "test test test test test test test test test test test junk" } }
    : undefined;

// -----------------------------
// Hardhat config
// -----------------------------
const config: HardhatUserConfig = {
  solidity: {
    // Несколько компиляторов для совместимости библиотек
    compilers: [
      {
        version: "0.8.26",
        settings: {
          optimizer: { enabled: true, runs: 1200 },
          viaIR: true
        }
      },
      {
        version: "0.8.20",
        settings: {
          optimizer: { enabled: true, runs: 800 },
          viaIR: false
        }
      },
      {
        version: "0.7.6",
        settings: {
          optimizer: { enabled: true, runs: 200 },
          evmVersion: "istanbul"
        }
      }
    ],
    overrides: {
      // Пример: для конкретных файлов можно задать иные настройки
      // "contracts/legacy/*.sol": { version: "0.7.6", settings: { optimizer: { enabled: true, runs: 200 } } }
    }
  },

  // Жёсткие пути — удобно для CI и разнесения билд-артефактов
  paths: {
    sources: "contracts",
    tests: "test",
    cache: "cache",
    artifacts: "artifacts",
    deployments: "deployments",
    deploy: "deploy" // hardhat-deploy scripts
  },

  // Параметры mocha для долгих сценариев деплоя/эмуляции
  mocha: {
    timeout: 120_000
  },

  // Отчёт по газу
  gasReporter: {
    enabled: GAS,
    currency: REPORT_CURRENCY,
    coinmarketcap: COINMARKETCAP || undefined,
    showTimeSpent: true,
    excludeContracts: ["mocks/"],
    reportPureAndViewMethods: true,
    onlyCalledMethods: false,
    // token: "ETH", // можно переопределять per-network
  },

  // hardhat-deploy: именованные аккаунты для повторяемых деплоев
  namedAccounts: {
    deployer: {
      default: 0,          // первый аккаунт
      mainnet: 0,
      sepolia: 0,
      holesky: 0
    },
    admin: {
      default: 1
    },
    airdropOperator: {
      default: 1
    },
    tester: {
      default: 2
    }
  },

  // Сети — читаются из ENV, чтобы не жёстко кодировать ключи в репозитории
  networks: {
    hardhat: {
      chainId: 31337,
      allowUnlimitedContractSize: false,
      accounts: {
        // более предсказуемый gasLimit в тестах
        count: 20
      },
      forking: process.env.HARDHAT_FORK_URL
        ? {
            url: process.env.HARDHAT_FORK_URL,
            blockNumber: process.env.HARDHAT_FORK_BLOCK ? parseInt(process.env.HARDHAT_FORK_BLOCK, 10) : undefined
          }
        : undefined
    },

    // Ethereum
    mainnet: withAccounts(url("RPC_MAINNET")),
    sepolia: withAccounts(url("RPC_SEPOLIA") || "https://rpc.sepolia.org"),
    holesky: withAccounts(url("RPC_HOLESKY")),

    // Polygon
    polygon: withAccounts(url("RPC_POLYGON")),
    polygonAmoy: withAccounts(url("RPC_POLYGON_AMOY")),

    // Arbitrum
    arbitrum: withAccounts(url("RPC_ARBITRUM")),
    arbitrumSepolia: withAccounts(url("RPC_ARBITRUM_SEPOLIA")),

    // Optimism
    optimism: withAccounts(url("RPC_OPTIMISM")),
    optimismSepolia: withAccounts(url("RPC_OPTIMISM_SEPOLIA")),

    // Base
    base: withAccounts(url("RPC_BASE")),
    baseSepolia: withAccounts(url("RPC_BASE_SEPOLIA")),

    // BSC
    bsc: withAccounts(url("RPC_BSC")),
    bscTestnet: withAccounts(url("RPC_BSC_TESTNET")),

    // Avalanche
    avalanche: withAccounts(url("RPC_AVALANCHE")),
    avalancheFuji: withAccounts(url("RPC_FUJI")),

    // zk / L2 примеры (опционально)
    linea: withAccounts(url("RPC_LINEA")),
    scroll: withAccounts(url("RPC_SCROLL")),
    mantle: withAccounts(url("RPC_MANTLE"))
  },

  // Etherscan API ключи по сетям; поддерживаются кастомные сканеры
  etherscan: {
    // Передавайте ключи через переменные окружения:
    // ETHERSCAN_API_KEY, POLYGONSCAN_API_KEY, ARBISCAN_API_KEY, OPTIMISTIC_API_KEY, BASESCAN_API_KEY, BSCSCAN_API_KEY, SNOWTRACE_API_KEY, LINEASCAN_API_KEY, SCROLLSCAN_API_KEY, MANTLESCAN_API_KEY
    apiKey: {
      mainnet: process.env.ETHERSCAN_API_KEY || "",
      sepolia: process.env.ETHERSCAN_API_KEY || "",
      holesky: process.env.ETHERSCAN_API_KEY || "",

      polygon: process.env.POLYGONSCAN_API_KEY || "",
      polygonAmoy: process.env.POLYGONSCAN_API_KEY || "",

      arbitrumOne: process.env.ARBISCAN_API_KEY || "",
      arbitrumSepolia: process.env.ARBISCAN_API_KEY || "",

      optimisticEthereum: process.env.OPTIMISTIC_API_KEY || "",
      optimisticSepolia: process.env.OPTIMISTIC_API_KEY || "",

      base: process.env.BASESCAN_API_KEY || "",
      baseSepolia: process.env.BASESCAN_API_KEY || "",

      bsc: process.env.BSCSCAN_API_KEY || "",
      bscTestnet: process.env.BSCSCAN_API_KEY || "",

      avalanche: process.env.SNOWTRACE_API_KEY || "",
      avalancheFujiTestnet: process.env.SNOWTRACE_API_KEY || "",

      linea: process.env.LINEASCAN_API_KEY || "",
      scroll: process.env.SCROLLSCAN_API_KEY || "",
      mantle: process.env.MANTLESCAN_API_KEY || ""
    },
    customChains: [
      // Примеры кастомных цепочек; добавляйте при необходимости
      {
        network: "polygonAmoy",
        chainId: 80002,
        urls: {
          apiURL: "https://api-amoy.polygonscan.com/api",
          browserURL: "https://www.oklink.com/amoy"
        }
      },
      {
        network: "baseSepolia",
        chainId: 84532,
        urls: {
          apiURL: "https://api-sepolia.basescan.org/api",
          browserURL: "https://sepolia.basescan.org"
        }
      }
    ]
  },

  // Плагины hardhat-deploy
  deterministicDeployment: process.env.DETERMINISTIC_SALT
    ? {
        // Позволяет воспроизводимые адреса контрактов
        factory: process.env.DETERMINISTIC_FACTORY || undefined,
        deployer: undefined, // использовать namedAccounts.deployer
        funding: "10000000000000000", // 0.01 ETH для фабрики, при необходимости
        signedTx: false,
        salt: process.env.DETERMINISTIC_SALT
      }
    : undefined
};

export default config;

/**
 * Рекомендованные переменные окружения (.env):
 *
 * PRIVATE_KEY=0x....
 * PRIVATE_KEY_2=0x....
 *
 * RPC_MAINNET=https://...
 * RPC_SEPOLIA=https://...
 * RPC_HOLESKY=https://...
 * RPC_POLYGON=https://...
 * RPC_POLYGON_AMOY=https://...
 * RPC_ARBITRUM=https://...
 * RPC_ARBITRUM_SEPOLIA=https://...
 * RPC_OPTIMISM=https://...
 * RPC_OPTIMISM_SEPOLIA=https://...
 * RPC_BASE=https://...
 * RPC_BASE_SEPOLIA=https://...
 * RPC_BSC=https://...
 * RPC_BSC_TESTNET=https://...
 * RPC_AVALANCHE=https://...
 * RPC_FUJI=https://...
 * RPC_LINEA=https://...
 * RPC_SCROLL=https://...
 * RPC_MANTLE=https://...
 *
 * ETHERSCAN_API_KEY=...
 * POLYGONSCAN_API_KEY=...
 * ARBISCAN_API_KEY=...
 * OPTIMISTIC_API_KEY=...
 * BASESCAN_API_KEY=...
 * BSCSCAN_API_KEY=...
 * SNOWTRACE_API_KEY=...
 * LINEASCAN_API_KEY=...
 * SCROLLSCAN_API_KEY=...
 * MANTLESCAN_API_KEY=...
 *
 * GAS_REPORT=true
 * REPORT_CURRENCY=USD
 * COINMARKETCAP=your-cmc-api-key
 *
 * HARDHAT_FORK_URL=https://mainnet.infura.io/v3/...
 * HARDHAT_FORK_BLOCK=21000000
 *
 * DETERMINISTIC_SALT=0x0000... (32 байта hex)
 * DETERMINISTIC_FACTORY=0x...   (опционально)
 */
