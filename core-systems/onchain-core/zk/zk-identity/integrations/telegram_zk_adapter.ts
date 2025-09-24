import { ethers } from "ethers";
import fetch from "node-fetch";
import { poseidonHash } from "../test/utils";
import { ZkIdentity } from "../typechain-types";
import { createProof } from "../test/utils";
import { TelegramUser, verifyTelegramLogin } from "./telegram_auth_utils";

// Настройки
const RPC_URL = process.env.RPC_URL || "https://mainnet.infura.io/v3/YOUR_KEY";
const PRIVATE_KEY = process.env.PRIVATE_KEY!;
const ZK_IDENTITY_ADDRESS = process.env.ZK_IDENTITY_ADDRESS!;

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const zkIdentity = new ethers.Contract(ZK_IDENTITY_ADDRESS, require("../artifacts/contracts/ZkIdentity.sol/ZkIdentity.json").abi, signer) as ZkIdentity;

// Основной обработчик Telegram входа и регистрации
export async function registerTelegramZkIdentity(authData: any): Promise<string> {
  // 1. Проверка подлинности Telegram входа
  const user: TelegramUser = verifyTelegramLogin(authData);
  const telegramId = BigInt(user.id);

  // 2. Генерация trapdoor и nullifier, используя Telegram ID как seed
  const trapdoor = poseidonHash([telegramId, BigInt(Date.now())]);
  const nullifier = poseidonHash([telegramId, BigInt(42)]); // фиксированное значение для uniqueness
  const commitment = poseidonHash([trapdoor, nullifier]);

  // 3. Регистрация коммита на контракте
  const tx = await zkIdentity.register(commitment);
  await tx.wait();

  return `ZK Identity зарегистрирован для Telegram ID ${telegramId}. Commitment: ${commitment.toString()}`;
}

// Генерация zk-доказательства входа по Telegram
export async function proveTelegramLogin(telegramId: bigint, trapdoor: bigint, nullifier: bigint): Promise<any> {
  const root = await zkIdentity.getRoot();
  return await createProof("groth16", trapdoor, nullifier, root);
}
