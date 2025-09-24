import { ethers } from "ethers";
import { poseidonHash } from "../test/utils";
import { createProof } from "../test/utils";
import { ZkIdentity } from "../typechain-types";

// WalletConnect client
import { SignClient } from "@walletconnect/sign-client";
import { SessionTypes } from "@walletconnect/types";

const ZK_IDENTITY_CONTRACT = process.env.ZK_IDENTITY_ADDRESS!;
const RPC_URL = process.env.RPC_URL!;
const PRIVATE_KEY = process.env.PRIVATE_KEY!;

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const zkIdentity = new ethers.Contract(
  ZK_IDENTITY_CONTRACT,
  require("../artifacts/contracts/ZkIdentity.sol/ZkIdentity.json").abi,
  signer
) as ZkIdentity;

/**
 * Получение WalletConnect сессии и генерация приватного идентификатора.
 */
export async function generateZkProofFromWallet(session: SessionTypes.Struct): Promise<{
  identityCommitment: bigint;
  trapdoor: bigint;
  nullifier: bigint;
  proof: any;
}> {
  // 1. Получаем Ethereum адрес из WalletConnect-сессии
  const ethAddress = session.namespaces.eip155.accounts[0].split(":")[2];
  const addressBigInt = BigInt(ethers.utils.getAddress(ethAddress).toLowerCase().slice(2), 16);

  // 2. Генерация приватных данных
  const trapdoor = poseidonHash([addressBigInt, BigInt(Date.now())]);
  const nullifier = poseidonHash([addressBigInt, BigInt(1)]);

  const identityCommitment = poseidonHash([trapdoor, nullifier]);

  // 3. Регистрация в контракте
  const tx = await zkIdentity.register(identityCommitment);
  await tx.wait();

  const merkleRoot = await zkIdentity.getRoot();

  // 4. Генерация zk-proof
  const proof = await createProof("groth16", trapdoor, nullifier, merkleRoot);

  return {
    identityCommitment,
    trapdoor,
    nullifier,
    proof,
  };
}
