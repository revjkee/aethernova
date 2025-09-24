import { ethers } from "hardhat";
import { ZkIdentity, VerifierGroth16, VerifierPlonk } from "../typechain-types";
import { PoseidonHasher } from "../utils/hasher";
import { MerkleTree } from "../utils/merkleTree";
import { generateIdentity, poseidonHash } from "./utils";
import { BigNumberish } from "ethers";
import { TREE_DEPTH, ZERO_VALUE } from "../circuits/circuit_constants.json";

interface DeploymentResult {
  zkIdentity: ZkIdentity;
  grothVerifier: VerifierGroth16;
  plonkVerifier: VerifierPlonk;
}

interface IdentityInput {
  trapdoor: bigint;
  nullifier: bigint;
  commitment: bigint;
  nullifierHash: bigint;
  merkleRoot: bigint;
}

/**
 * Деплой смарт-контрактов ZkIdentity и двух верификаторов
 */
export async function deployContracts(): Promise<DeploymentResult> {
  const Groth = await ethers.getContractFactory("VerifierGroth16");
  const grothVerifier = await Groth.deploy();
  await grothVerifier.deployed();

  const Plonk = await ethers.getContractFactory("VerifierPlonk");
  const plonkVerifier = await Plonk.deploy();
  await plonkVerifier.deployed();

  const ZkIdentityFactory = await ethers.getContractFactory("ZkIdentity");
  const zkIdentity = await ZkIdentityFactory.deploy(
    grothVerifier.address,
    plonkVerifier.address,
    TREE_DEPTH,
    ZERO_VALUE
  );
  await zkIdentity.deployed();

  return { zkIdentity, grothVerifier, plonkVerifier };
}

/**
 * Создаёт валидные входные данные для регистрации и пруфов
 */
export function createIdentityInput(tree: MerkleTree): IdentityInput {
  const { trapdoor, nullifier } = generateIdentity();
  const commitment = poseidonHash([trapdoor, nullifier]);
  tree.insert(commitment);
  const root = tree.getRoot();
  const nullifierHash = poseidonHash([nullifier]);

  return {
    trapdoor,
    nullifier,
    commitment,
    nullifierHash,
    merkleRoot: root
  };
}

/**
 * Инициализирует дерево с N пользователей
 */
export function initializeMerkleWithIdentities(n: number): {
  tree: MerkleTree;
  identities: IdentityInput[];
} {
  const hasher = new PoseidonHasher();
  const tree = new MerkleTree(TREE_DEPTH, ZERO_VALUE, hasher);
  const identities: IdentityInput[] = [];

  for (let i = 0; i < n; i++) {
    const input = createIdentityInput(tree);
    identities.push(input);
  }

  return { tree, identities };
}
