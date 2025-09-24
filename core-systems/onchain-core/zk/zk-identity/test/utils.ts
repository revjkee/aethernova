import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { poseidon } from "circomlibjs";
import { BigNumberish } from "ethers";
import { toHex } from "web3-utils";

export type Identity = {
  trapdoor: bigint;
  nullifier: bigint;
  commitment: bigint;
};

export type ProofOutput = {
  proof: any;
  publicSignals: string[];
};

/**
 * Генерирует уникальную identity (trapdoor + nullifier + commitment)
 */
export function generateIdentity(): Identity {
  const trapdoor = BigInt("0x" + crypto.randomUUID().replace(/-/g, "").slice(0, 62));
  const nullifier = BigInt("0x" + crypto.randomUUID().replace(/-/g, "").slice(0, 62));
  const commitment = poseidonHash([trapdoor, nullifier]);

  return { trapdoor, nullifier, commitment };
}

/**
 * Хэширует входы с использованием Poseidon
 */
export function poseidonHash(inputs: BigNumberish[]): bigint {
  const values = inputs.map(i => BigInt(i));
  return poseidon(values);
}

/**
 * Подготавливает входы для circom
 */
export function buildInput(
  trapdoor: bigint,
  nullifier: bigint,
  merkleRoot: bigint,
  merklePathElements: bigint[],
  merklePathIndices: number[]
) {
  return {
    identityTrapdoor: trapdoor.toString(),
    identityNullifier: nullifier.toString(),
    treePathIndices: merklePathIndices,
    treeSiblings: merklePathElements.map(el => el.toString()),
    root: merkleRoot.toString(),
  };
}

/**
 * Генерирует zk-SNARK proof (Groth16 / PLONK)
 * Требует установленного snarkjs и настроенных .zkey/verifier
 */
export async function createProof(
  scheme: "groth16" | "plonk",
  trapdoor: bigint,
  nullifier: bigint,
  merkleRoot: bigint
): Promise<ProofOutput> {
  const tempInputPath = path.join(__dirname, "temp_input.json");
  const tempProofPath = path.join(__dirname, "temp_proof.json");
  const tempPublicPath = path.join(__dirname, "temp_public.json");

  // Моки: merkle path = 0 (вставка в корень)
  const inputs = buildInput(trapdoor, nullifier, merkleRoot, Array(20).fill(0n), Array(20).fill(0));
  fs.writeFileSync(tempInputPath, JSON.stringify(inputs));

  const circuitDir = path.resolve(__dirname, "../circuits");
  const wasmPath = `${circuitDir}/zk_identity.wasm`;
  const zkeyPath = `${circuitDir}/verifier_${scheme}.zkey`;

  const cmd = scheme === "groth16"
    ? `snarkjs groth16 prove ${zkeyPath} ${wasmPath} ${tempInputPath} ${tempProofPath} ${tempPublicPath}`
    : `snarkjs plonk prove ${zkeyPath} ${wasmPath} ${tempInputPath} ${tempProofPath} ${tempPublicPath}`;

  execSync(cmd);

  const proof = JSON.parse(fs.readFileSync(tempProofPath, "utf-8"));
  const publicSignals = JSON.parse(fs.readFileSync(tempPublicPath, "utf-8"));

  // Очистка временных файлов
  fs.unlinkSync(tempInputPath);
  fs.unlinkSync(tempProofPath);
  fs.unlinkSync(tempPublicPath);

  return { proof, publicSignals };
}
