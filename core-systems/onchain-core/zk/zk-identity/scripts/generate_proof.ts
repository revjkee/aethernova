import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import { poseidon } from "circomlibjs";

interface InputData {
  trapdoor: string;
  nullifier: string;
  merklePathElements: string[];
  merklePathIndices: number[];
  merkleRoot: string;
}

interface ProofResult {
  proof: any;
  publicSignals: string[];
}

function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith("0x") ? hex : "0x" + hex);
}

function poseidonHash(inputs: bigint[]): bigint {
  return poseidon(inputs);
}

function writeJson(filepath: string, data: any) {
  fs.writeFileSync(filepath, JSON.stringify(data), { encoding: "utf-8" });
}

function readJson(filepath: string): any {
  return JSON.parse(fs.readFileSync(filepath, "utf-8"));
}

function buildInputFile(input: InputData, destination: string) {
  const circuitInput = {
    identityTrapdoor: input.trapdoor,
    identityNullifier: input.nullifier,
    root: input.merkleRoot,
    treeSiblings: input.merklePathElements,
    treePathIndices: input.merklePathIndices,
  };
  writeJson(destination, circuitInput);
}

function runProof(
  scheme: "groth16" | "plonk",
  wasmPath: string,
  zkeyPath: string,
  inputPath: string,
  outputProofPath: string,
  outputPublicPath: string
) {
  const cmd =
    scheme === "groth16"
      ? `snarkjs groth16 prove "${zkeyPath}" "${wasmPath}" "${inputPath}" "${outputProofPath}" "${outputPublicPath}"`
      : `snarkjs plonk prove "${zkeyPath}" "${wasmPath}" "${inputPath}" "${outputProofPath}" "${outputPublicPath}"`;
  execSync(cmd, { stdio: "inherit" });
}

export function generateProofOffline(
  scheme: "groth16" | "plonk",
  input: InputData,
  circuitsDir = path.resolve(__dirname, "../circuits")
): ProofResult {
  const temp = path.resolve(__dirname, "../temp");
  fs.mkdirSync(temp, { recursive: true });

  const inputPath = path.join(temp, "input.json");
  const proofPath = path.join(temp, "proof.json");
  const publicPath = path.join(temp, "public.json");

  const wasm = path.join(circuitsDir, "zk_identity.wasm");
  const zkey = path.join(circuitsDir, `verifier_${scheme}.zkey`);

  buildInputFile(input, inputPath);
  runProof(scheme, wasm, zkey, inputPath, proofPath, publicPath);

  const proof = readJson(proofPath);
  const publicSignals = readJson(publicPath);

  fs.rmSync(temp, { recursive: true, force: true });

  return { proof, publicSignals };
}

// Пример использования
if (require.main === module) {
  const inputData: InputData = {
    trapdoor: "123456789123456789",
    nullifier: "987654321987654321",
    merklePathElements: Array(20).fill("0"),
    merklePathIndices: Array(20).fill(0),
    merkleRoot: "123456789123456789123456789",
  };

  const scheme: "groth16" | "plonk" = "groth16";
  const { proof, publicSignals } = generateProofOffline(scheme, inputData);

  console.log("PROOF:", JSON.stringify(proof, null, 2));
  console.log("PUBLIC SIGNALS:", publicSignals);
}
