import fs from "fs";
import path from "path";
import { groth16, plonk } from "snarkjs";

type Scheme = "groth16" | "plonk";

interface ProofInput {
  proofPath: string;
  publicPath: string;
  vkeyPath: string;
  scheme: Scheme;
}

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

async function verifyProof({ proofPath, publicPath, vkeyPath, scheme }: ProofInput): Promise<boolean> {
  const proof = readJson(proofPath);
  const publicSignals = readJson(publicPath);
  const vkey = readJson(vkeyPath);

  switch (scheme) {
    case "groth16":
      return await groth16.verify(vkey, publicSignals, proof);
    case "plonk":
      return await plonk.verify(vkey, publicSignals, proof);
    default:
      throw new Error(`Unknown scheme: ${scheme}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const scheme: Scheme = args[0] as Scheme;

  const proofFile = args[1] || `../temp/proof.json`;
  const publicFile = args[2] || `../temp/public.json`;
  const vkeyFile = args[3] || `../circuits/verification_key_${scheme}.json`;

  if (!["groth16", "plonk"].includes(scheme)) {
    console.error("Usage: ts-node verify_proof.ts <groth16|plonk> [proof.json] [public.json] [vkey.json]");
    process.exit(1);
  }

  try {
    const result = await verifyProof({
      scheme,
      proofPath: proofFile,
      publicPath: publicFile,
      vkeyPath: vkeyFile
    });

    if (result) {
      console.log(`[✓] ${scheme.toUpperCase()} proof verified successfully.`);
    } else {
      console.error(`[✗] ${scheme.toUpperCase()} proof verification failed.`);
      process.exit(2);
    }
  } catch (err) {
    console.error(`[!] Error verifying proof:`, err.message);
    process.exit(3);
  }
}

if (require.main === module) {
  main();
}
