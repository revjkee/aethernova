// hr_ai/governance/zk_voting/proofs/generate_vote_proof.js

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

async function generateVoteProof(inputJsonPath, outputDir) {
  const input = JSON.parse(fs.readFileSync(inputJsonPath));
  const wasmPath = path.join(__dirname, "semaphore_vote.wasm");
  const zkeyPath = path.join(__dirname, "final.zkey");
  const proofPath = path.join(outputDir, "proof.json");
  const publicPath = path.join(outputDir, "public.json");

  try {
    console.log(`[+] Loading inputs from: ${inputJsonPath}`);
    console.log(`[+] Generating witness...`);

    const {witnessCalculator} = require("./witness_calculator.js");
    const wasmBuffer = fs.readFileSync(wasmPath);
    const wc = await witnessCalculator(wasmBuffer);
    const witness = await wc.calculateWTNSBin(input, 0);

    const witnessFile = path.join(outputDir, "witness.wtns");
    fs.writeFileSync(witnessFile, witness);

    console.log(`[+] Witness written to: ${witnessFile}`);
    console.log(`[+] Generating proof...`);

    const {proof, publicSignals} = await snarkjs.groth16.prove(zkeyPath, witnessFile);

    fs.writeFileSync(proofPath, JSON.stringify(proof, null, 2));
    fs.writeFileSync(publicPath, JSON.stringify(publicSignals, null, 2));

    console.log(`[✓] Proof generated: ${proofPath}`);
    console.log(`[✓] Public signals: ${publicPath}`);
  } catch (err) {
    console.error(`[!] Error during proof generation: ${err.message}`);
    process.exit(1);
  }
}

// Run from CLI
if (require.main === module) {
  const [,, inputJsonPath, outputDir] = process.argv;
  if (!inputJsonPath || !outputDir) {
    console.error("Usage: node generate_vote_proof.js <input.json> <outputDir>");
    process.exit(1);
  }
  generateVoteProof(inputJsonPath, outputDir);
}
