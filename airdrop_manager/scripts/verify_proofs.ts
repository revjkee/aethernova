// airdrop_manager/scripts/verify_proofs.ts
/**
 * Industrial Merkle & ZK proof verifier for airdrops.
 *
 * Features
 * - Merkle proof verification (OpenZeppelin-compatible): sorted pairs by default.
 * - Leaf hashing schema: keccak256(abi.encodePacked(address,uint256)) by default.
 * - Optional on-chain root fetch via JSON-RPC (EIP-1474).
 * - Optional Groth16 verification using snarkjs (dynamic import).
 * - EIP-55 checksum normalization for addresses.
 * - Batch input (array) or single object; NDJSON is also supported.
 * - Deterministic JSON result to stdout; exit code != 0 on any failure.
 *
 * References
 * - Solidity keccak256 / abi.encodePacked + collision note: https://docs.soliditylang.org/en/latest/abi-spec.html
 *   and example usage with encodePacked: https://docs.soliditylang.org/en/latest/control-structures.html  // keccak256(...abi.encodePacked(...)) :contentReference[oaicite:1]{index=1}
 * - OpenZeppelin MerkleProof (verify/processProof): https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof  :contentReference[oaicite:2]{index=2}
 * - ethers v6 keccak256 / crypto utils: https://docs.ethers.org/v6/api/crypto/ and hashing utilities: https://docs.ethers.org/v6/api/hashing/  :contentReference[oaicite:3]{index=3}
 * - EIP-55 checksum addresses: https://eips.ethereum.org/EIPS/eip-55  :contentReference[oaicite:4]{index=4}
 * - JSON-RPC (EIP-1474): https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1474.md  :contentReference[oaicite:5]{index=5}
 * - snarkjs Groth16 (optional): https://github.com/iden3/snarkjs and Circom docs verify command  :contentReference[oaicite:6]{index=6}
 */

import * as fs from "node:fs";
import * as path from "node:path";

// ethers v6 API
import {
  Contract,
  JsonRpcProvider,
  getAddress,
  isAddress,
  getBytes,
  hexlify,
  keccak256,
  concat,
  toBeHex,
} from "ethers";

// ----------------------------- Types -----------------------------------------

type LeafEncoding =
  | "address_uint256"         // keccak256( addr[20] || uint256[32] )  (abi.encodePacked)
  | "address_uint128"         // keccak256( addr[20] || uint128[16] )
  | "bytes32_uint256";        // keccak256( bytes32[32] || uint256[32] )

type ProofItem = string; // 0x-prefixed 32-byte hex
type Hex32 = string;

interface MerkleProofInput {
  address?: string;           // for address_* schemas
  account?: string;           // alias for address
  node?: string;              // for bytes32_* schema
  amount?: string | number;   // decimal or hex string
  value?: string | number;    // alias for amount
  proof: ProofItem[];
  root?: string;
  leafEncoding?: LeafEncoding;
  sortedPairs?: boolean;      // default: true (OpenZeppelin)
  comment?: string;           // optional label
}

interface CliArgs {
  proofFile?: string;         // JSON | NDJSON
  root?: string;              // hex root override
  rpcUrl?: string;            // JSON-RPC URL
  contract?: string;          // contract address holding root
  rootFn?: string;            // function name that returns bytes32 (default tries merkleRoot(), root())
  abiFile?: string;           // custom ABI file (if not provided uses minimal)
  sorted?: boolean;           // override pair sorting
  encoding?: LeafEncoding;    // override leaf encoding
  zkProof?: string;           // path to proof.json
  zkPublic?: string;          // path to public.json
  zkVkey?: string;            // path to verification_key.json
}

// --------------------------- Utilities ---------------------------------------

function readJson<T = any>(p: string): T {
  const raw = fs.readFileSync(p, "utf-8");
  return JSON.parse(raw) as T;
}

function* readNdjson(p: string): Generator<any> {
  const raw = fs.readFileSync(p, "utf-8");
  for (const line of raw.split(/\r?\n/)) {
    const l = line.trim();
    if (!l) continue;
    yield JSON.parse(l);
  }
}

function ensureHex32(x: string, label: string): Hex32 {
  if (typeof x !== "string" || !x.startsWith("0x") || (x.length !== 66)) {
    throw new Error(`Invalid ${label}: expected 0x + 64 hex chars`);
  }
  return x.toLowerCase();
}

function normalizeAddress(addr?: string): string | undefined {
  if (!addr) return undefined;
  if (!isAddress(addr)) throw new Error(`Invalid address: ${addr}`);
  // EIP-55 checksum normalization
  return getAddress(addr);
}

// Convert decimal/hex amount to 32-byte big-endian hex (0x + 64)
function amountToUintBE32(amount?: string | number): string {
  if (amount === undefined || amount === null) {
    throw new Error("amount/value is required for address_* or bytes32_uint256 encodings");
  }
  let bi: bigint;
  if (typeof amount === "number") {
    if (!Number.isFinite(amount) || amount < 0) throw new Error("Invalid amount number");
    bi = BigInt(amount);
  } else {
    const s = amount.trim();
    bi = s.startsWith("0x") ? BigInt(s) : BigInt(s);
  }
  if (bi < 0n) throw new Error("Negative amount not supported");
  return toBeHex(bi, 32); // zero-padded to 32 bytes (ethers v6)
}

// Compute leaf hash according to encoding
function computeLeaf(input: MerkleProofInput, encoding?: LeafEncoding): Hex32 {
  const enc: LeafEncoding = encoding || input.leafEncoding || "address_uint256";
  const addr = normalizeAddress(input.address ?? input.account);
  const amt = input.amount ?? input.value;

  switch (enc) {
    case "address_uint256": {
      if (!addr) throw new Error("address/account is required for address_uint256");
      const addrBytes = getBytes(addr); // 20 bytes
      const amt32 = getBytes(amountToUintBE32(amt)); // 32 bytes
      return keccak256(concat([addrBytes, amt32]));
    }
    case "address_uint128": {
      if (!addr) throw new Error("address/account is required for address_uint128");
      const addrBytes = getBytes(addr); // 20
      // pack amount into 16 bytes (high-truncated, check bounds)
      const amtHex = toBeHex(BigInt(amt as any), 16);
      const amt16 = getBytes(amtHex);
      return keccak256(concat([addrBytes, amt16]));
    }
    case "bytes32_uint256": {
      const node = input.node;
      if (!node) throw new Error("node (bytes32) is required for bytes32_uint256");
      const node32 = getBytes(ensureHex32(node, "node"));
      const amt32 = getBytes(amountToUintBE32(amt));
      return keccak256(concat([node32, amt32]));
    }
    default:
      throw new Error(`Unknown leafEncoding: ${enc}`);
  }
}

// Compare two 32-byte hashes lexicographically (by bytes)
function lessEq(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < 32; i++) {
    if (a[i] < b[i]) return true;
    if (a[i] > b[i]) return false;
  }
  return true;
}

function verifyMerkleProof(
  leaf: Hex32,
  proof: ProofItem[],
  root: Hex32,
  sortedPairs = true
): { ok: boolean; computed: Hex32 } {
  let computed = leaf;
  for (const p of proof) {
    const ph = ensureHex32(p, "proof item");
    if (sortedPairs) {
      const a = getBytes(computed);
      const b = getBytes(ph);
      const [l, r] = lessEq(a, b) ? [a, b] : [b, a];
      computed = keccak256(concat([l, r]));
    } else {
      computed = keccak256(concat([getBytes(computed), getBytes(ph)]));
    }
  }
  return { ok: ensureHex32(computed, "computed") === ensureHex32(root, "root"), computed };
}

// Fetch root from contract via JSON-RPC
async function fetchOnChainRoot(
  rpcUrl: string,
  contract: string,
  rootFn?: string,
  abiFile?: string
): Promise<Hex32> {
  const provider = new JsonRpcProvider(rpcUrl);
  const addr = normalizeAddress(contract)!;

  // Minimal ABI candidates if not supplied
  const fallbackAbi = [
    { inputs: [], name: "merkleRoot", outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }], stateMutability: "view", type: "function" },
    { inputs: [], name: "root",       outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }], stateMutability: "view", type: "function" },
  ];
  const abi = abiFile ? readJson<any[]>(abiFile) : fallbackAbi;

  const c = new Contract(addr, abi, provider);

  // If function specified, call it; otherwise try common names
  const candidates = rootFn ? [rootFn] : ["merkleRoot", "root"];
  for (const fn of candidates) {
    if (typeof (c as any)[fn] === "function") {
      const v = await (c as any)[fn]();
      return ensureHex32(hexlify(v), "on-chain root");
    }
  }
  throw new Error(`No suitable function to read root. Tried: ${candidates.join(", ")}`);
}

// Optional zkSNARK verification (Groth16) via snarkjs
async function verifyGroth16(zkVkey: string, zkPublic: string, zkProof: string): Promise<boolean> {
  // dynamic import to avoid hard dependency
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const snarkjs = await import("snarkjs"); // requires snarkjs installed
  const vkey = readJson<any>(zkVkey);
  const pub = readJson<any>(zkPublic);
  const proof = readJson<any>(zkProof);
  // snarkjs.groth16.verify(vkey, publicSignals, proof)
  return await (snarkjs as any).groth16.verify(vkey, pub, proof);
}

// ------------------------------ CLI ------------------------------------------

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => (i + 1 < argv.length ? argv[i + 1] : undefined);
    switch (a) {
      case "--proof-file": args.proofFile = next(); i++; break;
      case "--root": args.root = next(); i++; break;
      case "--rpc-url": args.rpcUrl = next(); i++; break;
      case "--contract": args.contract = next(); i++; break;
      case "--root-fn": args.rootFn = next(); i++; break;
      case "--abi-file": args.abiFile = next(); i++; break;
      case "--sorted": args.sorted = true; break;
      case "--unsorted": args.sorted = false; break;
      case "--encoding": args.encoding = next() as LeafEncoding; i++; break;
      case "--zk-proof": args.zkProof = next(); i++; break;
      case "--zk-public": args.zkPublic = next(); i++; break;
      case "--zk-vkey": args.zkVkey = next(); i++; break;
      case "-h":
      case "--help":
        printHelp(); process.exit(0);
      default:
        if (a.startsWith("-")) {
          throw new Error(`Unknown flag: ${a}`);
        }
    }
  }
  return args;
}

function printHelp() {
  console.log(`Usage:
  ts-node scripts/verify_proofs.ts --proof-file ./proof.json --root 0x...
  ts-node scripts/verify_proofs.ts --proof-file ./batch.json --rpc-url https://... --contract 0x... [--root-fn merkleRoot]
  ts-node scripts/verify_proofs.ts --proof-file ./proof.ndjson --encoding address_uint256 --sorted
  ts-node scripts/verify_proofs.ts --zk-vkey vkey.json --zk-public public.json --zk-proof proof.json

Input JSON (single):
{
  "address": "0xabc...def",
  "amount": "1000000000000000000",
  "proof": ["0x...", "..."],
  "root": "0x...",                     // optional; otherwise --root or on-chain
  "leafEncoding": "address_uint256",   // optional
  "sortedPairs": true                  // optional
}

Input JSON (batch): [ {...}, {...} ]
NDJSON: one JSON object per line.

Leaf encodings:
- address_uint256 (default)
- address_uint128
- bytes32_uint256
`);
}

// ------------------------------ Main -----------------------------------------

async function main() {
  const args = parseArgs(process.argv);

  if (!args.proofFile) {
    printHelp();
    throw new Error("--proof-file is required");
  }
  const filePath = path.resolve(args.proofFile);
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);

  // Load inputs: single JSON, array JSON, or NDJSON
  let items: MerkleProofInput[] = [];
  if (filePath.endsWith(".ndjson")) {
    items = Array.from(readNdjson(filePath)) as MerkleProofInput[];
  } else {
    const j = readJson<any>(filePath);
    items = Array.isArray(j) ? (j as MerkleProofInput[]) : [j as MerkleProofInput];
  }
  if (items.length === 0) throw new Error("No proof items found");

  // Resolve root: priority = input.root (per item) -> CLI --root -> on-chain (if rpc+contract)
  let onChainRoot: string | undefined = undefined;
  if (!args.root && args.rpcUrl && args.contract) {
    onChainRoot = await fetchOnChainRoot(args.rpcUrl, args.contract, args.rootFn, args.abiFile);
  }

  // Optional ZK verification (Groth16)
  let zkOk: boolean | undefined = undefined;
  if (args.zkVkey || args.zkPublic || args.zkProof) {
    if (!(args.zkVkey && args.zkPublic && args.zkProof)) {
      throw new Error("For ZK verification provide all of --zk-vkey, --zk-public, --zk-proof");
    }
    zkOk = await verifyGroth16(args.zkVkey, args.zkPublic, args.zkProof);
  }

  const results = [];
  let failures = 0;

  for (const [idx, it] of items.entries()) {
    const encoding = (args.encoding || it.leafEncoding) as LeafEncoding | undefined;
    const sortedPairs = (typeof args.sorted === "boolean" ? args.sorted : (it.sortedPairs ?? true));
    let leaf: string;
    let root: string;

    try {
      leaf = computeLeaf(it, encoding);
      const rootSrc = it.root || args.root || onChainRoot;
      if (!rootSrc) throw new Error("No root provided (item.root or --root or RPC/contract)");
      root = ensureHex32(rootSrc, "root");

      const { ok, computed } = verifyMerkleProof(leaf, it.proof || [], root, sortedPairs);
      if (!ok) failures++;

      results.push({
        index: idx,
        ok,
        comment: it.comment || null,
        address: it.address ?? it.account ?? null,
        amount: it.amount ?? it.value ?? null,
        encoding: encoding || "address_uint256",
        sortedPairs,
        leaf,
        computedRoot: computed,
        expectedRoot: root,
        sourceRoot: it.root ? "input" : (args.root ? "cli" : "on-chain"),
      });
    } catch (e: any) {
      failures++;
      results.push({
        index: idx,
        ok: false,
        error: `${e?.name || "Error"}: ${e?.message || String(e)}`,
        comment: it.comment || null,
        address: it.address ?? it.account ?? null,
        amount: it.amount ?? it.value ?? null,
      });
    }
  }

  const out = {
    file: filePath,
    count: items.length,
    failures,
    zkChecked: zkOk !== undefined,
    zkValid: zkOk ?? null,
    timestamp: new Date().toISOString(),
    results,
  };

  // Print deterministic JSON
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  if (failures > 0 || zkOk === false) process.exit(2);
}

main().catch((err) => {
  process.stderr.write(JSON.stringify({ ok: false, error: `${err?.name || "Error"}: ${err?.message || String(err)}` }) + "\n");
  process.exit(1);
});
