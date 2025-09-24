// airdrop_manager/scripts/generate_merkle_tree.ts
/* eslint-disable no-console */
/**
 * Industrial-grade Merkle tree generator for token airdrops.
 * - Input: JSON (array or mapping) or CSV
 * - Leaf encoder: solidityPacked(["address","uint256"]) by default
 * - Hash: keccak256 (ethers v6)
 * - Pair hashing: sorted pairs (default) or left-right
 * - Odd duplication: duplicate last (default) or carry
 * - Dedupe strategy: error | sum | last
 * - Outputs:
 *    out/merkle-root.json
 *    out/claims.json      -> { claims: { [address]: { amount, proof[] } } }
 *    out/leaves.json      -> [ { address, amount, leaf } ]
 *    out/summary.txt
 *
 * Usage:
 *   ts-node scripts/generate_merkle_tree.ts \
 *     --input holders.json \
 *     --out out \
 *     --schema address,uint256 \
 *     --addr-key address --amt-key amount \
 *     --sorted-pairs --duplicate-odd \
 *     --dedupe error --decimals 0 \
 *     --salt "airdrop:v1:chain=1:token=0x..." \
 *     --format json
 */

import { promises as fs } from "fs";
import * as path from "path";
import { Command } from "commander";
import {
  keccak256,
  getAddress,
  isAddress,
  solidityPacked,
  parseUnits,
  arrayify,
  concat,
} from "ethers";

// -------------------------------
// Types
// -------------------------------
type Address = string;

interface RawClaim {
  [k: string]: unknown;
}

interface NormalizedClaim {
  address: Address;
  amount: string; // integer string (wei-style after decimals applied)
}

interface ClaimsMap {
  [addr: Address]: { amount: string; proof: string[] };
}

interface RootFile {
  merkleRoot: string;
  leafCount: number;
  schema: { types: string[]; fields: string[] };
  salt?: string | null;
  hashFunction: "keccak256";
  pairSorting: boolean;
  duplicateOdd: boolean;
  dedupe: "error" | "sum" | "last";
}

interface CLIOptions {
  input: string;
  out: string;
  format?: "json" | "csv";
  addrKey: string;
  amtKey: string;
  schema: string; // e.g. "address,uint256"
  decimals: number;
  sortedPairs: boolean;
  duplicateOdd: boolean;
  sortLeaves: boolean;
  dedupe: "error" | "sum" | "last";
  delimiter: string;
  salt?: string;
  includeLayers?: boolean;
}

// -------------------------------
// CLI
// -------------------------------
const program = new Command();
program
  .requiredOption("-i, --input <file>", "Input file: JSON or CSV")
  .option("-o, --out <dir>", "Output directory", "out")
  .option("-f, --format <fmt>", "Input format: json|csv (auto by ext if omitted)")
  .option("--addr-key <key>", "Key name for address (JSON/CSV header)", "address")
  .option("--amt-key <key>", "Key name for amount  (JSON/CSV header)", "amount")
  .option("--schema <types>", 'Solidity types for leaf, default "address,uint256"', "address,uint256")
  .option("--decimals <n>", "If amounts are human-readable, convert with given decimals", parseInt as any, 0)
  .option("--sorted-pairs", "Sort sibling pair at each level before hashing", true as any)
  .option("--no-sorted-pairs", "Disable sorted pairs")
  .option("--duplicate-odd", "Duplicate last node on odd count", true as any)
  .option("--no-duplicate-odd", "Do not duplicate last node on odd count")
  .option("--sort-leaves", "Sort leaves by hex before tree build (deterministic)", false as any)
  .option("--dedupe <mode>", "Duplicate address strategy: error|sum|last", "error")
  .option("--delimiter <char>", "CSV delimiter", ",")
  .option("--salt <string>", "Domain-separation salt, included BEFORE encoded fields")
  .option("--include-layers", "Write full layers to out/tree.json (debug, large!)", false as any);

program.parse(process.argv);
const opts = program.opts<CLIOptions>();

// -------------------------------
// Helpers
// -------------------------------
function ensureHex32(x: string): string {
  if (!/^0x[0-9a-fA-F]{64}$/.test(x)) {
    throw new Error(`Expected 0x-prefixed 32-byte hex, got: ${x}`);
  }
  return x.toLowerCase();
}

function checksum(addr: string): Address {
  if (!isAddress(addr)) throw new Error(`Invalid address: ${addr}`);
  return getAddress(addr);
}

function parseAmount(raw: unknown, decimals: number): string {
  if (typeof raw === "number") {
    if (!Number.isFinite(raw)) throw new Error(`Invalid amount: ${raw}`);
    // numbers may be unsafe if big; convert via string
    raw = String(raw);
  }
  if (typeof raw !== "string") throw new Error(`Amount must be string/number, got ${typeof raw}`);
  raw = raw.trim();
  if (decimals > 0) {
    // human -> integer units via ethers parseUnits
    return parseUnits(raw, decimals).toString();
  }
  // integer string expected (no decimals)
  if (!/^[0-9]+$/.test(raw)) throw new Error(`Non-integer amount without --decimals: ${raw}`);
  return raw;
}

function encodeLeaf(
  types: string[],
  values: unknown[],
  salt?: string
): string {
  const packed = salt
    ? solidityPacked(["string", ...types], [salt, ...values])
    : solidityPacked(types, values);
  return keccak256(packed);
}

function hashPair(a: string, b: string, sortedPairs: boolean): string {
  const [x, y] = sortedPairs
    ? [a, b].sort((m, n) => (m.toLowerCase() < n.toLowerCase() ? -1 : m.toLowerCase() > n.toLowerCase() ? 1 : 0))
    : [a, b];
  return keccak256(concat([arrayify(x), arrayify(y)]));
}

// -------------------------------
// CSV Parser (robust enough for common cases: quotes + delimiter)
// -------------------------------
function parseCSV(text: string, delimiter: string): RawClaim[] {
  const rows: string[][] = [];
  let cur = "";
  let row: string[] = [];
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (ch === '"') {
      if (inQuotes && text[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (!inQuotes && (ch === "\n" || ch === "\r")) {
      if (cur.length || row.length) {
        row.push(cur);
        rows.push(row);
        row = [];
        cur = "";
      }
      // eat \r\n pairs
      if (ch === "\r" && text[i + 1] === "\n") i++;
      continue;
    }

    if (!inQuotes && ch === delimiter) {
      row.push(cur);
      cur = "";
      continue;
    }

    cur += ch;
  }
  if (cur.length || row.length) {
    row.push(cur);
    rows.push(row);
  }

  if (rows.length === 0) return [];

  const header = rows[0].map((h) => h.trim());
  const data = rows.slice(1).filter((r) => r.some((c) => c.trim().length > 0));

  return data.map((r) => {
    const obj: RawClaim = {};
    for (let i = 0; i < header.length; i++) {
      obj[header[i]] = (r[i] ?? "").trim();
    }
    return obj;
  });
}

// -------------------------------
// Input loading & normalization
// -------------------------------
async function loadRawClaims(file: string, fmt?: "json" | "csv", delimiter = ","): Promise<RawClaim[]> {
  const content = await fs.readFile(file, "utf8");
  const ext = path.extname(file).toLowerCase().replace(".", "");
  const format = fmt ?? ((ext === "csv" || ext === "tsv") ? "csv" : "json");

  if (format === "csv") {
    return parseCSV(content, delimiter);
  }

  // JSON
  const data = JSON.parse(content);

  // Supported shapes:
  // 1) [{address, amount}, ...]
  // 2) {"0xAddr1": "123", "0xAddr2": "456", ...}
  // 3) {"claims": {...}} or {"holders": [...]}
  if (Array.isArray(data)) {
    return data as RawClaim[];
  } else if (typeof data === "object" && data !== null) {
    if (Array.isArray((data as any).claims)) return (data as any).claims as RawClaim[];
    if (Array.isArray((data as any).holders)) return (data as any).holders as RawClaim[];
    // mapping address->amount
    const obj = data as Record<string, unknown>;
    const asArray: RawClaim[] = [];
    for (const [k, v] of Object.entries(obj)) {
      asArray.push({ address: k, amount: v as any });
    }
    return asArray;
  }
  throw new Error("Unsupported JSON structure");
}

function normalizeClaims(
  raws: RawClaim[],
  addrKey: string,
  amtKey: string,
  decimals: number,
  dedupe: "error" | "sum" | "last"
): NormalizedClaim[] {
  const map = new Map<Address, bigint>();

  for (const r of raws) {
    const rawAddr = String(r[addrKey] ?? "").trim();
    const rawAmt = r[amtKey];

    if (!rawAddr) throw new Error(`Missing address at row: ${JSON.stringify(r)}`);
    const addr = checksum(rawAddr);
    const amt = BigInt(parseAmount(rawAmt, decimals));
    if (amt < 0n) throw new Error(`Negative amount for ${addr}`);

    if (!map.has(addr)) {
      map.set(addr, amt);
      continue;
    }
    // duplicate handling
    if (dedupe === "error") {
      throw new Error(`Duplicate address found: ${addr}`);
    } else if (dedupe === "sum") {
      map.set(addr, map.get(addr)! + amt);
    } else if (dedupe === "last") {
      map.set(addr, amt);
    } else {
      throw new Error(`Unknown dedupe mode: ${dedupe}`);
    }
  }

  return [...map.entries()].map(([address, amount]) => ({ address, amount: amount.toString() }));
}

// -------------------------------
// Merkle tree
// -------------------------------
function buildLeaves(
  claims: NormalizedClaim[],
  types: string[],
  fields: string[],
  salt?: string
): { leaves: string[]; leafMeta: { address: Address; amount: string; leaf: string }[] } {
  const leaves: string[] = [];
  const meta: { address: Address; amount: string; leaf: string }[] = [];

  for (const c of claims) {
    // Map values according to fields order; supported minimal set: address, amount
    const values: unknown[] = fields.map((f) => {
      if (f === "address") return c.address;
      if (f === "amount") return BigInt(c.amount);
      // passthrough or empty
      return (c as any)[f];
    });

    const leaf = encodeLeaf(types, values, salt);
    leaves.push(leaf);
    meta.push({ address: c.address, amount: c.amount, leaf });
  }
  return { leaves, leafMeta: meta };
}

function buildMerkleTree(
  leaves: string[],
  sortedPairs: boolean,
  duplicateOdd: boolean,
  sortLeaves: boolean
): { root: string; layers: string[][] } {
  if (leaves.length === 0) {
    // keccak256 of empty bytes by convention could be used; safer to throw here.
    throw new Error("No leaves to build the tree");
  }

  const layers: string[][] = [];
  let level = sortLeaves ? [...leaves].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)) : [...leaves];
  layers.push(level);

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1];
      if (right === undefined) {
        if (duplicateOdd) {
          next.push(hashPair(left, left, sortedPairs));
        } else {
          // carry
          next.push(left);
        }
      } else {
        next.push(hashPair(left, right, sortedPairs));
      }
    }
    level = next;
    layers.push(level);
  }

  const root = ensureHex32(layers[layers.length - 1][0]);
  return { root, layers };
}

function getProofForIndex(
  index: number,
  layers: string[][],
  duplicateOdd: boolean,
  sortedPairs: boolean
): string[] {
  const proof: string[] = [];
  let idx = index;

  for (let level = 0; level < layers.length - 1; level++) {
    const cur = layers[level];
    const isRight = idx % 2 === 1;
    const pairIndex = isRight ? idx - 1 : idx + 1;

    if (pairIndex < cur.length) {
      proof.push(cur[pairIndex]);
    } else if (pairIndex >= cur.length && duplicateOdd) {
      // duplicate last
      proof.push(cur[idx]);
    } else {
      // carried node, no sibling at this level
    }
    idx = Math.floor(idx / 2);
  }

  // sanity: ensure all proof elements are 32-byte hex
  return proof.map(ensureHex32);
}

// -------------------------------
// Main
// -------------------------------
(async () => {
  const {
    input,
    out,
    format,
    addrKey,
    amtKey,
    schema,
    decimals,
    sortedPairs,
    duplicateOdd,
    sortLeaves,
    dedupe,
    delimiter,
    salt,
    includeLayers,
  } = opts;

  await fs.mkdir(out, { recursive: true });

  // Parse schema
  const types = schema.split(",").map((s) => s.trim()).filter(Boolean);
  const fields = types.map((t) => {
    // minimal mapping heuristic
    if (t === "address") return "address";
    if (t === "uint256" || t === "uint" || t.endsWith("256")) return "amount";
    return t; // user-provided custom key name must exist in input
  });

  // Load and normalize
  const raws = await loadRawClaims(input, format, delimiter);
  const claims = normalizeClaims(raws, addrKey, amtKey, decimals, dedupe);

  // Build leaves
  const { leaves, leafMeta } = buildLeaves(claims, types, fields, salt);

  // Build tree
  const { root, layers } = buildMerkleTree(leaves, sortedPairs, duplicateOdd, sortLeaves);

  // Build proofs map
  const claimsMap: ClaimsMap = {};
  // Address order must match leaf indices construction
  const addrToIndex = new Map<Address, number>();
  for (let i = 0; i < leafMeta.length; i++) {
    addrToIndex.set(leafMeta[i].address, i);
  }

  for (let i = 0; i < leafMeta.length; i++) {
    const { address, amount } = leafMeta[i];
    const proof = getProofForIndex(i, layers, duplicateOdd, sortedPairs);
    claimsMap[address] = { amount, proof };
  }

  // Write outputs
  const rootFile: RootFile = {
    merkleRoot: root,
    leafCount: leaves.length,
    schema: { types, fields },
    salt: salt ?? null,
    hashFunction: "keccak256",
    pairSorting: !!sortedPairs,
    duplicateOdd: !!duplicateOdd,
    dedupe,
  };

  await fs.writeFile(path.join(out, "merkle-root.json"), JSON.stringify(rootFile, null, 2), "utf8");
  await fs.writeFile(path.join(out, "claims.json"), JSON.stringify({ claims: claimsMap }, null, 2), "utf8");
  await fs.writeFile(path.join(out, "leaves.json"), JSON.stringify(leafMeta, null, 2), "utf8");

  if (includeLayers) {
    await fs.writeFile(path.join(out, "tree.json"), JSON.stringify({ layers }, null, 2), "utf8");
  }

  const total = claims.reduce((acc, c) => acc + BigInt(c.amount), 0n);
  const summary = [
    `Merkle Root: ${root}`,
    `Leaves: ${leaves.length}`,
    `Total amount (integer units): ${total.toString()}`,
    `Schema: ${types.join(", ")}  fields: ${fields.join(", ")}`,
    `Salt: ${salt ?? "(none)"}`,
    `Sorted pairs: ${sortedPairs}  Duplicate odd: ${duplicateOdd}  Sort leaves: ${sortLeaves}`,
    `Dedupe: ${dedupe}`,
    `Input: ${input}`,
    `Outputs: ${path.resolve(out)}/merkle-root.json, claims.json, leaves.json${includeLayers ? ", tree.json" : ""}`,
  ].join("\n");

  await fs.writeFile(path.join(out, "summary.txt"), summary + "\n", "utf8");

  console.log(summary);
})().catch((err) => {
  console.error(`Error: ${err?.message || String(err)}`);
  process.exit(1);
});
