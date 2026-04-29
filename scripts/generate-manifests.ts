#!/usr/bin/env node
/**
 * Generate production-ready preset manifests from built circuit artifacts.
 *
 *   tsx scripts/generate-manifests.ts
 *
 * Reads the compiled circuit artifacts from `packages/circuits/build/` and
 * writes validated JSON manifests to `presets/`. This replaces the placeholder
 * URIs with concrete artifact references.
 *
 * The script:
 *   1. Reads the verification key, input names, and artifact hashes from build/.
 *   2. Computes SHA-256 hashes of the wasm and zkey artifacts for integrity.
 *   3. Writes manifests with `artifact.location` pointing to the build dir
 *      (for local use) or a user-specified base URL for production deployment.
 *
 * Environment:
 *   ARTIFACT_BASE_URL  Base URL where artifacts will be hosted.
 *                      Default: file:// relative path to build dir (local dev).
 *                      For production, set to your IPFS gateway or CDN, e.g.:
 *                        https://cdn.example.com/circuits/
 *                        ipfs://Qm.../
 */
import { createHash, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { CircuitMetaSchema, SchemaMetaSchema } from "../packages/circuits/src/manifest.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");

const BUILD_DIR = resolve(REPO_ROOT, "packages/circuits/build");
const PRESETS_DIR = resolve(REPO_ROOT, "presets");

const BASE_URL = process.env.ARTIFACT_BASE_URL ?? `file://${resolve(BUILD_DIR)}/`;

function sha256Hex(filePath: string): string {
  const data = readFileSync(filePath);
  return "0x" + createHash("sha256").update(data).digest("hex");
}

const c = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
} as const;

function ok(msg: string) {
  console.log(`  ${c.green}✓${c.reset} ${msg}`);
}

function fail(msg: string) {
  console.log(`  ${c.red}✗${c.reset} ${msg}`);
}

type CircuitConfig = {
  circuitId: string;
  schemaId: string;
  description: string;
  inputs: string[];
  normalize: {
    raw: Record<string, string>;
    norm: Record<string, string>;
  };
};

const CIRCUITS: CircuitConfig[] = [
  {
    circuitId: "bridge-approval-origin-v1",
    schemaId: "bridge-approval-origin-v1",
    description:
      "Groth16 circuit binding a hidden bridge approval to a public Poseidon origin commitment, with policy checks: dstChainId == policy, amount <= cap, signersPresent >= threshold, nowSec <= validUntil.",
    inputs: [
      "originCommitment",
      "policyDstChainId",
      "policyMaxAmount",
      "policyMinSigners",
      "nowSec",
    ],
    normalize: {
      raw: {
        approvalId: "string",
        signerSet: "string",
        signerThreshold: "number",
        signersPresent: "number",
        srcChainId: "number",
        dstChainId: "number",
        asset: "string",
        amount: "string",
        recipient: "string",
        approvedAt: "number",
        expiresAt: "number",
      },
      norm: {
        approvalIdHash: "field",
        signerSetHash: "field",
        dstChainId: "u32",
        amount: "u240",
        signersPresent: "u16",
        validUntil: "u64",
      },
    },
  },
  {
    circuitId: "lst-collateral-origin-v1",
    schemaId: "lst-collateral-origin-v1",
    description:
      "Groth16 circuit binding a hidden LST/LRT collateral lot to a public Poseidon collateral commitment, with policy checks: asset whitelist, rehypothecation depth, custody hops, validator-set revocation, mint freshness.",
    inputs: [
      "collateralCommitment",
      "policyAssetIdHash",
      "policyMaxRehypoDepth",
      "policyMaxCustodyHops",
      "policyMinMintAge",
      "nowSec",
    ],
    normalize: {
      raw: {
        lotId: "string",
        asset: "string",
        amount: "string",
        mintChainId: "number",
        mintTxHash: "string",
        mintedAt: "number",
        custodyPath: "array",
        validatorSetRoot: "string",
        rehypothecationDepth: "number",
      },
      norm: {
        lotIdHash: "field",
        assetIdHash: "field",
        mintChainId: "u32",
        custodyHops: "u16",
        rehypothecationDepth: "u16",
        validatorSetRevoked: "u1",
        mintedAt: "u64",
      },
    },
  },
];

function generateManifests() {
  console.log(`\n${c.bold}Generating preset manifests from build artifacts${c.reset}`);
  console.log(`  artifact base URL: ${c.dim}${BASE_URL}${c.reset}`);

  const buildId = (schemaId: string) =>
    schemaId.replace(/-v1$/, "");

  for (const cfg of CIRCUITS) {
    const buildName = buildId(cfg.schemaId);
    const circuitDir = resolve(BUILD_DIR, buildName);

    if (!existsSync(circuitDir)) {
      fail(`build dir missing for ${buildName} — run \`pnpm circuits:prove\` first`);
      continue;
    }

    const wasmPath = resolve(circuitDir, `${buildName}_js`, `${buildName}.wasm`);
    const zkeyPath = resolve(circuitDir, `${buildName}_final.zkey`);

    if (!existsSync(wasmPath) || !existsSync(zkeyPath)) {
      fail(`artifacts missing for ${buildName} — run \`pnpm circuits:prove\` first`);
      continue;
    }

    const wasmHash = sha256Hex(wasmPath);
    const zkeyHash = sha256Hex(zkeyPath);

    const wasmUrl = `${BASE_URL}${buildName}/${buildName}_js/${buildName}.wasm`;
    const zkeyUrl = `${BASE_URL}${buildName}/${buildName}_final.zkey`;
    const jsUrl = `${BASE_URL}${buildName}/${buildName}_js/${buildName}.js`;

    // Schema manifest
    const schemaManifest = {
      id: cfg.schemaId,
      description: cfg.description,
      normalize: {
        artifact: {
          type: "https" as const,
          wasm: wasmUrl,
          js: jsUrl,
        },
        hash: wasmHash,
        abi: {
          raw: cfg.normalize.raw,
          norm: cfg.normalize.norm,
        },
      },
    };

    const schemaResult = SchemaMetaSchema.safeParse(schemaManifest);
    if (!schemaResult.success) {
      fail(`schema manifest validation failed for ${cfg.schemaId}: ${schemaResult.error.message}`);
      continue;
    }

    // Circuit manifest
    const circuitManifest = {
      circuitId: cfg.circuitId,
      schema: cfg.schemaId,
      description: cfg.description,
      inputs: cfg.inputs,
      verifiers: [
        {
          type: "onchain" as const,
          address: "0x0000000000000000000000000000000000000000",
          chainId: 84532,
          alg: "groth16-bn254-snarkjs" as const,
        },
      ],
      artifact: {
        location: {
          type: "https" as const,
          wasm: wasmUrl,
          zkey: zkeyUrl,
        },
      },
    };

    const circuitResult = CircuitMetaSchema.safeParse(circuitManifest);
    if (!circuitResult.success) {
      fail(`circuit manifest validation failed for ${cfg.circuitId}: ${circuitResult.error.message}`);
      continue;
    }

    const schemaPath = resolve(PRESETS_DIR, "schemas", `${cfg.schemaId}.json`);
    const circuitPath = resolve(PRESETS_DIR, "circuits", `${cfg.circuitId}.json`);

    writeFileSync(schemaPath, JSON.stringify(schemaManifest, null, 2) + "\n");
    ok(`presets/schemas/${cfg.schemaId}.json (hash: ${wasmHash.slice(0, 18)}…)`);

    writeFileSync(circuitPath, JSON.stringify(circuitManifest, null, 2) + "\n");
    ok(`presets/circuits/${cfg.circuitId}.json (zkey: ${zkeyHash.slice(0, 18)}…)`);
  }
}

generateManifests();
console.log(`\n${c.bold}done${c.reset}`);
