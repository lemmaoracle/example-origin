#!/usr/bin/env node
/**
 * Upload circuit artifacts to IPFS (Pinata) and register with Lemma.
 *
 *   tsx scripts/register-circuit.ts             # dry-run
 *   tsx scripts/register-circuit.ts --execute    # upload + register
 *
 * This script:
 * 1. Uploads wasm/zkey for each circuit to Pinata (IPFS)
 * 2. Updates the preset JSON with real IPFS URIs
 * 3. Registers schema + circuit with Lemma API via the SDK
 *
 * Prerequisites:
 *   - LEMMA_API_KEY  — Lemma API key
 *   - PINATA_API_KEY / PINATA_SECRET_API_KEY — Pinata credentials
 *   - Circuit artifacts built (`pnpm circuits:prove`)
 *
 * Based on example-x402/scripts/register-circuit.ts
 */
import { circuits, create, schemas } from "@lemmaoracle/sdk";
import type { LemmaClient, CircuitMeta, SchemaMeta } from "@lemmaoracle/spec";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");

const LEMMA_API_KEY = process.env.LEMMA_API_KEY ?? "";
const PINATA_API_KEY = process.env.PINATA_API_KEY ?? "";
const PINATA_SECRET_API_KEY = process.env.PINATA_SECRET_API_KEY ?? "";

const args = process.argv.slice(2);
const EXECUTE = args.includes("--execute");

const LEMMA_API_BASE = "https://workers.lemma.workers.dev";

const CIRCUITS_BUILD = path.join(
  PROJECT_ROOT,
  "packages/circuits/build",
);

type CircuitDef = Readonly<{
  circuitId: string;
  schemaId: string;
  description: string;
  inputs: ReadonlyArray<string>;
  wasmRel: string;
  zkeyRel: string;
}>;

const CIRCUIT_DEFS: ReadonlyArray<CircuitDef> = [
  {
    circuitId: "bridge-approval-origin",
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
    wasmRel: "bridge-approval-origin/bridge-approval-origin_js/bridge-approval-origin.wasm",
    zkeyRel: "bridge-approval-origin/bridge-approval-origin_final.zkey",
  },
  {
    circuitId: "lst-collateral-origin",
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
    wasmRel: "lst-collateral-origin/lst-collateral-origin_js/lst-collateral-origin.wasm",
    zkeyRel: "lst-collateral-origin/lst-collateral-origin_final.zkey",
  },
];

/* ------------------------------------------------------------------ */
/*  Pinata Upload                                                      */
/* ------------------------------------------------------------------ */

type PinataUploadResponse = Readonly<{
  IpfsHash: string;
  PinSize: number;
  Timestamp: string;
  isDuplicate?: boolean;
}>;

const uploadToPinata = (
  filePath: string,
  fileName: string,
): Promise<PinataUploadResponse> => {
  const file = fs.readFileSync(filePath);
  const formData = new FormData();
  formData.append("file", new Blob([file]), fileName);
  formData.append(
    "pinataMetadata",
    JSON.stringify({
      name: fileName,
      keyvalues: { project: "example-origin", timestamp: Date.now().toString() },
    }),
  );
  formData.append("pinataOptions", JSON.stringify({ cidVersion: 0 }));

  return fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
    method: "POST",
    headers: {
      pinata_api_key: PINATA_API_KEY,
      pinata_secret_api_key: PINATA_SECRET_API_KEY,
    },
    body: formData,
  }).then((res: Response) =>
    res.ok
      ? res.json() as Promise<PinataUploadResponse>
      : Promise.reject(new Error(`Pinata upload failed: ${res.status}`)),
  );
};

const uploadArtifact = (filePath: string, label: string): Promise<string> => {
  const fullPath = path.resolve(CIRCUITS_BUILD, filePath);
  if (!fs.existsSync(fullPath)) {
    return Promise.reject(
      new Error(`Artifact not found: ${fullPath}. Run 'pnpm circuits:prove' first.`),
    );
  }
  console.log(`  Uploading ${label}...`);
  return uploadToPinata(fullPath, path.basename(fullPath)).then(
    (r) => `ipfs://${r.IpfsHash}`,
  );
};

/* ------------------------------------------------------------------ */
/*  Schema presets (loaded from existing JSON)                         */
/* ------------------------------------------------------------------ */

const loadSchemaPreset = (schemaId: string): SchemaMeta => {
  const presetPath = path.join(PROJECT_ROOT, "presets/schemas", `${schemaId}.json`);
  return JSON.parse(fs.readFileSync(presetPath, "utf-8")) as SchemaMeta;
};

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

const c = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
};

async function main() {
  console.log(`\n${c.bold}example-origin — Circuit registration${c.reset}`);
  console.log(`  api base:  ${LEMMA_API_BASE}`);
  console.log(
    `  mode:      ${EXECUTE ? c.red + "EXECUTE" : c.green + "dry-run"}${c.reset}`,
  );
  console.log(
    `  api key:   ${LEMMA_API_KEY ? "set" : c.dim + "absent" + c.reset}`,
  );
  console.log(
    `  pinata:    ${PINATA_API_KEY ? "configured" : c.dim + "absent" + c.reset}`,
  );

  if (EXECUTE && !LEMMA_API_KEY) {
    console.error(
      `\n  ${c.red}LEMMA_API_KEY is required for --execute${c.reset}`,
    );
    process.exit(1);
  }

  if (EXECUTE && (!PINATA_API_KEY || !PINATA_SECRET_API_KEY)) {
    console.warn(
      `\n  ${c.yellow}PINATA_API_KEY / PINATA_SECRET_API_KEY not set — circuit artifacts will not be uploaded to IPFS${c.reset}`,
    );
    console.warn(
      `  ${c.yellow}Schemas will be registered; circuits will use placeholder artifact URLs.${c.reset}`,
    );
  }

  const client: LemmaClient = create({
    apiBase: LEMMA_API_BASE,
    apiKey: LEMMA_API_KEY,
  });

  // 1. Register schemas first (circuits reference schemas)
  console.log(`\n${c.bold}─ Schemas ─${c.reset}`);
  const schemaIds = [...new Set(CIRCUIT_DEFS.map((d) => d.schemaId))];
  for (const schemaId of schemaIds) {
    const schemaMeta = loadSchemaPreset(schemaId);
    console.log(`\n${c.cyan}[schema]${c.reset} ${c.bold}${schemaId}${c.reset}`);

    if (!EXECUTE) {
      console.log(`  ${c.yellow}↳ dry-run — not registering${c.reset}`);
      continue;
    }

    try {
      const res = await schemas.register(client, schemaMeta);
      console.log(`  ${c.green}✓ registered${c.reset}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("already exists") || msg.includes("409")) {
        console.log(`  ${c.yellow}already registered${c.reset}`);
      } else {
        console.error(`  ${c.red}✗ failed:${c.reset}`, msg);
        process.exit(1);
      }
    }
  }

  // 2. Upload artifacts + register circuits
  console.log(`\n${c.bold}─ Circuits ─${c.reset}`);
  for (const def of CIRCUIT_DEFS) {
    console.log(`\n${c.cyan}[circuit]${c.reset} ${c.bold}${def.circuitId}${c.reset}`);

    // Upload artifacts (even in dry-run, show what would be uploaded)
    let wasmUrl = "https://example.invalid/placeholder/circuit.wasm";
    let zkeyUrl = "https://example.invalid/placeholder/circuit_final.zkey";

    if (EXECUTE && PINATA_API_KEY && PINATA_SECRET_API_KEY) {
      try {
        [wasmUrl, zkeyUrl] = await Promise.all([
          uploadArtifact(def.wasmRel, `${def.circuitId}.wasm`),
          uploadArtifact(def.zkeyRel, `${def.circuitId}_final.zkey`),
        ]);
        console.log(`  ${c.green}✓${c.reset} wasm: ${wasmUrl}`);
        console.log(`  ${c.green}✓${c.reset} zkey: ${zkeyUrl}`);
      } catch (err: unknown) {
        console.error(
          `  ${c.red}✗ upload failed:${c.reset}`,
          err instanceof Error ? err.message : String(err),
        );
        process.exit(1);
      }
    } else if (!EXECUTE) {
      console.log(`  ${c.yellow}↳ would upload:${c.reset}`);
      console.log(`    wasm: ${path.join(CIRCUITS_BUILD, def.wasmRel)}`);
      console.log(`    zkey: ${path.join(CIRCUITS_BUILD, def.zkeyRel)}`);
    } else {
      console.log(`  ${c.yellow}↳ skipping IPFS upload (no Pinata credentials)${c.reset}`);
      console.log(`    using placeholder artifact URLs`);
    }

    const circuitMeta: CircuitMeta = {
      circuitId: def.circuitId,
      schema: def.schemaId,
      description: def.description,
      inputs: [...def.inputs],
      verifiers: [
        {
          type: "onchain",
          address: "0x0000000000000000000000000000000000000000",
          chainId: 84532,
          alg: "groth16-bn254-snarkjs",
        },
      ],
      artifact: {
        location: {
          type: "ipfs",
          wasm: wasmUrl,
          zkey: zkeyUrl,
        },
      },
    };

    if (!EXECUTE) {
      console.log(`  ${c.yellow}↳ dry-run — would register:${c.reset}`);
      console.log(
        `    circuitId: ${circuitMeta.circuitId}, schema: ${circuitMeta.schema}`,
      );
      continue;
    }

    try {
      const res = await circuits.register(client, circuitMeta);
      console.log(`  ${c.green}✓ registered${c.reset}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("already exists") || msg.includes("409")) {
        console.log(`  ${c.yellow}already registered — checking existing...${c.reset}`);
        try {
          const existing = await circuits.getById(client, def.circuitId);
          console.log(`  ${c.dim}existing wasm: ${existing.artifact?.location?.wasm}${c.reset}`);
          console.log(`  ${c.dim}existing zkey: ${existing.artifact?.location?.zkey}${c.reset}`);
        } catch {
          console.error(`  ${c.red}✗ could not fetch existing circuit${c.reset}`);
        }
      } else {
        console.error(`  ${c.red}✗ register failed:${c.reset}`, msg);
        process.exit(1);
      }
    }
  }

  console.log(
    `\n${c.bold}done${c.reset} — ${EXECUTE ? "registered" : "previewed (use --execute to upload + register)"}.`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
