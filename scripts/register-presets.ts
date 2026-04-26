#!/usr/bin/env node
/**
 * Register circuit + scheme presets with Lemma using the real SDK.
 *
 *   tsx scripts/register-presets.ts             # dry-run (default, no API calls)
 *   tsx scripts/register-presets.ts --execute   # actually call the API
 *
 * Wire format (handled by `@lemmaoracle/sdk`):
 *   POST {LEMMA_API_BASE_URL}/v1/schemas        ← schemas.register(client, payload)
 *   POST {LEMMA_API_BASE_URL}/v1/circuits       ← circuits.register(client, payload)
 *
 * Env:
 *   LEMMA_API_BASE_URL  default https://workers.lemma.workers.dev (SDK default)
 *   LEMMA_API_KEY       required when --execute is passed; sent as `x-api-key`
 *
 * The script:
 *   1. Loads every JSON under presets/schemes and presets/circuits.
 *   2. Validates each manifest with zod (CircuitMetaSchema / SchemaMetaSchema)
 *      and re-asserts it as `SchemaMeta` / `CircuitMeta` from `@lemmaoracle/spec`.
 *   3. Either prints what would be sent (dry-run) or invokes
 *      `schemas.register` / `circuits.register` from `@lemmaoracle/sdk` and
 *      reports the response body.
 */
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { circuits, create, schemas } from "@lemmaoracle/sdk";
import type {
  CircuitMeta,
  LemmaClient,
  LemmaClientConfig,
  SchemaMeta,
} from "@lemmaoracle/spec";
import {
  CircuitMetaSchema,
  SchemaMetaSchema,
} from "../packages/circuits/src/manifest.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");

const args = process.argv.slice(2);
const EXECUTE = args.includes("--execute");
const API_BASE = process.env.LEMMA_API_BASE_URL;
const API_KEY = process.env.LEMMA_API_KEY ?? "";

type Manifest<T> = { file: string; payload: T };

const c = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
} as const;

function loadManifests<T>(
  dir: string,
  parse: (raw: unknown) => T,
): Manifest<T>[] {
  const out: Manifest<T>[] = [];
  for (const file of readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort()) {
    const path = resolve(dir, file);
    const raw = JSON.parse(readFileSync(path, "utf-8"));
    out.push({ file, payload: parse(raw) });
  }
  return out;
}

function pretty(indent: number, value: unknown): string {
  const pad = " ".repeat(indent);
  return JSON.stringify(value, null, 2)
    .split("\n")
    .map((l, i) => (i === 0 ? l : pad + l))
    .join("\n");
}

async function registerScheme(
  client: LemmaClient,
  m: Manifest<SchemaMeta>,
): Promise<void> {
  console.log(
    `\n${c.cyan}[scheme]${c.reset} ${c.bold}${m.payload.id}${c.reset} ${c.dim}(${m.file})${c.reset}`,
  );
  console.log(`  schemas.register → POST ${client.apiBase}/v1/schemas`);
  console.log("  payload:", pretty(4, m.payload));

  if (!EXECUTE) {
    console.log(`  ${c.yellow}↳ dry-run — not sending${c.reset}`);
    return;
  }
  try {
    const res = await schemas.register(client, m.payload);
    console.log(`  ${c.green}✓ registered${c.reset}`, res);
  } catch (err) {
    console.error(`  ${c.red}✗ schemas.register failed${c.reset}`, err);
    process.exit(1);
  }
}

async function registerCircuit(
  client: LemmaClient,
  m: Manifest<CircuitMeta>,
): Promise<void> {
  console.log(
    `\n${c.cyan}[circuit]${c.reset} ${c.bold}${m.payload.circuitId}${c.reset} ${c.dim}(${m.file})${c.reset}`,
  );
  console.log(`  circuits.register → POST ${client.apiBase}/v1/circuits`);
  console.log("  payload:", pretty(4, m.payload));

  if (!EXECUTE) {
    console.log(`  ${c.yellow}↳ dry-run — not sending${c.reset}`);
    return;
  }
  try {
    const res = await circuits.register(client, m.payload);
    console.log(`  ${c.green}✓ registered${c.reset}`, res);
  } catch (err) {
    console.error(`  ${c.red}✗ circuits.register failed${c.reset}`, err);
    process.exit(1);
  }
}

async function main() {
  console.log(
    `\n${c.bold}example-origin — Lemma preset registration${c.reset}`,
  );

  const config: LemmaClientConfig = {
    ...(API_BASE ? { apiBase: API_BASE } : {}),
    ...(API_KEY ? { apiKey: API_KEY } : {}),
  };
  const client = create(config);

  console.log(`  api base:  ${client.apiBase}`);
  console.log(
    `  mode:      ${EXECUTE ? c.red + "EXECUTE (will write)" : c.green + "dry-run"}${c.reset}`,
  );
  console.log(`  api key:   ${API_KEY ? "set" : c.dim + "absent" + c.reset}`);

  if (EXECUTE && !API_KEY) {
    console.error(
      `\n  ${c.red}LEMMA_API_KEY is required for --execute; aborting${c.reset}`,
    );
    process.exit(1);
  }

  // zod-validate, then re-assert as the SDK's spec types so
  // schemas.register / circuits.register get exactly the shape they expect.
  const schemeManifests = loadManifests<SchemaMeta>(
    resolve(REPO_ROOT, "presets/schemes"),
    (raw) => SchemaMetaSchema.parse(raw) as SchemaMeta,
  );
  const circuitManifests = loadManifests<CircuitMeta>(
    resolve(REPO_ROOT, "presets/circuits"),
    (raw) => CircuitMetaSchema.parse(raw) as CircuitMeta,
  );

  console.log(
    `\nfound ${schemeManifests.length} scheme preset(s), ${circuitManifests.length} circuit preset(s)`,
  );

  // Schemes first — every circuit references its scheme by id.
  for (const m of schemeManifests) {
    await registerScheme(client, m);
  }
  for (const m of circuitManifests) {
    if (!schemeManifests.some((s) => s.payload.id === m.payload.schema)) {
      console.error(
        `  ${c.red}circuit ${m.payload.circuitId} references unknown schema ${m.payload.schema}${c.reset}`,
      );
      process.exit(1);
    }
    await registerCircuit(client, m);
  }

  console.log(
    `\n${c.bold}done${c.reset} — ${schemeManifests.length + circuitManifests.length} preset(s) ${
      EXECUTE ? "registered" : "previewed (use --execute to write)"
    }.`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
