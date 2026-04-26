#!/usr/bin/env node
/**
 * Register circuit + scheme presets with Lemma.
 *
 *   tsx scripts/register-presets.ts             # dry-run (default, no API calls)
 *   tsx scripts/register-presets.ts --execute   # actually POST to LEMMA_API_BASE_URL
 *
 * Endpoints (mirrors @lemmaoracle/sdk):
 *   POST {LEMMA_API_BASE_URL}/v1/schemas
 *   POST {LEMMA_API_BASE_URL}/v1/circuits
 *
 * Env:
 *   LEMMA_API_BASE_URL  default https://workers.lemma.workers.dev
 *   LEMMA_API_KEY       required when --execute is passed
 *   LEMMA_ORG_ID        optional; sent as `x-org-id` header if present
 *   LEMMA_PROJECT_ID    optional; sent as `x-project-id` header if present
 *
 * The script:
 *   1. Loads every JSON under presets/schemes and presets/circuits
 *   2. Validates each manifest with zod (CircuitMetaSchema / SchemaMetaSchema)
 *   3. Either prints what would be sent (dry-run) or POSTs and reports the
 *      response body for each call
 *
 * If/when @lemmaoracle/sdk is added as a dep, swap `register*` for the SDK
 * `circuits.register(client, …)` / `schemas.register(client, …)` calls — the
 * payload shapes already match.
 */
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CircuitMetaSchema,
  SchemaMetaSchema,
  type CircuitManifest,
  type SchemeManifest,
} from "../packages/circuits/src/manifest.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");

const args = process.argv.slice(2);
const EXECUTE = args.includes("--execute");
const API_BASE =
  process.env.LEMMA_API_BASE_URL ?? "https://workers.lemma.workers.dev";
const API_KEY = process.env.LEMMA_API_KEY ?? "";

type RegistrationKind = "scheme" | "circuit";

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
): { file: string; payload: T }[] {
  const out: { file: string; payload: T }[] = [];
  for (const file of readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort()) {
    const path = resolve(dir, file);
    const raw = JSON.parse(readFileSync(path, "utf-8"));
    out.push({ file, payload: parse(raw) });
  }
  return out;
}

async function postJson(
  path: string,
  body: unknown,
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (API_KEY) headers["authorization"] = `Bearer ${API_KEY}`;
  if (process.env.LEMMA_ORG_ID) headers["x-org-id"] = process.env.LEMMA_ORG_ID;
  if (process.env.LEMMA_PROJECT_ID)
    headers["x-project-id"] = process.env.LEMMA_PROJECT_ID;

  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    parsed = await res.text();
  }
  return { status: res.status, body: parsed };
}

async function register(
  kind: RegistrationKind,
  file: string,
  payload: SchemeManifest | CircuitManifest,
): Promise<void> {
  const path = kind === "scheme" ? "/v1/schemas" : "/v1/circuits";
  const id =
    "id" in payload ? payload.id : (payload as CircuitManifest).circuitId;
  console.log(
    `\n${c.cyan}[${kind}]${c.reset} ${c.bold}${id}${c.reset} ${c.dim}(${file})${c.reset}`,
  );
  console.log(`  POST ${API_BASE}${path}`);
  console.log(
    "  payload:",
    JSON.stringify(payload, null, 2)
      .split("\n")
      .map((l, i) => (i === 0 ? l : "    " + l))
      .join("\n"),
  );

  if (!EXECUTE) {
    console.log(`  ${c.yellow}↳ dry-run — not sending${c.reset}`);
    return;
  }
  if (!API_KEY) {
    console.error(
      `  ${c.red}LEMMA_API_KEY is required for --execute; aborting${c.reset}`,
    );
    process.exit(1);
  }

  try {
    const { status, body } = await postJson(path, payload);
    if (status >= 200 && status < 300) {
      console.log(`  ${c.green}✓ ${status}${c.reset}`, body);
    } else {
      console.error(`  ${c.red}✗ ${status}${c.reset}`, body);
      process.exit(1);
    }
  } catch (err) {
    console.error(`  ${c.red}✗ network error${c.reset}`, err);
    process.exit(1);
  }
}

async function main() {
  console.log(
    `\n${c.bold}example-origin — Lemma preset registration${c.reset}`,
  );
  console.log(`  api base:  ${API_BASE}`);
  console.log(
    `  mode:      ${EXECUTE ? c.red + "EXECUTE (will write)" : c.green + "dry-run"}${c.reset}`,
  );
  console.log(`  api key:   ${API_KEY ? "set" : c.dim + "absent" + c.reset}`);
  if (process.env.LEMMA_ORG_ID)
    console.log(`  org id:    ${process.env.LEMMA_ORG_ID}`);
  if (process.env.LEMMA_PROJECT_ID)
    console.log(`  project:   ${process.env.LEMMA_PROJECT_ID}`);

  const schemes = loadManifests(
    resolve(REPO_ROOT, "presets/schemes"),
    (raw) => SchemaMetaSchema.parse(raw),
  );
  const circuits = loadManifests(
    resolve(REPO_ROOT, "presets/circuits"),
    (raw) => CircuitMetaSchema.parse(raw),
  );

  console.log(
    `\nfound ${schemes.length} scheme preset(s), ${circuits.length} circuit preset(s)`,
  );

  // Schemes first — circuits reference scheme ids by name.
  for (const { file, payload } of schemes) {
    await register("scheme", file, payload);
  }
  for (const { file, payload } of circuits) {
    // Validate that the circuit references a registered scheme.
    if (!schemes.some((s) => s.payload.id === payload.schema)) {
      console.error(
        `  ${c.red}circuit ${payload.circuitId} references unknown schema ${payload.schema}${c.reset}`,
      );
      process.exit(1);
    }
    await register("circuit", file, payload);
  }

  console.log(
    `\n${c.bold}done${c.reset} — ${schemes.length + circuits.length} preset(s) ${
      EXECUTE ? "registered" : "previewed (use --execute to write)"
    }.`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
