/**
 * Demo runner.
 *
 *   pnpm demo                  # both scenarios
 *   pnpm demo:bridge           # bridge approvals only
 *   pnpm demo:collateral       # LST/LRT collateral only
 *
 * For each fixture: issue an attestation, run the appropriate domain verifier,
 * and print the decision. Exits non-zero only if a fixture that should pass
 * fails (or a fixture that should fail unexpectedly passes) — useful as a
 * smoke test in CI.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  generateIssuerKey,
  issueAttestation,
  verifyBridgeApproval,
  verifyLstCollateral,
  type BridgePolicy,
  type LstPolicy,
  type RevocationList,
} from "../index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// packages/core/src/demo → repo-root/data
const DATA_DIR = resolve(__dirname, "../../../../data");

const c = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
} as const;

const issuer = generateIssuerKey(process.env.ISSUER_DID ?? "did:lemma:demo-issuer");

const bridgePolicy: BridgePolicy = {
  allowedSrcChainIds: [1, 56, 137, 8453],
  allowedDstChainIds: [1, 42161, 8453, 10],
  maxAmount: 5_000_000_000n, // 5,000 USDC (6-decimal) or equivalent
  minSignersPresent: 3,
  maxApprovalAgeSec: 24 * 60 * 60, // 24 hours
};

const lstPolicy: LstPolicy = {
  allowedMintChainIds: [1, 8453],
  maxRehypothecationDepth: 1,
  trustedCustodians: ["did:custodian:lemma-vault-1"],
  maxMintAgeSec: 30 * 24 * 60 * 60,
};

const revocations: RevocationList = {
  subjects: [],
  validatorSetRoots: [
    "0xbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad0",
  ],
};

// All fixtures evaluated against a fixed `now` so age/expiry checks are stable.
const NOW_SEC = 1714065000;

type BridgeFixture = {
  label: string;
  subjectId: string;
  hide: string[];
  attributes: Parameters<typeof issueAttestation>[2];
};

function loadFixtures<T>(envVar: string, fallback: string): T[] {
  const path = process.env[envVar] || resolve(DATA_DIR, fallback);
  return JSON.parse(readFileSync(path, "utf-8")) as T[];
}

function header(title: string) {
  const bar = "═".repeat(64);
  console.log(`\n${c.dim}${bar}${c.reset}`);
  console.log(`  ${c.bold}${c.cyan}${title}${c.reset}`);
  console.log(`${c.dim}${bar}${c.reset}`);
}

function section(label: string) {
  console.log(`\n${c.yellow}— ${label} —${c.reset}`);
}

function ok(msg: string) {
  console.log(`  ${c.green}✓${c.reset} ${msg}`);
}

function rej(msg: string) {
  console.log(`  ${c.red}✗${c.reset} ${msg}`);
}

function note(msg: string) {
  console.log(`    ${c.dim}${msg}${c.reset}`);
}

let pass = 0;
let unexpected = 0;

function expectMatch(label: string, gotOk: boolean) {
  // Convention: fixture labels containing "should" + "execute"/"accepted" are
  // expected to pass; everything else is expected to be rejected.
  const expectedPass =
    /should\s+(execute|be\s+accepted)/i.test(label) || /well[-\s]formed/i.test(label);
  if (expectedPass === gotOk) {
    pass += 1;
    return;
  }
  unexpected += 1;
  console.log(
    `  ${c.red}!! unexpected outcome — fixture expected ${
      expectedPass ? "PASS" : "REJECT"
    }${c.reset}`,
  );
}

async function runBridge() {
  header("Scenario 1 — Bridge approval origin (pre-execution)");
  console.log(
    `  ${c.dim}policy: src=${bridgePolicy.allowedSrcChainIds.join(",")} dst=${bridgePolicy.allowedDstChainIds.join(",")} maxAmount=${bridgePolicy.maxAmount} minSigners=${bridgePolicy.minSignersPresent} maxApprovalAge=${bridgePolicy.maxApprovalAgeSec}s${c.reset}`,
  );

  const fixtures = loadFixtures<BridgeFixture>(
    "BRIDGE_FIXTURE_PATH",
    "bridge-approvals.json",
  );

  for (const fx of fixtures) {
    section(fx.label);
    const att = issueAttestation(issuer, fx.subjectId, fx.attributes, {
      hide: fx.hide,
      nowSec: NOW_SEC,
      ttlSec: 24 * 60 * 60,
    });
    note(
      `disclosed ${Object.keys(att.disclosure.revealed).length} attr(s); hidden ${att.disclosure.hidden.length}: [${att.disclosure.hidden.join(", ")}]`,
    );
    const result = verifyBridgeApproval(att, {
      issuer,
      nowSec: NOW_SEC,
      revocations,
      policy: bridgePolicy,
    });
    if (result.ok) {
      ok(`approved — ${result.notes[result.notes.length - 1]}`);
    } else {
      rej(`rejected — ${result.reason}`);
    }
    for (const n of result.notes) note(n);
    expectMatch(fx.label, result.ok);
  }
}

async function runCollateral() {
  header("Scenario 2 — LST/LRT collateral provenance (pre-lending)");
  console.log(
    `  ${c.dim}policy: trustedCustodians=[${lstPolicy.trustedCustodians.join(",")}] maxDepth=${lstPolicy.maxRehypothecationDepth} maxAge=${lstPolicy.maxMintAgeSec}s${c.reset}`,
  );
  console.log(
    `  ${c.dim}revoked validator-set roots: ${revocations.validatorSetRoots.length}${c.reset}`,
  );

  const fixtures = loadFixtures<BridgeFixture>(
    "COLLATERAL_FIXTURE_PATH",
    "lst-collateral.json",
  );

  for (const fx of fixtures) {
    section(fx.label);
    const att = issueAttestation(issuer, fx.subjectId, fx.attributes, {
      hide: fx.hide,
      nowSec: NOW_SEC,
      ttlSec: 24 * 60 * 60,
    });
    note(
      `disclosed ${Object.keys(att.disclosure.revealed).length} attr(s); hidden ${att.disclosure.hidden.length}: [${att.disclosure.hidden.join(", ")}]`,
    );
    const result = verifyLstCollateral(att, {
      issuer,
      nowSec: NOW_SEC,
      revocations,
      policy: lstPolicy,
    });
    if (result.ok) {
      ok(`accepted — ${result.notes[result.notes.length - 4]}`);
    } else {
      rej(`rejected — ${result.reason}`);
    }
    for (const n of result.notes) note(n);
    expectMatch(fx.label, result.ok);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const scenario =
    args.find((a) => a.startsWith("--scenario="))?.split("=")[1] ?? "all";

  console.log(
    `\n${c.bold}example-origin${c.reset} ${c.dim}— minimal Lemma PoC${c.reset}`,
  );
  console.log(`${c.dim}issuer: ${issuer.did}${c.reset}`);
  console.log(`${c.dim}now:    ${NOW_SEC}${c.reset}`);

  if (scenario === "bridge" || scenario === "all") await runBridge();
  if (scenario === "collateral" || scenario === "all") await runCollateral();

  header("Summary");
  console.log(
    `  ${c.green}${pass}${c.reset} matched expectations, ${unexpected ? c.red : c.dim}${unexpected}${c.reset} unexpected`,
  );

  const strict = (process.env.DEMO_MODE ?? "strict") === "strict";
  if (unexpected > 0 && strict) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
