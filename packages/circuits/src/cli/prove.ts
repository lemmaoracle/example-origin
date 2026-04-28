#!/usr/bin/env node
/**
 * Full Groth16 proof-generation pipeline for both demo circuits.
 *
 *   pnpm --filter @example-origin/circuits circuits:prove
 *
 * Steps per circuit:
 *   1. circom compile → .r1cs + .wasm
 *   2. snarkjs r1cs info (constraint count)
 *   3. Powers of Tau ceremony (reuse or download; for PoC we generate a small one)
 *   4. Phase 2 setup → circuit_final.zkey
 *   5. Generate deterministic input JSON
 *   6. snarkjs groth16 fullprove → proof + publicSignals
 *   7. snarkjs groth16 verify → ✓ / ✗
 *
 * All build artifacts go to packages/circuits/build/<circuitId>/.
 * The small Powers of Tau file is cached under build/ptau/.
 */
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildBridgeApprovalInput, buildLstCollateralInput } from "../inputs.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "../..");
const BUILD_DIR = resolve(PKG_ROOT, "build");
const PTAU_DIR = resolve(BUILD_DIR, "ptau");
const CIRCUIT_SRC = resolve(PKG_ROOT, "src");
const CIRCUITLIB_DIR = resolve(PKG_ROOT, "node_modules");

const NOW = 1714065000;

const c = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
} as const;

function log(tag: string, msg: string) {
  console.log(`  ${c.cyan}[${tag}]${c.reset} ${msg}`);
}

function ok(msg: string) {
  console.log(`  ${c.green}✓${c.reset} ${msg}`);
}

function fail(msg: string) {
  console.log(`  ${c.red}✗${c.reset} ${msg}`);
}

function run(cmd: string, label: string) {
  try {
    execSync(cmd, { stdio: "inherit" });
    ok(label);
  } catch (err) {
    fail(label);
    throw err;
  }
}

function ensureDir(dir: string) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

// ---------------------------------------------------------------------------
// Powers of Tau
// ---------------------------------------------------------------------------

/**
 * For the PoC circuits (~few hundred constraints) a 12th-root-of-unity
 * ceremony (2^12 = 4096 constraints max) is more than enough.
 * If the file already exists we skip the generation.
 */
function ensurePtau(): string {
  const ptauPath = resolve(PTAU_DIR, "pot12_final.ptau");
  if (existsSync(ptauPath)) {
    ok(`Powers of Tau cached: ${ptauPath}`);
    return ptauPath;
  }

  ensureDir(PTAU_DIR);
  log("ptau", "Generating Powers of Tau (2^12) — one-time cost");

  // Phase 1: start ceremony
  const ptau0 = resolve(PTAU_DIR, "pot12_0000.ptau");
  run(
    `npx snarkjs powersoftau new bn128 12 "${ptau0}"`,
    "powersoftau new",
  );

  // Phase 1: contribute (non-interactive)
  const ptau1 = resolve(PTAU_DIR, "pot12_0001.ptau");
  run(
    `npx snarkjs powersoftau contribute "${ptau0}" "${ptau1}" --name="example-origin-poc" -e="example-origin-poc-entropy"`,
    "powersoftau contribute",
  );

  // Phase 1: prepare for phase 2 (must be done before zkey new)
  run(
    `npx snarkjs powersoftau prepare phase2 "${ptau1}" "${ptauPath}"`,
    "powersoftau prepare phase2",
  );

  return ptauPath;
}

// ---------------------------------------------------------------------------
// Per-circuit pipeline
// ---------------------------------------------------------------------------

type CircuitDef = {
  id: string;
  srcFile: string;
  buildInput: () => Promise<Record<string, string>>;
};

const CIRCUITS: CircuitDef[] = [
  {
    id: "bridge-approval-origin",
    srcFile: resolve(CIRCUIT_SRC, "bridge-approval-origin/bridge-approval-origin.circom"),
    buildInput: async () => {
      const input = await buildBridgeApprovalInput(
        {
          approvalId: "0xa1b2c3",
          signerSet: "did:bridge:gov-multisig-v3",
          dstChainId: 42161,
          amount: "1000000000",
          signersPresent: 5,
          validUntil: NOW + 9000,
          salt: "1234567890",
        },
        {
          policyDstChainId: 42161,
          policyMaxAmount: "5000000000",
          policyMinSigners: 3,
          nowSec: NOW,
        },
      );
      return input as Record<string, string>;
    },
  },
  {
    id: "lst-collateral-origin",
    srcFile: resolve(CIRCUIT_SRC, "lst-collateral-origin/lst-collateral-origin.circom"),
    buildInput: async () => {
      const input = await buildLstCollateralInput(
        {
          lotId: "rsETH-2026-04-22-#7",
          assetId: "rsETH",
          mintChainId: 1,
          custodyHops: 2,
          rehypothecationDepth: 0,
          validatorSetRevoked: 0,
          mintedAt: NOW - 100_000,
          salt: "999",
        },
        {
          policyAssetId: "rsETH",
          policyMaxRehypoDepth: 1,
          policyMaxCustodyHops: 3,
          policyMinMintAge: 60,
          nowSec: NOW,
        },
      );
      return input as Record<string, string>;
    },
  },
];

async function proveCircuit(circuit: CircuitDef, ptauPath: string) {
  const circuitDir = resolve(BUILD_DIR, circuit.id);
  ensureDir(circuitDir);

  const r1cs = resolve(circuitDir, `${circuit.id}.r1cs`);
  const wasm = resolve(circuitDir, `${circuit.id}.js`);
  const zkey0 = resolve(circuitDir, `${circuit.id}_0000.zkey`);
  const zkeyFinal = resolve(circuitDir, `${circuit.id}_final.zkey`);
  const vkey = resolve(circuitDir, "verification_key.json");
  const inputJson = resolve(circuitDir, "input.json");
  const proofJson = resolve(circuitDir, "proof.json");
  const publicJson = resolve(circuitDir, "public.json");

  console.log(`\n${c.bold}${c.cyan}${circuit.id}${c.reset}`);

  // 1. Compile
  log("compile", "circom → r1cs + wasm");
  run(
    `circom "${circuit.srcFile}" --r1cs --wasm --sym -l "${CIRCUITLIB_DIR}" -o "${circuitDir}"`,
    `compiled ${circuit.id}`,
  );

  // 2. R1CS info
  try {
    const info = execSync(`npx snarkjs r1cs info "${r1cs}"`, {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    log("r1cs", info.trim());
  } catch {
    log("r1cs", "(info unavailable)");
  }

  // 3. Phase 2 setup
  log("setup", "Phase 2 key generation");
  run(
    `npx snarkjs zkey new "${r1cs}" "${ptauPath}" "${zkey0}"`,
    "zkey new",
  );
  run(
    `npx snarkjs zkey contribute "${zkey0}" "${zkeyFinal}" --name="example-origin-${circuit.id}" -e="example-origin-${circuit.id}-entropy"`,
    "zkey contribute",
  );
  run(
    `npx snarkjs zkey export verificationkey "${zkeyFinal}" "${vkey}"`,
    "export verification key",
  );

  // 4. Generate input
  log("input", "building deterministic witness input");
  const input = await circuit.buildInput();
  writeFileSync(inputJson, JSON.stringify(input, null, 2) + "\n");
  ok(`input written to ${inputJson}`);

  // 5. Full prove
  log("prove", "groth16 fullprove");
  const wasmPath = resolve(circuitDir, `${circuit.id}_js`, `${circuit.id}.wasm`);
  execSync(
    `npx snarkjs groth16 fullprove "${inputJson}" "${wasmPath}" "${zkeyFinal}" "${proofJson}" "${publicJson}"`,
    { stdio: "inherit" },
  );
  ok("proof generated");

  // 6. Verify
  log("verify", "groth16 verify");
  try {
    const verifyOutput = execSync(
      `npx snarkjs groth16 verify "${vkey}" "${publicJson}" "${proofJson}"`,
      { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] },
    );
    const isValid = /ok!/i.test(verifyOutput);
    if (isValid) {
      ok("proof verified — valid!");
    } else {
      fail("proof verification FAILED");
      console.log(verifyOutput);
      process.exit(1);
    }
  } catch (err) {
    fail("proof verification error");
    throw err;
  }

  // 7. Summary
  const proofSize = readFileSync(proofJson).length;
  const pubSize = readFileSync(publicJson).length;
  log("output", `proof=${(proofSize / 1024).toFixed(1)}KB public=${(pubSize / 1024).toFixed(1)}KB`);
  log("output", `artifacts in ${circuitDir}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  const target = args.find((a) => a.startsWith("--circuit="))?.split("=")[1];

  console.log(`\n${c.bold}example-origin — Groth16 proof generation pipeline${c.reset}`);

  // Check circom
  try {
    const ver = execSync("circom --version", { encoding: "utf-8" }).trim();
    log("circom", ver);
  } catch {
    fail("circom not on PATH — install from https://github.com/iden3/circom");
    process.exit(1);
  }

  const ptauPath = ensurePtau();

  const circuits = target
    ? CIRCUITS.filter((c) => c.id === target)
    : CIRCUITS;

  if (circuits.length === 0) {
    fail(`no circuit matching "${target}"`);
    process.exit(1);
  }

  for (const circuit of circuits) {
    await proveCircuit(circuit, ptauPath);
  }

  console.log(`\n${c.green}${c.bold}all proofs generated and verified${c.reset}\n`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
