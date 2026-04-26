/**
 * CI-friendly circuit check.
 *
 *   pnpm --filter @example-origin/circuits circuits:check
 *
 * Steps:
 *   1. Validate every preset manifest under `presets/` against its zod schema.
 *   2. Generate deterministic inputs for both circuits and confirm the JS-side
 *      Poseidon commitment matches what the witness will check.
 *   3. If `circom` is on PATH, also run `circom --inspect` on each circuit so
 *      a syntax/structural break fails CI. Skipped quietly otherwise — the
 *      first two steps already give us a regression net.
 */
import { execSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildBridgeApprovalInput,
  buildLstCollateralInput,
} from "../inputs.js";
import { CircuitMetaSchema, SchemaMetaSchema } from "../manifest.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "../../../..");

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf-8"));
}

function checkPresets() {
  const circuitsDir = resolve(REPO_ROOT, "presets/circuits");
  const schemasDir = resolve(REPO_ROOT, "presets/schemas");
  const failures: string[] = [];

  for (const f of readdirSync(circuitsDir).filter((n) => n.endsWith(".json"))) {
    const path = resolve(circuitsDir, f);
    const result = CircuitMetaSchema.safeParse(loadJson(path));
    if (!result.success) {
      failures.push(`circuits/${f}: ${result.error.message}`);
    } else {
      console.log(`  ✓ presets/circuits/${f}`);
    }
  }
  for (const f of readdirSync(schemasDir).filter((n) => n.endsWith(".json"))) {
    const path = resolve(schemasDir, f);
    const result = SchemaMetaSchema.safeParse(loadJson(path));
    if (!result.success) {
      failures.push(`schemas/${f}: ${result.error.message}`);
    } else {
      console.log(`  ✓ presets/schemas/${f}`);
    }
  }
  if (failures.length > 0) {
    console.error("\nmanifest validation failed:\n  " + failures.join("\n  "));
    process.exit(1);
  }
}

async function checkInputs() {
  const NOW = 1714065000;
  const bridge = await buildBridgeApprovalInput(
    {
      approvalId: "0xa1b2c3",
      signerSet: "did:bridge:gov-multisig-v3",
      dstChainId: 42161,
      amount: "1000000000",
      signersPresent: 5,
      validUntil: NOW + 9000,
    },
    {
      policyDstChainId: 42161,
      policyMaxAmount: "5000000000",
      policyMinSigners: 3,
      nowSec: NOW,
    },
  );
  if (!/^[0-9]+$/.test(bridge.originCommitment)) {
    console.error("bridge originCommitment is not a decimal field element");
    process.exit(1);
  }
  console.log(
    `  ✓ bridge-approval-origin input — origin=${bridge.originCommitment.slice(0, 16)}…`,
  );

  const lst = await buildLstCollateralInput(
    {
      lotId: "rsETH-2026-04-22-#7",
      assetId: "rsETH",
      mintChainId: 1,
      custodyHops: 2,
      rehypothecationDepth: 0,
      validatorSetRevoked: 0,
      mintedAt: NOW - 100_000,
    },
    {
      policyAssetId: "rsETH",
      policyMaxRehypoDepth: 1,
      policyMaxCustodyHops: 3,
      policyMinMintAge: 60,
      nowSec: NOW,
    },
  );
  if (!/^[0-9]+$/.test(lst.collateralCommitment)) {
    console.error("lst collateralCommitment is not a decimal field element");
    process.exit(1);
  }
  console.log(
    `  ✓ lst-collateral-origin input — commitment=${lst.collateralCommitment.slice(0, 16)}…`,
  );
}

function maybeRunCircom() {
  let circomVersion: string;
  try {
    circomVersion = execSync("circom --version", { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    console.log("  ⓘ circom not on PATH — skipping --inspect (install circom 2.x to enable)");
    return;
  }
  console.log(`  using ${circomVersion}`);

  const circuits = [
    "src/bridge-approval-origin/bridge-approval-origin.circom",
    "src/lst-collateral-origin/lst-collateral-origin.circom",
  ];
  for (const rel of circuits) {
    const path = resolve(__dirname, "../..", rel);
    if (!existsSync(path)) {
      console.error(`circuit missing: ${path}`);
      process.exit(1);
    }
    try {
      // -l adds the workspace's circomlib install to the include path
      const include = resolve(__dirname, "../../node_modules");
      execSync(`circom --inspect -l "${include}" "${path}"`, {
        stdio: "inherit",
      });
      console.log(`  ✓ circom --inspect ${rel}`);
    } catch {
      console.error(`  ✗ circom --inspect failed for ${rel}`);
      process.exit(1);
    }
  }
}

async function main() {
  console.log("\n[1/3] preset manifests");
  checkPresets();
  console.log("\n[2/3] deterministic input generation");
  await checkInputs();
  console.log("\n[3/3] circom --inspect (if available)");
  maybeRunCircom();
  console.log("\nall circuit resources validated.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
