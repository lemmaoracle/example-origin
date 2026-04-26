/**
 * Generate deterministic example inputs for both demo circuits.
 *
 *   pnpm --filter @example-origin/circuits circuits:inputs
 *
 * Writes:
 *   packages/circuits/inputs/bridge-approval-origin.input.json
 *   packages/circuits/inputs/lst-collateral-origin.input.json
 *
 * The fixtures are aligned with `data/bridge-approvals.json` and
 * `data/lst-collateral.json` so the circuit witness reflects the same
 * scenarios the existing PoC verifier accepts.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildBridgeApprovalInput,
  buildLstCollateralInput,
} from "../inputs.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// packages/circuits/src/cli → packages/circuits/inputs
const OUT_DIR = resolve(__dirname, "../../inputs");

const NOW = 1714065000;

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

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

  writeFileSync(
    resolve(OUT_DIR, "bridge-approval-origin.input.json"),
    JSON.stringify(bridge, null, 2) + "\n",
  );
  writeFileSync(
    resolve(OUT_DIR, "lst-collateral-origin.input.json"),
    JSON.stringify(lst, null, 2) + "\n",
  );

  console.log("wrote", OUT_DIR);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
