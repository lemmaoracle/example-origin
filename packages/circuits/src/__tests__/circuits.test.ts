import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect } from "vitest";
import {
  buildBridgeApprovalInput,
  buildLstCollateralInput,
} from "../inputs.js";
import { CircuitMetaSchema, SchemaMetaSchema } from "../manifest.js";

const REPO_ROOT = resolve(__dirname, "../../../..");
const NOW = 1714065000;

describe("buildBridgeApprovalInput", () => {
  it("produces a Poseidon-bound commitment over the witness", async () => {
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
    expect(input.originCommitment).toMatch(/^[0-9]+$/);
    expect(input.dstChainId).toBe("42161");
    expect(input.amount).toBe("1000000000");
  });

  it("changes commitment when any private witness changes", async () => {
    const base = await buildBridgeApprovalInput(
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
    const tampered = await buildBridgeApprovalInput(
      {
        approvalId: "0xa1b2c3",
        signerSet: "did:bridge:gov-multisig-v3",
        dstChainId: 42161,
        amount: "9999999999",
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
    expect(base.originCommitment).not.toBe(tampered.originCommitment);
  });

  it("rejects non-numeric amounts", async () => {
    await expect(
      buildBridgeApprovalInput(
        {
          approvalId: "0xa1b2c3",
          signerSet: "did:bridge:gov-multisig-v3",
          dstChainId: 42161,
          amount: "1.0e9",
          signersPresent: 5,
          validUntil: NOW + 9000,
        },
        {
          policyDstChainId: 42161,
          policyMaxAmount: "5000000000",
          policyMinSigners: 3,
          nowSec: NOW,
        },
      ),
    ).rejects.toThrow();
  });
});

describe("buildLstCollateralInput", () => {
  it("hashes asset id consistently between witness and policy", async () => {
    const input = await buildLstCollateralInput(
      {
        lotId: "rsETH-2026-04-22-#7",
        assetId: "rsETH",
        mintChainId: 1,
        custodyHops: 2,
        rehypothecationDepth: 0,
        validatorSetRevoked: 0,
        mintedAt: NOW - 1000,
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
    // The circuit checks `assetIdHash === policyAssetIdHash`; if our generator
    // hashes them inconsistently, that constraint fails before we even compile.
    expect(input.assetIdHash).toBe(input.policyAssetIdHash);
    expect(input.collateralCommitment).toMatch(/^[0-9]+$/);
  });

  it("rejects non-boolean validatorSetRevoked", async () => {
    await expect(
      buildLstCollateralInput(
        {
          lotId: "x",
          assetId: "rsETH",
          mintChainId: 1,
          custodyHops: 2,
          rehypothecationDepth: 0,
          validatorSetRevoked: 2 as 0 | 1,
          mintedAt: NOW - 1000,
        },
        {
          policyAssetId: "rsETH",
          policyMaxRehypoDepth: 1,
          policyMaxCustodyHops: 3,
          policyMinMintAge: 60,
          nowSec: NOW,
        },
      ),
    ).rejects.toThrow();
  });
});

describe("preset manifests", () => {
  it("circuit manifests pass CircuitMetaSchema", () => {
    const dir = resolve(REPO_ROOT, "presets/circuits");
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".json"))) {
      const json = JSON.parse(readFileSync(resolve(dir, f), "utf-8"));
      const r = CircuitMetaSchema.safeParse(json);
      expect(r.success, `${f}: ${r.success ? "" : r.error.message}`).toBe(true);
    }
  });

  it("scheme manifests pass SchemaMetaSchema", () => {
    const dir = resolve(REPO_ROOT, "presets/schemes");
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".json"))) {
      const json = JSON.parse(readFileSync(resolve(dir, f), "utf-8"));
      const r = SchemaMetaSchema.safeParse(json);
      expect(r.success, `${f}: ${r.success ? "" : r.error.message}`).toBe(true);
    }
  });

  it("rejects http:// artifact URIs", () => {
    const r = CircuitMetaSchema.safeParse({
      circuitId: "x",
      schema: "x",
      inputs: ["a"],
      verifiers: [{ type: "offchain" }],
      artifact: {
        location: {
          type: "https",
          wasm: "http://insecure/wasm",
          zkey: "http://insecure/zkey",
        },
      },
    });
    expect(r.success).toBe(false);
  });
});
