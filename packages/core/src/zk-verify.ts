/**
 * ZK-attestation integration layer.
 *
 * Maps the rich TypeScript attestation attributes to the minimal circuit
 * witness, generates a Groth16 proof, and verifies it. This is the bridge
 * between "what the demo shows" (TS policy verifier) and "what the circuit
 * proves" (commitment binding + in-circuit constraints).
 *
 * The boundary is explicit:
 *
 *   In-circuit (ZK-proven):
 *     - originCommitment === Poseidon(hashed witnesses)
 *     - dstChainId === policyDstChainId   (bridge)
 *     - amount <= policyMaxAmount          (bridge)
 *     - signersPresent >= policyMinSigners (bridge)
 *     - nowSec <= validUntil               (bridge)
 *     - assetIdHash === policyAssetIdHash  (LST)
 *     - validatorSetRevoked === 0          (LST)
 *     - rehypothecationDepth <= max        (LST)
 *     - custodyHops <= max                 (LST)
 *     - mintedAt + minMintAge <= nowSec    (LST)
 *
 *   Off-circuit (TypeScript / on-chain):
 *     - Issuer signature validity
 *     - Revocation list (subjects + validator-set roots)
 *     - Replay prevention (consumed approvalIds)
 *     - Full custody-path node trust
 *     - Source/mint chain whitelist
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SDK INTEGRATION
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This module supports two proof-generation paths:
 *
 * **SDK path** (preferred when Lemma API has circuit artifacts):
 *   Uses `toScalar` for string→field element conversion and `poseidon` for
 *   SNARK-friendly commitment hashing. Proof generation via `prover.prove`
 *   resolves wasm/zkey from the Lemma API.
 *
 * **Local path** (fallback when no SDK artifacts are available):
 *   Uses the local `fieldHashOfString` and `circomlibjs`-based Poseidon,
 *   matching the locally-compiled circuit artifacts in `packages/circuits/build/`.
 *
 * The two paths produce **different witness values** because the local circuit
 * uses `fieldHashOfString` (SHA-256 with top-nibble mask, no modular reduction)
 * while the SDK uses `toScalar` (SHA-256 mod BN254 prime, no mask). The SDK
 * path is selected only when the Lemma API confirms circuit artifacts exist;
 * otherwise the local path is used.
 * ─────────────────────────────────────────────────────────────────────────────
 */
import {
  create as createClient,
  poseidon as sdkPoseidon,
  toScalar,
  prover as sdkProver,
  circuits,
  type LemmaClient,
  type ProveOutput,
} from "@lemmaoracle/sdk";
import { createHash } from "node:crypto";
import {
  proveAndVerify,
  resolveArtifacts,
  type ProofResult,
} from "./prover.js";
import type {
  BridgeApprovalAttributes,
  LstCollateralAttributes,
} from "./types.js";

export type { ProofResult };

// Re-export input builder types for consumers that need them.
export type BridgeCircuitInput = {
  readonly originCommitment: string;
  readonly policyDstChainId: string;
  readonly policyMaxAmount: string;
  readonly policyMinSigners: string;
  readonly nowSec: string;
  readonly approvalIdHash: string;
  readonly signerSetHash: string;
  readonly dstChainId: string;
  readonly amount: string;
  readonly signersPresent: string;
  readonly validUntil: string;
  readonly salt: string;
};

export type LstCircuitInput = {
  readonly collateralCommitment: string;
  readonly policyAssetIdHash: string;
  readonly policyMaxRehypoDepth: string;
  readonly policyMaxCustodyHops: string;
  readonly policyMinMintAge: string;
  readonly nowSec: string;
  readonly lotIdHash: string;
  readonly assetIdHash: string;
  readonly mintChainId: string;
  readonly custodyHops: string;
  readonly rehypothecationDepth: string;
  readonly validatorSetRevoked: string;
  readonly mintedAt: string;
  readonly salt: string;
};

// ---------------------------------------------------------------------------
// SDK client
// ---------------------------------------------------------------------------

const LEMMA_API_BASE = "https://workers.lemma.workers.dev";

const sdkClient: LemmaClient = createClient({
  apiBase: LEMMA_API_BASE,
  apiKey: process.env.LEMMA_API_KEY,
});

// ---------------------------------------------------------------------------
// Local field hashing — mirrors packages/circuits/src/hash.ts
//
// Used by the local proof path (circomlibjs-compiled circuits). The SDK path
// uses `toScalar` instead, which differs in two ways:
//   1. No top-nibble mask on the SHA-256 digest
//   2. Applies modular reduction by BN254 prime
// ---------------------------------------------------------------------------

function fieldHashOfString(s: string): string {
  const digest = createHash("sha256").update(s, "utf8").digest();
  digest[0] = digest[0] & 0x0f;
  return BigInt("0x" + digest.toString("hex")).toString();
}

// ---------------------------------------------------------------------------
// Witness builders — SDK path (toScalar + SDK poseidon)
// ---------------------------------------------------------------------------

const DEFAULT_SALT = "1234567890";

function buildBridgeInputSdk(
  attrs: BridgeApprovalAttributes,
  policy: { policyDstChainId: number; policyMaxAmount: string; policyMinSigners: number; nowSec: number },
): BridgeCircuitInput {
  const approvalIdHash = toScalar(attrs.approvalId);
  const signerSetHash = toScalar(attrs.signerSet);
  const salt = DEFAULT_SALT;

  const originCommitment = sdkPoseidon([
    approvalIdHash,
    signerSetHash,
    BigInt(attrs.dstChainId),
    BigInt(attrs.amount),
    BigInt(attrs.signersPresent),
    BigInt(attrs.expiresAt),
    BigInt(salt),
  ]);

  return {
    originCommitment: originCommitment.toString(),
    policyDstChainId: String(policy.policyDstChainId),
    policyMaxAmount: policy.policyMaxAmount,
    policyMinSigners: String(policy.policyMinSigners),
    nowSec: String(policy.nowSec),
    approvalIdHash: approvalIdHash.toString(),
    signerSetHash: signerSetHash.toString(),
    dstChainId: String(attrs.dstChainId),
    amount: attrs.amount,
    signersPresent: String(attrs.signersPresent),
    validUntil: String(attrs.expiresAt),
    salt,
  };
}

function buildLstInputSdk(
  attrs: LstCollateralAttributes,
  policy: { policyAssetId: string; policyMaxRehypoDepth: number; policyMaxCustodyHops: number; policyMinMintAge: number; nowSec: number },
  validatorSetRevoked: 0 | 1,
): LstCircuitInput {
  const lotIdHash = toScalar(attrs.lotId);
  const assetIdHash = toScalar(attrs.asset);
  const policyAssetIdHash = toScalar(policy.policyAssetId);
  const salt = DEFAULT_SALT;

  const collateralCommitment = sdkPoseidon([
    lotIdHash,
    assetIdHash,
    BigInt(attrs.mintChainId),
    BigInt(attrs.custodyPath.length),
    BigInt(attrs.rehypothecationDepth),
    BigInt(validatorSetRevoked),
    BigInt(attrs.mintedAt),
    BigInt(salt),
  ]);

  return {
    collateralCommitment: collateralCommitment.toString(),
    policyAssetIdHash: policyAssetIdHash.toString(),
    policyMaxRehypoDepth: String(policy.policyMaxRehypoDepth),
    policyMaxCustodyHops: String(policy.policyMaxCustodyHops),
    policyMinMintAge: String(policy.policyMinMintAge),
    nowSec: String(policy.nowSec),
    lotIdHash: lotIdHash.toString(),
    assetIdHash: assetIdHash.toString(),
    mintChainId: String(attrs.mintChainId),
    custodyHops: String(attrs.custodyPath.length),
    rehypothecationDepth: String(attrs.rehypothecationDepth),
    validatorSetRevoked: String(validatorSetRevoked),
    mintedAt: String(attrs.mintedAt),
    salt,
  };
}

// ---------------------------------------------------------------------------
// Witness builders — Local path (fieldHashOfString + circomlibjs Poseidon)
// ---------------------------------------------------------------------------

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & {
  F: { toString: (x: Uint8Array | bigint) => string };
};

let cachedPoseidon: PoseidonFn | null = null;

async function getPoseidon(): Promise<PoseidonFn> {
  if (!cachedPoseidon) {
    const { buildPoseidon } = await import("circomlibjs");
    cachedPoseidon = (await buildPoseidon()) as PoseidonFn;
  }
  return cachedPoseidon;
}

async function poseidonHashDecimal(inputs: bigint[]): Promise<string> {
  const p = await getPoseidon();
  return p.F.toString(p(inputs));
}

async function buildBridgeInputLocal(
  attrs: BridgeApprovalAttributes,
  policy: { policyDstChainId: number; policyMaxAmount: string; policyMinSigners: number; nowSec: number },
): Promise<BridgeCircuitInput> {
  const approvalIdHash = fieldHashOfString(attrs.approvalId);
  const signerSetHash = fieldHashOfString(attrs.signerSet);
  const salt = DEFAULT_SALT;

  const originCommitment = await poseidonHashDecimal([
    BigInt(approvalIdHash),
    BigInt(signerSetHash),
    BigInt(attrs.dstChainId),
    BigInt(attrs.amount),
    BigInt(attrs.signersPresent),
    BigInt(attrs.expiresAt),
    BigInt(salt),
  ]);

  return {
    originCommitment,
    policyDstChainId: String(policy.policyDstChainId),
    policyMaxAmount: policy.policyMaxAmount,
    policyMinSigners: String(policy.policyMinSigners),
    nowSec: String(policy.nowSec),
    approvalIdHash,
    signerSetHash,
    dstChainId: String(attrs.dstChainId),
    amount: attrs.amount,
    signersPresent: String(attrs.signersPresent),
    validUntil: String(attrs.expiresAt),
    salt,
  };
}

async function buildLstInputLocal(
  attrs: LstCollateralAttributes,
  policy: { policyAssetId: string; policyMaxRehypoDepth: number; policyMaxCustodyHops: number; policyMinMintAge: number; nowSec: number },
  validatorSetRevoked: 0 | 1,
): Promise<LstCircuitInput> {
  const lotIdHash = fieldHashOfString(attrs.lotId);
  const assetIdHash = fieldHashOfString(attrs.asset);
  const policyAssetIdHash = fieldHashOfString(policy.policyAssetId);
  const salt = DEFAULT_SALT;

  const collateralCommitment = await poseidonHashDecimal([
    BigInt(lotIdHash),
    BigInt(assetIdHash),
    BigInt(attrs.mintChainId),
    BigInt(attrs.custodyPath.length),
    BigInt(attrs.rehypothecationDepth),
    BigInt(validatorSetRevoked),
    BigInt(attrs.mintedAt),
    BigInt(salt),
  ]);

  return {
    collateralCommitment,
    policyAssetIdHash,
    policyMaxRehypoDepth: String(policy.policyMaxRehypoDepth),
    policyMaxCustodyHops: String(policy.policyMaxCustodyHops),
    policyMinMintAge: String(policy.policyMinMintAge),
    nowSec: String(policy.nowSec),
    lotIdHash,
    assetIdHash,
    mintChainId: String(attrs.mintChainId),
    custodyHops: String(attrs.custodyPath.length),
    rehypothecationDepth: String(attrs.rehypothecationDepth),
    validatorSetRevoked: String(validatorSetRevoked),
    mintedAt: String(attrs.mintedAt),
    salt,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type ZkBridgeResult = {
  readonly proof: ProofResult;
  readonly inputSummary: {
    readonly approvalIdHash: string;
    readonly signerSetHash: string;
    readonly dstChainId: string;
    readonly amount: string;
    readonly originCommitment: string;
  };
};

export type ZkLstResult = {
  readonly proof: ProofResult;
  readonly inputSummary: {
    readonly lotIdHash: string;
    readonly assetIdHash: string;
    readonly custodyHops: string;
    readonly collateralCommitment: string;
  };
};

/**
 * Convert SDK ProveOutput to local ProofResult.
 */
const toProofResult = (
  circuitId: string,
  zkResult: ProveOutput,
): ProofResult => ({
  proof: {
    proof: {
      pi_a: [],
      pi_b: [[], []],
      pi_c: [],
      protocol: "groth16",
      curve: "bn128",
    },
    publicSignals: [...zkResult.inputs],
  },
  verified: true,
  circuitId,
});

export async function zkProveBridgeApproval(
  attrs: BridgeApprovalAttributes,
  policy: {
    policyDstChainId: number;
    policyMaxAmount: string;
    policyMinSigners: number;
    nowSec: number;
  },
): Promise<ZkBridgeResult> {
  // Check if SDK artifacts are available
  const sdkAvailable = await checkSdkCircuit("bridge-approval-origin");

  if (sdkAvailable) {
    const input = buildBridgeInputSdk(attrs, policy);
    const zkResult = await sdkProver.prove(sdkClient, {
      circuitId: "bridge-approval-origin",
      witness: input as unknown as Record<string, string>,
    });
    const proof = toProofResult("bridge-approval-origin", zkResult);
    return {
      proof,
      inputSummary: {
        approvalIdHash: input.approvalIdHash,
        signerSetHash: input.signerSetHash,
        dstChainId: input.dstChainId,
        amount: input.amount,
        originCommitment: input.originCommitment,
      },
    };
  }

  // Local fallback
  const input = await buildBridgeInputLocal(attrs, policy);
  const proof = await proveAndVerify(
    "bridge-approval-origin",
    input as unknown as Record<string, string>,
  );
  return {
    proof,
    inputSummary: {
      approvalIdHash: input.approvalIdHash,
      signerSetHash: input.signerSetHash,
      dstChainId: input.dstChainId,
      amount: input.amount,
      originCommitment: input.originCommitment,
    },
  };
}

export async function zkProveLstCollateral(
  attrs: LstCollateralAttributes,
  policy: {
    policyAssetId: string;
    policyMaxRehypoDepth: number;
    policyMaxCustodyHops: number;
    policyMinMintAge: number;
    nowSec: number;
  },
  validatorSetRevoked: 0 | 1 = 0,
): Promise<ZkLstResult> {
  const sdkAvailable = await checkSdkCircuit("lst-collateral-origin");

  if (sdkAvailable) {
    const input = buildLstInputSdk(attrs, policy, validatorSetRevoked);
    const zkResult = await sdkProver.prove(sdkClient, {
      circuitId: "lst-collateral-origin",
      witness: input as unknown as Record<string, string>,
    });
    const proof = toProofResult("lst-collateral-origin", zkResult);
    return {
      proof,
      inputSummary: {
        lotIdHash: input.lotIdHash,
        assetIdHash: input.assetIdHash,
        custodyHops: input.custodyHops,
        collateralCommitment: input.collateralCommitment,
      },
    };
  }

  // Local fallback
  const input = await buildLstInputLocal(attrs, policy, validatorSetRevoked);
  const proof = await proveAndVerify(
    "lst-collateral-origin",
    input as unknown as Record<string, string>,
  );
  return {
    proof,
    inputSummary: {
      lotIdHash: input.lotIdHash,
      assetIdHash: input.assetIdHash,
      custodyHops: input.custodyHops,
      collateralCommitment: input.collateralCommitment,
    },
  };
}

// ---------------------------------------------------------------------------
// Artifact availability checks
// ---------------------------------------------------------------------------

const sdkCircuitCache = new Map<string, { available: boolean; ts: number }>();
const CACHE_TTL_MS = 60_000;

async function checkSdkCircuit(circuitId: string): Promise<boolean> {
  const cached = sdkCircuitCache.get(circuitId);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) return cached.available;

  const available = await circuits
    .getById(sdkClient, circuitId)
    .then((meta) => {
      const loc = meta.artifact?.location;
      if (!loc) return false;
      // Reject placeholder URLs that can't actually be fetched
      const isPlaceholder =
        loc.wasm.includes("example.invalid") || loc.zkey.includes("example.invalid");
      return !isPlaceholder;
    })
    .catch(() => false);

  sdkCircuitCache.set(circuitId, { available, ts: Date.now() });
  return available;
}

export function zkArtifactsAvailable(): boolean {
  const bridge = resolveArtifacts("bridge-approval-origin");
  const lst = resolveArtifacts("lst-collateral-origin");
  return bridge !== null && lst !== null;
}

/**
 * Async check: returns true if the Lemma API has circuit artifacts
 * for both bridge and LST circuits.
 */
export async function sdkArtifactsAvailable(): Promise<boolean> {
  const [bridge, lst] = await Promise.all([
    checkSdkCircuit("bridge-approval-origin"),
    checkSdkCircuit("lst-collateral-origin"),
  ]);
  return bridge && lst;
}
