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
 * PRODUCTION MIGRATION: @lemmaoracle/sdk equivalents
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This module performs two roles that are separate in production Lemma:
 *
 * A. Witness input construction (fieldHashOfString + poseidonHashDecimal)
 *    ────────────────────────────────────────────────────────────────────
 *    This PoC:  manually hashes identifiers and computes Poseidon commitments
 *               inline, mirroring `packages/circuits/src/inputs.ts`.
 *    Production: the SDK's `prepare(client, { schema, payload })` handles
 *                normalisation and Poseidon Merkle commitment computation
 *                (Whitepaper §4.5). The schema's WASM normalize artifact
 *                converts raw attributes to circuit-friendly field elements,
 *                and `prepare` returns:
 *                - `prep.commitments.root`   → the on-chain anchor
 *                - `prep.commitments.leaves`  → per-attribute leaf hashes
 *                - `prep.inclusionProofs`     → Merkle paths for each leaf
 *                - `prep.leafPreimages`       → (name, value, blinding) tuples
 *
 *                The circuit witness is then constructed from `prep` output:
 *                ```ts
 *                const prep = await prepare(client, {
 *                  schema: "bridge-approval-origin-v1",
 *                  payload: rawAttrs,
 *                });
 *                const witness = {
 *                  attr_commitment_root: prep.commitments.root,
 *                  randomness: prep.commitments.randomness,
 *                  leaf: prep.commitments.leaves[0],
 *                  // ... circuit-specific fields
 *                };
 *                ```
 *
 * B. Proof generation + verification
 *    ────────────────────────────────
 *    This PoC:  `proveAndVerify(circuitId, input)` generates and verifies
 *               locally (see prover.ts for SDK equivalents).
 *    Production: the two steps are separated:
 *                1. `prover.prove(client, { circuitId, witness })` — local
 *                   proof generation using wasm/zkey from `CircuitMeta`.
 *                2. `proofs.submit(client, { docHash, circuitId, proof,
 *                   inputs })` — submits to Lemma API for server-side +
 *                   on-chain verification.
 *
 * C. Full production flow for bridge origin attestation
 *    ──────────────────────────────────────────────────
 *    ```ts
 *    import { create, schemas, define, prepare, prover, proofs, documents }
 *      from "@lemmaoracle/sdk";
 *
 *    const client = create({ apiBase, apiKey });
 *
 *    // 1. Schema + circuit metadata
 *    const schemaMeta = await schemas.getById(client, "bridge-approval-origin-v1");
 *    const schema = await define(schemaMeta);
 *
 *    // 2. Normalise + commit (replaces fieldHashOfString / poseidonHashDecimal)
 *    const prep = await prepare(client, {
 *      schema: schema.id,
 *      payload: {
 *        approvalId: "0xa1b2c3",
 *        signerSet: "did:bridge:gov-multisig-v3",
 *        dstChainId: 42161,
 *        amount: "1000000000",
 *        signersPresent: 5,
 *        expiresAt: 1714069800,
 *      },
 *    });
 *    // prep.commitments.root  → originCommitment (public input)
 *    // prep.commitments.leaves → individual attribute commitments
 *
 *    // 3. Register document (anchors commitment root on-chain)
 *    await documents.register(client, {
 *      schema: schema.id,
 *      docHash: enc.docHash,
 *      cid: enc.cid,
 *      issuerId: "did:lemma:bridge-issuer",
 *      subjectId: "approval:0xa1b2c3",
 *      commitments: prep.commitments,
 *      revocation: { root: "0x0", scheme: "bitmask-merkle-v1" },
 *      signature: {
 *        format: "bbs+",
 *        payload: bbsSigHex,
 *        issuerId: "did:lemma:bridge-issuer",
 *      },
 *    });
 *
 *    // 4. Generate ZK proof (replaces local proveAndVerify)
 *    const zkResult = await prover.prove(client, {
 *      circuitId: "bridge-approval-origin-v1",
 *      witness: {
 *        attr_commitment_root: prep.commitments.root,
 *        randomness: prep.commitments.randomness,
 *        // ... circuit-specific witness fields
 *      },
 *    });
 *
 *    // 5. Submit proof for on-chain verification
 *    const result = await proofs.submit(client, {
 *      docHash: enc.docHash,
 *      circuitId: "bridge-approval-origin-v1",
 *      proof: zkResult.proof,
 *      inputs: zkResult.inputs,
 *      chainId: 84532,
 *      onchain: true,
 *    });
 *    // result.status → "onchain-verified" | "rejected"
 *    ```
 *
 * The key architectural insight: this PoC's `zkProveBridgeApproval` /
 * `zkProveLstCollateral` functions collapse normalise, commit, prove, and
 * verify into a single call chain for demo simplicity. In production, each
 * step is a distinct SDK call that goes through the Lemma API, and the
 * commitment root is anchored on-chain via `documents.register` before the
 * proof is submitted. The underlying Groth16 proof is identical — only the
 * transport and trust boundary differ.
 * ─────────────────────────────────────────────────────────────────────────────
 */
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
// Field hashing — mirrors packages/circuits/src/hash.ts
//
// Production equivalent:
//   `prepare(client, { schema, payload })` computes Poseidon Merkle
//   commitments via the schema's WASM normalize artifact. The SDK's
//   `toScalar` helper converts values to BN254 field elements: numbers
//   stay numbers, numeric strings parse via BigInt, other strings hash
//   via SHA-256 then mod prime. This PoC's `fieldHashOfString` is the
//   manual equivalent of that last path (string → SHA-256 → mod p).
// ---------------------------------------------------------------------------

function fieldHashOfString(s: string): string {
  const digest = createHash("sha256").update(s, "utf8").digest();
  digest[0] = digest[0] & 0x0f;
  return BigInt("0x" + digest.toString("hex")).toString();
}

// ---------------------------------------------------------------------------
// Poseidon — lazy-loaded, mirrors packages/circuits/src/poseidon.ts
//
// Production equivalent:
//   The SDK's `prepare` computes Poseidon Merkle commitments internally
//   using the same `circomlibjs` Poseidon implementation. The commitment
//   root (`prep.commitments.root`) is the public input to the circuit.
//   This PoC computes it directly for demo self-containment.
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

// ---------------------------------------------------------------------------
// Input builders — mirrors packages/circuits/src/inputs.ts
//
// Production equivalent:
//   The SDK's `prepare` + `prover.prove` pipeline replaces these builders.
//   `prepare` normalises raw attributes into field elements and computes
//   Poseidon commitments. `prover.prove` takes the normalised witness
//   and generates the Groth16 proof using wasm/zkey from `CircuitMeta`.
//   This PoC builds circuit inputs directly for demo self-containment.
// ---------------------------------------------------------------------------

const DEFAULT_SALT = "1234567890";

async function buildBridgeInput(
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

async function buildLstInput(
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
//
// Production equivalent for each function:
//
//   zkProveBridgeApproval →
//     1. prepare(client, { schema: "bridge-approval-origin-v1", payload: attrs })
//     2. prover.prove(client, { circuitId: "bridge-approval-origin-v1", witness })
//     3. proofs.submit(client, { docHash, circuitId, proof, inputs, onchain: true })
//
//   zkProveLstCollateral →
//     1. prepare(client, { schema: "lst-collateral-origin-v1", payload: attrs })
//     2. prover.prove(client, { circuitId: "lst-collateral-origin-v1", witness })
//     3. proofs.submit(client, { docHash, circuitId, proof, inputs, onchain: true })
//
//   zkArtifactsAvailable →
//     circuits.getById(client, circuitId) resolves successfully and
//     circuitMeta.artifact.location is present (wasm + zkey URIs exist).
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

export async function zkProveBridgeApproval(
  attrs: BridgeApprovalAttributes,
  policy: {
    policyDstChainId: number;
    policyMaxAmount: string;
    policyMinSigners: number;
    nowSec: number;
  },
): Promise<ZkBridgeResult> {
  const input = await buildBridgeInput(attrs, policy);
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
  const input = await buildLstInput(attrs, policy, validatorSetRevoked);
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

export function zkArtifactsAvailable(): boolean {
  const bridge = resolveArtifacts("bridge-approval-origin");
  const lst = resolveArtifacts("lst-collateral-origin");
  return bridge !== null && lst !== null;
}
