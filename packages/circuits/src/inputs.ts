/**
 * Deterministic input builders for the two demo circuits.
 *
 * These produce the JSON files snarkjs / circom expect for `wtns calculate`.
 * The same Poseidon implementation that lives inside the circuit is used here
 * to derive the public commitment, so circuit and JS always agree.
 */
import { z } from "zod";
import { fieldHashOfString } from "./hash.js";
import { poseidonHashDecimal } from "./poseidon.js";

export const BridgeApprovalRawSchema = z.object({
  approvalId: z.string().min(1),
  signerSet: z.string().min(1),
  dstChainId: z.number().int().positive(),
  amount: z.string().regex(/^\d+$/u),
  signersPresent: z.number().int().nonnegative(),
  validUntil: z.number().int().positive(),
  salt: z.string().regex(/^\d+$/u).optional(),
});
export type BridgeApprovalRaw = z.infer<typeof BridgeApprovalRawSchema>;

export const BridgePolicyInputSchema = z.object({
  policyDstChainId: z.number().int().positive(),
  policyMaxAmount: z.string().regex(/^\d+$/u),
  policyMinSigners: z.number().int().nonnegative(),
  nowSec: z.number().int().positive(),
});
export type BridgePolicyInput = z.infer<typeof BridgePolicyInputSchema>;

export type BridgeCircuitInput = {
  // public
  originCommitment: string;
  policyDstChainId: string;
  policyMaxAmount: string;
  policyMinSigners: string;
  nowSec: string;
  // private
  approvalIdHash: string;
  signerSetHash: string;
  dstChainId: string;
  amount: string;
  signersPresent: string;
  validUntil: string;
  salt: string;
};

const DEFAULT_SALT = "1234567890";

export async function buildBridgeApprovalInput(
  raw: BridgeApprovalRaw,
  policy: BridgePolicyInput,
): Promise<BridgeCircuitInput> {
  const r = BridgeApprovalRawSchema.parse(raw);
  const p = BridgePolicyInputSchema.parse(policy);

  const approvalIdHash = fieldHashOfString(r.approvalId);
  const signerSetHash = fieldHashOfString(r.signerSet);
  const salt = r.salt ?? DEFAULT_SALT;

  const originCommitment = await poseidonHashDecimal([
    BigInt(approvalIdHash),
    BigInt(signerSetHash),
    BigInt(r.dstChainId),
    BigInt(r.amount),
    BigInt(r.signersPresent),
    BigInt(r.validUntil),
    BigInt(salt),
  ]);

  return {
    originCommitment,
    policyDstChainId: String(p.policyDstChainId),
    policyMaxAmount: p.policyMaxAmount,
    policyMinSigners: String(p.policyMinSigners),
    nowSec: String(p.nowSec),
    approvalIdHash,
    signerSetHash,
    dstChainId: String(r.dstChainId),
    amount: r.amount,
    signersPresent: String(r.signersPresent),
    validUntil: String(r.validUntil),
    salt,
  };
}

export const LstCollateralRawSchema = z.object({
  lotId: z.string().min(1),
  assetId: z.string().min(1),
  mintChainId: z.number().int().positive(),
  custodyHops: z.number().int().nonnegative(),
  rehypothecationDepth: z.number().int().nonnegative(),
  validatorSetRevoked: z.union([z.literal(0), z.literal(1)]),
  mintedAt: z.number().int().positive(),
  salt: z.string().regex(/^\d+$/u).optional(),
});
export type LstCollateralRaw = z.infer<typeof LstCollateralRawSchema>;

export const LstPolicyInputSchema = z.object({
  policyAssetId: z.string().min(1),
  policyMaxRehypoDepth: z.number().int().nonnegative(),
  policyMaxCustodyHops: z.number().int().nonnegative(),
  policyMinMintAge: z.number().int().nonnegative(),
  nowSec: z.number().int().positive(),
});
export type LstPolicyInput = z.infer<typeof LstPolicyInputSchema>;

export type LstCircuitInput = {
  collateralCommitment: string;
  policyAssetIdHash: string;
  policyMaxRehypoDepth: string;
  policyMaxCustodyHops: string;
  policyMinMintAge: string;
  nowSec: string;
  lotIdHash: string;
  assetIdHash: string;
  mintChainId: string;
  custodyHops: string;
  rehypothecationDepth: string;
  validatorSetRevoked: string;
  mintedAt: string;
  salt: string;
};

export async function buildLstCollateralInput(
  raw: LstCollateralRaw,
  policy: LstPolicyInput,
): Promise<LstCircuitInput> {
  const r = LstCollateralRawSchema.parse(raw);
  const p = LstPolicyInputSchema.parse(policy);

  const lotIdHash = fieldHashOfString(r.lotId);
  const assetIdHash = fieldHashOfString(r.assetId);
  const policyAssetIdHash = fieldHashOfString(p.policyAssetId);
  const salt = r.salt ?? DEFAULT_SALT;

  const collateralCommitment = await poseidonHashDecimal([
    BigInt(lotIdHash),
    BigInt(assetIdHash),
    BigInt(r.mintChainId),
    BigInt(r.custodyHops),
    BigInt(r.rehypothecationDepth),
    BigInt(r.validatorSetRevoked),
    BigInt(r.mintedAt),
    BigInt(salt),
  ]);

  return {
    collateralCommitment,
    policyAssetIdHash,
    policyMaxRehypoDepth: String(p.policyMaxRehypoDepth),
    policyMaxCustodyHops: String(p.policyMaxCustodyHops),
    policyMinMintAge: String(p.policyMinMintAge),
    nowSec: String(p.nowSec),
    lotIdHash,
    assetIdHash,
    mintChainId: String(r.mintChainId),
    custodyHops: String(r.custodyHops),
    rehypothecationDepth: String(r.rehypothecationDepth),
    validatorSetRevoked: String(r.validatorSetRevoked),
    mintedAt: String(r.mintedAt),
    salt,
  };
}
