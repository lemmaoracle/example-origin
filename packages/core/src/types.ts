/**
 * Type definitions for origin attestations.
 *
 * An origin attestation is a signed claim about the *provenance* of an off-chain
 * artefact (a bridge approval, an LST mint event, …) plus selectively-disclosable
 * attributes that downstream verifiers consume before executing on-chain actions.
 *
 * The on-the-wire shape mimics the W3C VC + BBS+ / Poseidon-commit pattern used by
 * the production Lemma stack. In this PoC the proof is a deterministic HMAC over a
 * canonical encoding so the example is self-contained.
 */
import { z } from "zod";

export const HexString = z
  .string()
  .regex(/^0x[0-9a-fA-F]+$/u, "must be a 0x-prefixed hex string");

export const AttestationKindSchema = z.enum([
  "bridge-approval-v1",
  "lst-collateral-v1",
]);
export type AttestationKind = z.infer<typeof AttestationKindSchema>;

/**
 * Origin attributes for a bridge approval.
 *
 * The minimal set a downstream bridge contract / relayer needs to decide whether
 * to *execute* an approval that was authorised off-chain (e.g. via a 1-of-N
 * signer set, a centralised front-end, or a CEX-issued approval).
 */
export const BridgeApprovalAttributesSchema = z.object({
  kind: z.literal("bridge-approval-v1"),
  approvalId: z.string().min(1),
  signerSet: z.string().min(1),
  signerThreshold: z.number().int().positive(),
  signersPresent: z.number().int().positive(),
  srcChainId: z.number().int().positive(),
  dstChainId: z.number().int().positive(),
  asset: z.string().min(1),
  amount: z.string().regex(/^\d+$/u, "amount must be a base-10 integer string"),
  recipient: HexString,
  approvedAt: z.number().int().positive(),
  expiresAt: z.number().int().positive(),
});
export type BridgeApprovalAttributes = z.infer<
  typeof BridgeApprovalAttributesSchema
>;

/**
 * Origin attributes for an LST/LRT collateral lot before it is re-collateralised
 * inside a lending market.
 */
export const LstCollateralAttributesSchema = z.object({
  kind: z.literal("lst-collateral-v1"),
  lotId: z.string().min(1),
  asset: z.string().min(1),
  amount: z.string().regex(/^\d+$/u, "amount must be a base-10 integer string"),
  mintChainId: z.number().int().positive(),
  mintTxHash: HexString,
  mintedAt: z.number().int().positive(),
  custodyPath: z.array(z.string().min(1)).min(1),
  validatorSetRoot: HexString,
  rehypothecationDepth: z.number().int().nonnegative(),
});
export type LstCollateralAttributes = z.infer<
  typeof LstCollateralAttributesSchema
>;

export const AttestationAttributesSchema = z.union([
  BridgeApprovalAttributesSchema,
  LstCollateralAttributesSchema,
]);
export type AttestationAttributes = z.infer<typeof AttestationAttributesSchema>;

/**
 * Selective disclosure descriptor.
 *
 * `revealed` is the subset of attribute keys whose plaintext is included.
 * `commitments` are Poseidon-style leaf commitments for the *full* attribute set,
 * letting a verifier re-bind disclosed values to the signed root without seeing
 * the hidden ones. In this PoC the leaf commitment is HMAC-SHA256 over
 * (key, value, randomness); the production stack uses Poseidon over BN254.
 */
/**
 * Attribute values are scalars (string|number) or arrays of scalars (e.g. the
 * LST custody path). The leaf commitment for an array value covers its
 * canonical-JSON encoding, so the verifier can re-bind it the same way.
 */
const AttributeValue = z.union([
  z.string(),
  z.number(),
  z.array(z.union([z.string(), z.number()])),
]);

export const DisclosureSchema = z.object({
  revealed: z.record(z.string(), AttributeValue),
  hidden: z.array(z.string()),
  commitments: z.object({
    scheme: z.literal("hmac-sha256-poc"),
    root: HexString,
    /**
     * Per-leaf entries. `randomness` is included only for revealed leaves so a
     * verifier can recompute their commitments. Hidden leaves expose only
     * `key` and `commitment`.
     */
    leaves: z.array(
      z.object({
        key: z.string(),
        commitment: HexString,
        randomness: HexString.optional(),
      }),
    ),
  }),
});
export type Disclosure = z.infer<typeof DisclosureSchema>;

export const AttestationSchema = z.object({
  schema: AttestationKindSchema,
  issuerId: z.string().min(1),
  subjectId: z.string().min(1),
  attributesRoot: HexString,
  disclosure: DisclosureSchema,
  /** HMAC-SHA256 signature over canonical(issuerId | subjectId | schema | attributesRoot) */
  signature: HexString,
  notBefore: z.number().int().positive(),
  notAfter: z.number().int().positive(),
});
export type Attestation = z.infer<typeof AttestationSchema>;

export type RevealedAttributes = Record<
  string,
  string | number | Array<string | number>
>;

export type VerificationOk = {
  ok: true;
  schema: AttestationKind;
  revealed: RevealedAttributes;
  notes: string[];
};
export type VerificationFail = {
  ok: false;
  schema: AttestationKind | "unknown";
  reason: string;
  notes: string[];
};
export type VerificationResult = VerificationOk | VerificationFail;

export type RevocationList = {
  /** Revoked subjectIds (e.g. "approval:0xabc…", "lot:rsETH-2026-04-22-#7"). */
  subjects: string[];
  /** Revoked validator-set roots, as 0x-hex. */
  validatorSetRoots: string[];
};
