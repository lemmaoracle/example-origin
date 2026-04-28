/**
 * Pre-execution verification.
 *
 * `verifyAttestation` checks the signature, attribute commitments, and validity
 * window. The two domain wrappers — `verifyBridgeApproval` and
 * `verifyLstCollateral` — layer policy checks on top. They are what a bridge
 * relayer or a lending market would call *before* executing on-chain.
 *
 * The split mirrors the production Lemma split: the registered Groth16 circuit
 * (verified server-side via `proofs.submit` / on-chain via the registered
 * verifier contract) attests "the hidden witness satisfies the policy"; the
 * protocol layers add the domain trust decisions on top (chain whitelist,
 * signer threshold, validator-set freshness …) that don't belong in-circuit.
 */
import { canonicalize } from "./canonical.js";
import { commit, hmacHex, rootOfLeaves } from "./crypto.js";
import type { IssuerKey } from "./crypto.js";
import {
  AttestationSchema,
  BridgeApprovalAttributesSchema,
  LstCollateralAttributesSchema,
  type Attestation,
  type RevocationList,
  type VerificationResult,
} from "./types.js";

export type VerifyOptions = {
  /** Issuer trusted by the verifier. Signature is checked against this key. */
  issuer: IssuerKey;
  /** Override `now` (seconds since epoch) for deterministic tests. */
  nowSec?: number;
  /** Optional revocation list. */
  revocations?: RevocationList;
};

const ZERO_REVOCATIONS: RevocationList = { subjects: [], validatorSetRoots: [] };

function fail(
  schema: VerificationResult["schema"],
  reason: string,
  notes: string[] = [],
): VerificationResult {
  return { ok: false, schema, reason, notes };
}

/** Verify the cryptographic core of an attestation: shape, signature, commitments, validity. */
export function verifyAttestation(
  raw: unknown,
  opts: VerifyOptions,
): VerificationResult {
  const parsed = AttestationSchema.safeParse(raw);
  if (!parsed.success) {
    return fail("unknown", `malformed attestation: ${parsed.error.message}`);
  }
  const att = parsed.data;
  const notes: string[] = [];

  if (att.issuerId !== opts.issuer.did) {
    return fail(att.schema, `unknown issuer ${att.issuerId}`);
  }

  // Validity window
  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  if (now < att.notBefore) {
    return fail(att.schema, `attestation not yet valid (notBefore=${att.notBefore})`);
  }
  if (now > att.notAfter) {
    return fail(att.schema, `attestation expired at ${att.notAfter}`);
  }

  // Recompute the leaves root from the bundled commitments. Tampering with any
  // leaf changes the root, which then mismatches the signed root.
  const recomputed = rootOfLeaves(att.disclosure.commitments.leaves);

  // Signature check
  const expected = hmacHex(
    opts.issuer.secretHex,
    canonicalize({
      schema: att.schema,
      issuerId: att.issuerId,
      subjectId: att.subjectId,
      attributesRoot: att.attributesRoot,
    }),
  );
  if (expected !== att.signature) {
    return fail(att.schema, "signature mismatch");
  }

  // For each revealed attribute, reconstruct the leaf commitment and confirm it
  // matches the bundled leaf. Hidden leaves omit randomness, so we cannot (and
  // should not) recompute them.
  for (const [key, value] of Object.entries(att.disclosure.revealed)) {
    const leaf = att.disclosure.commitments.leaves.find((l) => l.key === key);
    if (!leaf) {
      return fail(att.schema, `revealed key "${key}" missing from commitments`);
    }
    if (!leaf.randomness) {
      return fail(att.schema, `revealed key "${key}" is missing leaf randomness`);
    }
    const expectedLeaf = commit(
      key,
      value as Parameters<typeof commit>[1],
      leaf.randomness,
    );
    if (expectedLeaf !== leaf.commitment) {
      return fail(att.schema, `commitment mismatch for "${key}"`);
    }
  }

  // The disclosure-root we recomputed must match the signed root. If anyone
  // tampered with leaves (added/removed/reordered) we surface it here.
  if (recomputed !== att.attributesRoot) {
    return fail(att.schema, "attributes root mismatch");
  }

  // Revocation
  const rev = opts.revocations ?? ZERO_REVOCATIONS;
  if (rev.subjects.includes(att.subjectId)) {
    return fail(att.schema, `subject ${att.subjectId} is revoked`);
  }

  notes.push(
    `${att.disclosure.hidden.length} attribute(s) kept hidden`,
    `validity window: ${att.notBefore} → ${att.notAfter}`,
  );

  return {
    ok: true,
    schema: att.schema,
    revealed: att.disclosure.revealed,
    notes,
  };
}

// ---------------------------------------------------------------------------
// Domain wrappers
// ---------------------------------------------------------------------------

export type BridgePolicy = {
  /** Allowed source chain ids. */
  allowedSrcChainIds: number[];
  /** Allowed destination chain ids. */
  allowedDstChainIds: number[];
  /** Maximum amount (base units) the bridge will execute against this attestation. */
  maxAmount: bigint;
  /** Minimum signer threshold the off-chain approval set must satisfy. */
  minSignersPresent: number;
  /** Maximum age (seconds) of the off-chain approval relative to `nowSec`. Prevents replay of stale pre-signed authorisations. */
  maxApprovalAgeSec: number;
};

/**
 * Pre-execution check for a bridge approval.
 *
 * Wrapped flow: cryptographic verification → domain policy. A relayer should
 * refuse to execute if either layer fails, *before* any on-chain call.
 */
export function verifyBridgeApproval(
  raw: unknown,
  opts: VerifyOptions & { policy: BridgePolicy },
): VerificationResult {
  const base = verifyAttestation(raw, opts);
  if (!base.ok) return base;
  if (base.schema !== "bridge-approval-v1") {
    return fail(base.schema, `expected bridge-approval-v1, got ${base.schema}`);
  }
  // Only the fields the policy actually consumes need to be revealed; everything
  // else can be hidden behind a commitment.
  const policyShape = BridgeApprovalAttributesSchema.pick({
    kind: true,
    signerSet: true,
    signerThreshold: true,
    signersPresent: true,
    srcChainId: true,
    dstChainId: true,
    asset: true,
    amount: true,
    approvedAt: true,
    expiresAt: true,
  });
  const attrs = policyShape.safeParse({
    kind: "bridge-approval-v1",
    ...base.revealed,
  });
  if (!attrs.success) {
    return fail(
      "bridge-approval-v1",
      `revealed attributes incomplete for bridge policy: ${attrs.error.message}`,
    );
  }
  const a = attrs.data;
  const notes = [...base.notes];

  if (!opts.policy.allowedSrcChainIds.includes(a.srcChainId)) {
    return fail("bridge-approval-v1", `src chain ${a.srcChainId} not allowed`, notes);
  }
  if (!opts.policy.allowedDstChainIds.includes(a.dstChainId)) {
    return fail("bridge-approval-v1", `dst chain ${a.dstChainId} not allowed`, notes);
  }
  if (BigInt(a.amount) > opts.policy.maxAmount) {
    return fail(
      "bridge-approval-v1",
      `amount ${a.amount} exceeds policy max ${opts.policy.maxAmount.toString()}`,
      notes,
    );
  }
  if (a.signersPresent < opts.policy.minSignersPresent) {
    return fail(
      "bridge-approval-v1",
      `only ${a.signersPresent} signers present, need ${opts.policy.minSignersPresent}`,
      notes,
    );
  }
  if (a.signersPresent < a.signerThreshold) {
    return fail(
      "bridge-approval-v1",
      `signers ${a.signersPresent} below approval-set threshold ${a.signerThreshold}`,
      notes,
    );
  }

  // Approval age — prevents replay of stale pre-signed authorisations (Drift-style)
  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const approvalAge = now - a.approvedAt;
  if (approvalAge > opts.policy.maxApprovalAgeSec) {
    return fail(
      "bridge-approval-v1",
      `approval age ${approvalAge}s exceeds max ${opts.policy.maxApprovalAgeSec}s`,
      notes,
    );
  }

  // Approval expiry — the off-chain authorisation must not have expired.
  // This is distinct from the attestation's notAfter (Lemma issuance window):
  //   expiresAt = when the *bridge approval* itself expires
  //   notAfter  = when the *attestation wrapping it* expires
  if (now > a.expiresAt) {
    return fail(
      "bridge-approval-v1",
      `approval expired at ${a.expiresAt}, now is ${now}`,
      notes,
    );
  }

  const recipientLabel = (base.revealed.recipient as string | undefined) ?? "(hidden)";
  notes.push(
    `bridge: ${a.asset} ${a.amount} ${a.srcChainId} → ${a.dstChainId} for ${recipientLabel}`,
    `signer set ${a.signerSet}: ${a.signersPresent}/${a.signerThreshold}`,
  );
  return { ok: true, schema: "bridge-approval-v1", revealed: base.revealed, notes };
}

export type LstPolicy = {
  /** Allowed mint chain ids (where the LST/LRT was minted). */
  allowedMintChainIds: number[];
  /** Maximum allowed rehypothecation depth (0 = no rehypothecation, 1 = one re-stake hop, …). */
  maxRehypothecationDepth: number;
  /** Custody addresses/labels the lender trusts as final-leg custodians. */
  trustedCustodians: string[];
  /** Maximum age (seconds) of the mint event relative to `nowSec`. */
  maxMintAgeSec: number;
};

/**
 * Pre-execution check for an LST/LRT collateral lot before it's accepted into a
 * lending market. Layered: cryptographic verification → revocation by validator
 * set → domain policy.
 */
export function verifyLstCollateral(
  raw: unknown,
  opts: VerifyOptions & { policy: LstPolicy },
): VerificationResult {
  const base = verifyAttestation(raw, opts);
  if (!base.ok) return base;
  if (base.schema !== "lst-collateral-v1") {
    return fail(base.schema, `expected lst-collateral-v1, got ${base.schema}`);
  }
  const policyShape = LstCollateralAttributesSchema.pick({
    kind: true,
    lotId: true,
    asset: true,
    amount: true,
    mintChainId: true,
    mintedAt: true,
    custodyPath: true,
    validatorSetRoot: true,
    rehypothecationDepth: true,
  });
  const attrs = policyShape.safeParse({
    kind: "lst-collateral-v1",
    ...base.revealed,
  });
  if (!attrs.success) {
    return fail(
      "lst-collateral-v1",
      `revealed attributes incomplete for LST policy: ${attrs.error.message}`,
      base.notes,
    );
  }
  const a = attrs.data;
  const notes = [...base.notes];

  const rev = opts.revocations ?? ZERO_REVOCATIONS;
  if (rev.validatorSetRoots.includes(a.validatorSetRoot)) {
    return fail(
      "lst-collateral-v1",
      `validator-set root ${a.validatorSetRoot} is revoked (slashed/operator-compromised)`,
      notes,
    );
  }

  if (!opts.policy.allowedMintChainIds.includes(a.mintChainId)) {
    return fail(
      "lst-collateral-v1",
      `mint chain ${a.mintChainId} not allowed`,
      notes,
    );
  }
  if (a.rehypothecationDepth > opts.policy.maxRehypothecationDepth) {
    return fail(
      "lst-collateral-v1",
      `rehypothecation depth ${a.rehypothecationDepth} exceeds max ${opts.policy.maxRehypothecationDepth}`,
      notes,
    );
  }

  const finalCustodian = a.custodyPath[a.custodyPath.length - 1];
  if (!opts.policy.trustedCustodians.includes(finalCustodian!)) {
    return fail(
      "lst-collateral-v1",
      `final custodian "${finalCustodian}" not in trusted set`,
      notes,
    );
  }

  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const ageSec = now - a.mintedAt;
  if (ageSec > opts.policy.maxMintAgeSec) {
    return fail(
      "lst-collateral-v1",
      `mint age ${ageSec}s exceeds max ${opts.policy.maxMintAgeSec}s`,
      notes,
    );
  }

  notes.push(
    `collateral: ${a.asset} ${a.amount} (lot ${a.lotId})`,
    `custody path: ${a.custodyPath.join(" → ")}`,
    `validator-set root: ${a.validatorSetRoot}`,
    `rehypothecation depth: ${a.rehypothecationDepth}`,
  );
  return { ok: true, schema: "lst-collateral-v1", revealed: base.revealed, notes };
}
