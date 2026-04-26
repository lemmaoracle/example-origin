/**
 * Origin-attestation issuance.
 *
 * The issuer takes raw attributes, picks which fields stay hidden, and emits a
 * signed attestation with selective-disclosure commitments. The verifier never
 * sees the hidden values — only their commitments — but can still re-bind any
 * disclosed value to the signed root.
 */
import { canonicalize } from "./canonical.js";
import { commit, hmacHex, randomNonceHex, rootOfLeaves } from "./crypto.js";
import type { IssuerKey } from "./crypto.js";
import {
  AttestationAttributesSchema,
  type AttestationAttributes,
  type Attestation,
  type Disclosure,
  type RevealedAttributes,
} from "./types.js";

export type IssueOptions = {
  /** Attribute keys to keep hidden (only commitments are revealed). */
  hide?: readonly string[];
  /** Validity window (seconds). Defaults to 1 hour. */
  ttlSec?: number;
  /** Override `now` (seconds since epoch). For deterministic tests. */
  nowSec?: number;
  /** Override the per-leaf randomness salt. For deterministic tests. */
  randomnessHex?: string;
};

/**
 * Issue an origin attestation over `attributes`, hiding the fields listed in
 * `opts.hide`. The signature covers issuer, subject, schema id and the leaves
 * root — so substituting either revealed values, the schema, or the issuer
 * invalidates the attestation.
 */
export function issueAttestation(
  issuer: IssuerKey,
  subjectId: string,
  attributes: AttestationAttributes,
  opts: IssueOptions = {},
): Attestation {
  const parsed = AttestationAttributesSchema.parse(attributes);
  const hide = new Set(opts.hide ?? []);
  const ttl = opts.ttlSec ?? 3600;
  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const randomness = opts.randomnessHex ?? randomNonceHex(16);

  const entries = Object.entries(parsed).filter(([k]) => k !== "kind");

  // Per-leaf randomness derived deterministically from a single nonce so we can
  // expose only the slices belonging to revealed leaves.
  const leafRandomness = (key: string): string =>
    `0x${Buffer.from(
      hmacHex(randomness.replace(/^0x/u, ""), `leaf:${key}`).slice(2),
      "hex",
    ).toString("hex")}`;

  const leavesAll = entries.map(([key, value]) => {
    const r = leafRandomness(key);
    return {
      key,
      commitment: commit(key, value as Parameters<typeof commit>[1], r),
      randomness: r,
    };
  });

  const revealed: RevealedAttributes = {};
  const hidden: string[] = [];
  for (const [key, value] of entries) {
    if (hide.has(key)) {
      hidden.push(key);
    } else {
      revealed[key] = value as RevealedAttributes[string];
    }
  }

  // For hidden leaves, strip the randomness so the verifier can re-bind the root
  // but cannot brute-force the attribute value.
  const leaves = leavesAll.map((l) =>
    hide.has(l.key)
      ? { key: l.key, commitment: l.commitment }
      : l,
  );

  const attributesRoot = rootOfLeaves(leaves);

  const signingPayload = canonicalize({
    schema: parsed.kind,
    issuerId: issuer.did,
    subjectId,
    attributesRoot,
  });
  const signature = hmacHex(issuer.secretHex, signingPayload);

  const disclosure: Disclosure = {
    revealed,
    hidden,
    commitments: {
      scheme: "hmac-sha256-poc",
      root: attributesRoot,
      leaves,
    },
  };

  return {
    schema: parsed.kind,
    issuerId: issuer.did,
    subjectId,
    attributesRoot,
    disclosure,
    signature,
    notBefore: now,
    notAfter: now + ttl,
  };
}
