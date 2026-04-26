/**
 * Crypto helpers used by the PoC.
 *
 * Production Lemma uses BBS+ signatures over BLS12-381 and Poseidon over BN254.
 * Here we use HMAC-SHA256 from node:crypto so the example runs with no native
 * dependencies. The shape of the API mirrors the production primitives so the
 * surrounding flow stays representative.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { canonicalize } from "./canonical.js";

export type AttributeValue =
  | string
  | number
  | Array<string | number>;

export type IssuerKey = {
  /** 32-byte issuer secret, hex-encoded. */
  secretHex: string;
  /** Issuer DID, e.g. did:lemma:demo-issuer. */
  did: string;
};

export function generateIssuerKey(did: string): IssuerKey {
  return { secretHex: randomBytes(32).toString("hex"), did };
}

export function hmacHex(secretHex: string, message: string): string {
  const key = Buffer.from(secretHex, "hex");
  return `0x${createHmac("sha256", key).update(message, "utf8").digest("hex")}`;
}

export function randomNonceHex(bytes = 16): string {
  return `0x${randomBytes(bytes).toString("hex")}`;
}

/**
 * Poseidon-style commitment placeholder.
 *
 * `commit(key, value, randomness)` returns an HMAC-SHA256 over the canonical
 * triple. This is collision-resistant and binding for the PoC; it is *not*
 * SNARK-friendly and is not what production Lemma would use.
 */
export function commit(
  key: string,
  value: AttributeValue,
  randomnessHex: string,
): string {
  const encoded = canonicalize(value);
  const tag = Array.isArray(value) ? "array" : typeof value;
  const message = `${key}|${tag}|${encoded}|${randomnessHex}`;
  const r = Buffer.from(randomnessHex.replace(/^0x/u, ""), "hex");
  return `0x${createHmac("sha256", r).update(message, "utf8").digest("hex")}`;
}

/**
 * Merkle-ish root: SHA256 over the sorted concatenation of leaf commitments.
 * Order-independent so disclosure of a subset of leaves can be re-bound without
 * revealing position. Each leaf commitment already mixes in per-issuance
 * randomness, so the root is hiding even though this function takes no salt.
 */
export function rootOfLeaves(
  leaves: { key: string; commitment: string }[],
): string {
  const sorted = [...leaves]
    .map((l) => `${l.key}=${l.commitment}`)
    .sort()
    .join("|");
  return `0x${createHash("sha256").update(sorted, "utf8").digest("hex")}`;
}
