import { createHash } from "node:crypto";

/**
 * Hash an arbitrary string into a BN254-safe field element.
 *
 * Returns a decimal string < 2^248 so it always fits inside the prime field.
 * The circuits don't verify *which* hash function is used — they just check
 * equality between witness and the public commitment. Anything stable works.
 */
export function fieldHashOfString(s: string): string {
  const digest = createHash("sha256").update(s, "utf8").digest();
  // Mask the top byte to 0x0f so the resulting integer is < 2^252 < BN254 prime.
  digest[0] = digest[0] & 0x0f;
  return BigInt("0x" + digest.toString("hex")).toString();
}
