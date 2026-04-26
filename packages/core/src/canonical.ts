/**
 * Canonical encoding helpers.
 *
 * The PoC needs a stable byte representation for hashing/HMAC. We use a sorted-key
 * JSON encoder: every object has its keys lexicographically ordered before
 * serialisation. This is deliberately not RFC 8785 — the goal is determinism, not
 * interoperability with external JCS implementations.
 */

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`);
  return `{${parts.join(",")}}`;
}
