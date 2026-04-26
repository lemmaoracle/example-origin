/**
 * Manifest schemas for the two demo circuits.
 *
 * The repo ships JSON manifests under `presets/circuits/*.json` and
 * `presets/schemes/*.json` that mirror Lemma's `CircuitMeta` / `SchemaMeta`
 * shapes (see `@lemmaoracle/spec`). The registration script validates against
 * these schemas before sending anything over the wire.
 */
import { z } from "zod";

const HttpsOrIpfsUri = z
  .string()
  .regex(
    /^(https:\/\/|ipfs:\/\/)/u,
    "artifact URI must use https:// or ipfs:// scheme",
  );

export const CircuitArtifactLocationSchema = z.object({
  type: z.enum(["ipfs", "https"]),
  wasm: HttpsOrIpfsUri,
  zkey: HttpsOrIpfsUri,
});

export const CircuitVerifierSchema = z.object({
  type: z.enum(["onchain", "offchain"]),
  address: z
    .string()
    .regex(/^0x[0-9a-fA-F]{40}$/u, "address must be 0x + 40 hex chars")
    .optional(),
  chainId: z.number().int().positive().optional(),
  alg: z.literal("groth16-bn254-snarkjs").optional(),
});

export const CircuitMetaSchema = z.object({
  circuitId: z.string().min(1),
  schema: z.string().min(1),
  description: z.string().optional(),
  inputs: z.array(z.string().min(1)).nonempty(),
  verifiers: z.array(CircuitVerifierSchema).nonempty(),
  artifact: z.object({ location: CircuitArtifactLocationSchema }),
});
export type CircuitManifest = z.infer<typeof CircuitMetaSchema>;

export const NormalizeArtifactSchema = z.object({
  artifact: z.object({
    type: z.enum(["ipfs", "https"]),
    wasm: HttpsOrIpfsUri,
    js: HttpsOrIpfsUri,
  }),
  hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/u),
  abi: z
    .object({
      raw: z.record(z.string(), z.string()),
      norm: z.record(z.string(), z.string()),
    })
    .optional(),
});

export const SchemaMetaSchema = z.object({
  id: z.string().min(1),
  description: z.string().optional(),
  normalize: NormalizeArtifactSchema,
});
export type SchemeManifest = z.infer<typeof SchemaMetaSchema>;
