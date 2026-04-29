/**
 * Local Groth16 proof generation and verification.
 *
 * This module bridges the Circom circuit pipeline with the core attestation
 * flow. Given circuit build artifacts (wasm + zkey), it can generate a Groth16
 * proof for a witness and verify it against the verification key — proving in
 * zero knowledge that the hidden witness satisfies the public policy.
 *
 * The demo uses this alongside the TypeScript policy verifier to demonstrate
 * the layered architecture:
 *
 *   ZK circuit  → proves commitment binding + in-circuit policy constraints
 *   TS verifier → checks off-circuit policy (issuer sig, revocation, replay)
 *
 * Both must pass for a real execution. This split is not a shortcut — it
 * mirrors the production Lemma architecture where the circuit handles what
 * belongs in ZK and the protocol layer handles the rest.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PRODUCTION MIGRATION: @lemmaoracle/sdk equivalents
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This module performs local proof generation using file-system paths to the
 * compiled circuit artifacts. In production, every operation here maps to a
 * Lemma SDK call that resolves artifacts from the Lemma API and submits proofs
 * for server-side / on-chain verification. The correspondence is:
 *
 * 1. Artifact resolution (`resolveArtifacts`)
 *    ─────────────────────────────────────────
 *    This PoC:  reads wasm/zkey/vkey from `packages/circuits/build/` on disk.
 *    Production: `circuits.getById(client, circuitId)` fetches `CircuitMeta`
 *                from `GET /v1/circuits/:circuitId`, which includes:
 *                - `artifact.location.wasm` (IPFS or HTTPS URI)
 *                - `artifact.location.zkey` (IPFS or HTTPS URI)
 *                - `verifiers[]` (on-chain verifier contract addresses)
 *
 *    Production code:
 *    ```ts
 *    import { circuits } from "@lemmaoracle/sdk";
 *    const meta = await circuits.getById(client, "bridge-approval-origin-v1");
 *    // meta.artifact.location.wasm → "ipfs://Qm.../circuit.wasm"
 *    // meta.artifact.location.zkey → "ipfs://Qm.../circuit_final.zkey"
 *    // meta.verifiers[0].address  → "0xVerifierBase" (on-chain Groth16 verifier)
 *    ```
 *
 * 2. Proof generation (`groth16Prove`)
 *    ──────────────────────────────────
 *    This PoC:  calls `snarkjs.groth16.fullProve(witness, wasmPath, zkeyPath)`
 *               with local file paths.
 *    Production: `prover.prove(client, { circuitId, witness })` — the SDK
 *                internally resolves `CircuitMeta` via `circuits.getById`,
 *                downloads wasm/zkey from IPFS/HTTPS into Uint8Array buffers,
 *                and calls `snarkjs.groth16.fullProve(witness, wasmBuf, zkeyBuf)`.
 *                When artifacts are unavailable, it falls back to a SHA-256
 *                commitment hash (not a valid ZK proof, but allows local-dev).
 *
 *    Production code:
 *    ```ts
 *    import { prover } from "@lemmaoracle/sdk";
 *    const zkResult = await prover.prove(client, {
 *      circuitId: "bridge-approval-origin-v1",
 *      witness: {
 *        approvalIdHash: "...", signerSetHash: "...", dstChainId: "42161",
 *        amount: "1000000000", signersPresent: "5", validUntil: "1714069800",
 *        salt: "1234567890",
 *        // The SDK also supports passing commitmentRoot / attr_commitment_root
 *        // for Merkle-path-based circuits that reference prepare() output.
 *      },
 *    });
 *    // zkResult.proof  → base64-encoded JSON of the Groth16 proof
 *    // zkResult.inputs → public signals (commitment, policy params, nowSec)
 *    ```
 *
 * 3. Proof verification (`groth16Verify`)
 *    ─────────────────────────────────────
 *    This PoC:  calls `snarkjs.groth16.verify(vkey, publicSignals, proof)`
 *               with a local verification_key.json.
 *    Production: `proofs.submit(client, { docHash, circuitId, proof, inputs })`
 *                — submits to `POST /v1/proofs` where the Lemma Workers
 *                backend verifies server-side and optionally settles on-chain
 *                via the registered verifier contract (`LemmaProofSettlement`).
 *                The response status transitions through:
 *                `received → verifying → verified → onchain-verified | rejected`
 *
 *    Production code:
 *    ```ts
 *    import { proofs } from "@lemmaoracle/sdk";
 *    const result = await proofs.submit(client, {
 *      docHash: "0x...",                          // from documents.register
 *      circuitId: "bridge-approval-origin-v1",
 *      proof: zkResult.proof,                     // from prover.prove
 *      inputs: zkResult.inputs,                   // from prover.prove
 *      chainId: 84532,                            // target chain for on-chain verification
 *      onchain: true,                             // trigger on-chain settlement
 *    });
 *    // result.status         → "verified" | "onchain-verified" | "rejected"
 *    // result.verificationId → unique ID for this verification attempt
 *    ```
 *
 * 4. Full production flow (end-to-end)
 *    ──────────────────────────────────
 *    The complete Lemma production flow for a bridge origin attestation is:
 *
 *    ```ts
 *    import { create, schemas, define, prepare, prover, proofs, documents }
 *      from "@lemmaoracle/sdk";
 *
 *    // a. Initialise client
 *    const client = create({ apiBase: "https://workers.lemma.workers.dev", apiKey });
 *
 *    // b. Resolve schema + circuit metadata from Lemma API
 *    const schemaMeta = await schemas.getById(client, "bridge-approval-origin-v1");
 *    const schema = await define(schemaMeta);  // downloads WASM normalize artifact
 *    const circuitMeta = await circuits.getById(client, "bridge-approval-origin-v1");
 *
 *    // c. Normalise + commit (Poseidon Merkle)
 *    const prep = await prepare(client, { schema: schema.id, payload: rawAttrs });
 *    // prep.commitments.root   → on-chain anchor
 *    // prep.commitments.leaves → per-attribute Poseidon commitments
 *    // prep.inclusionProofs   → Merkle paths for selective attribute proofs
 *
 *    // d. Register document (anchors docHash + commitment root on-chain)
 *    await documents.register(client, {
 *      schema: schema.id,
 *      docHash: enc.docHash,       // from encrypt()
 *      cid: enc.cid,               // IPFS CID of encrypted document
 *      issuerId: "did:lemma:bridge-issuer",
 *      subjectId: "approval:0xa1b2c3",
 *      commitments: prep.commitments,
 *      revocation: { root: "0x0", scheme: "bitmask-merkle-v1" },
 *      signature: { format: "bbs+", payload: bbsSigHex, issuerId: "did:lemma:bridge-issuer" },
 *    });
 *
 *    // e. Generate ZK proof locally
 *    const zkResult = await prover.prove(client, {
 *      circuitId: "bridge-approval-origin-v1",
 *      witness: { ...witnessFromCircuitInput },
 *    });
 *
 *    // f. Submit proof for server-side + on-chain verification
 *    const proofResult = await proofs.submit(client, {
 *      docHash: enc.docHash,
 *      circuitId: "bridge-approval-origin-v1",
 *      proof: zkResult.proof,
 *      inputs: zkResult.inputs,
 *      chainId: 84532,
 *      onchain: true,
 *    });
 *    // proofResult.status → "onchain-verified" means the Groth16 proof
 *    // was verified by the LemmaProofSettlement contract on-chain.
 *    ```
 *
 * The key difference: this PoC resolves artifacts from the local filesystem
 * and verifies proofs in-process, while the Lemma SDK resolves them from the
 * API, submits proofs to the Workers backend, and optionally settles them
 * on-chain via the verifier contract. The underlying snarkjs Groth16
 * operations are identical — only the artifact transport and verification
 * trust boundary differ.
 * ─────────────────────────────────────────────────────────────────────────────
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// packages/core/src → packages/circuits/build
const CIRCUITS_BUILD = resolve(__dirname, "../../circuits/build");

export type CircuitArtifacts = {
  readonly wasmPath: string;
  readonly zkeyPath: string;
  readonly vkeyPath: string;
};

export type Groth16Proof = {
  readonly proof: {
    readonly pi_a: readonly string[];
    readonly pi_b: readonly (readonly string[])[];
    readonly pi_c: readonly string[];
    readonly protocol: string;
    readonly curve: string;
  };
  readonly publicSignals: readonly string[];
};

export type ProofResult = {
  readonly proof: Groth16Proof;
  readonly verified: boolean;
  readonly circuitId: string;
};

const CIRCUIT_IDS = [
  "bridge-approval-origin",
  "lst-collateral-origin",
] as const;

/**
 * Resolve circuit artifacts from the local build directory.
 *
 * Production equivalent:
 *   `circuits.getById(client, circuitId)` → fetches `CircuitMeta` including
 *   `artifact.location` (IPFS/HTTPS URIs for wasm + zkey) and `verifiers[]`
 *   (on-chain Groth16 verifier contract addresses). The SDK's `prover.prove`
 *   downloads these artifacts at proof-generation time.
 */
export function resolveArtifacts(circuitId: string): CircuitArtifacts | null {
  const base = resolve(CIRCUITS_BUILD, circuitId);
  const wasmPath = resolve(base, `${circuitId}_js`, `${circuitId}.wasm`);
  const zkeyPath = resolve(base, `${circuitId}_final.zkey`);
  const vkeyPath = resolve(base, "verification_key.json");

  const exists =
    existsSync(wasmPath) && existsSync(zkeyPath) && existsSync(vkeyPath);

  return exists ? { wasmPath, zkeyPath, vkeyPath } : null;
}

export function artifactsAvailable(): boolean {
  return CIRCUIT_IDS.every((id) => resolveArtifacts(id) !== null);
}

/**
 * Generate a Groth16 proof using snarkjs with local file paths.
 *
 * Production equivalent:
 *   `prover.prove(client, { circuitId, witness })` — the SDK resolves
 *   `CircuitMeta` via `circuits.getById`, downloads wasm/zkey from
 *   `artifact.location` (IPFS gateway or HTTPS), and calls the same
 *   `snarkjs.groth16.fullProve` with `Uint8Array` buffers instead of
 *   file paths. The proof output is JSON-serialized then base64-encoded
 *   (`zkResult.proof`), and public signals are returned as
 *   `zkResult.inputs: ReadonlyArray<string>`.
 */
export async function groth16Prove(
  input: Record<string, string>,
  artifacts: CircuitArtifacts,
): Promise<Groth16Proof> {
  const snarkjs = await importSnarkjs();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    artifacts.wasmPath,
    artifacts.zkeyPath,
  );
  return {
    proof: proof as Groth16Proof["proof"],
    publicSignals: publicSignals as string[],
  };
}

/**
 * Verify a Groth16 proof against a local verification key.
 *
 * Production equivalent:
 *   `proofs.submit(client, { docHash, circuitId, proof, inputs })` —
 *   submits to `POST /v1/proofs` where the Lemma Workers backend performs
 *   server-side verification using the registered verification key. When
 *   `onchain: true` is set, the proof is also settled on-chain via
 *   `LemmaProofSettlement.settle()`, which calls the Groth16 verifier
 *   contract registered via `circuits.register`'s `verifiers[]` field.
 *
 *   Response status transitions:
 *     received → verifying → verified → onchain-verified | rejected
 */
export async function groth16Verify(
  proof: Groth16Proof,
  vkeyPath: string,
): Promise<boolean> {
  const snarkjs = await importSnarkjs();
  const vkey = JSON.parse(readFileSync(vkeyPath, "utf-8"));
  const result = await snarkjs.groth16.verify(
    vkey,
    proof.publicSignals,
    proof.proof,
  );
  return result === true;
}

async function importSnarkjs() {
  const mod = await import("snarkjs");
  return mod;
}

/**
 * Generate and verify a Groth16 proof for a circuit.
 *
 * Production equivalent (combining prove + submit):
 *   ```ts
 *   const zkResult = await prover.prove(client, { circuitId, witness });
 *   const proofResult = await proofs.submit(client, {
 *     docHash,          // from documents.register
 *     circuitId,
 *     proof: zkResult.proof,
 *     inputs: zkResult.inputs,
 *     chainId: 84532,  // target chain for on-chain verification
 *     onchain: true,
 *   });
 *   // proofResult.status → "verified" | "onchain-verified" | "rejected"
 *   ```
 */
export async function proveAndVerify(
  circuitId: string,
  input: Record<string, string>,
): Promise<ProofResult> {
  const artifacts = resolveArtifacts(circuitId);
  if (!artifacts) {
    return Promise.reject(
      new Error(
        `Circuit artifacts not found for "${circuitId}". Run \`pnpm circuits:prove\` first.`,
      ),
    );
  }
  const proof = await groth16Prove(input, artifacts);
  const verified = await groth16Verify(proof, artifacts.vkeyPath);
  return { proof, verified, circuitId };
}
