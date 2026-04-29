# example-origin — Lemma PoC: pre-execution origin proofs for DeFi bridges & LST/LRT lending

> **Tracing tells you what already happened. Lemma tells you what is allowed to happen next.**

A minimal, runnable PoC that responds to Kelp DAO / Drift–style incidents — where the on-chain transaction is technically valid, but the *origin* of the off-chain approval (or the LST/LRT collateral being deposited) is the actual attack surface.

This repo demonstrates two flows that bridges and lending markets can verify **before they execute**:

1. **Bridge approval origin** — prove an off-chain approval came from a real signer set, on an allowed source/destination chain, within an unexpired window, and that it hasn't been replayed.
2. **LST/LRT collateral provenance** — prove a liquid-staking / restaking lot was minted by a known operator, passed exclusively through trusted custody nodes, with bounded rehypothecation depth and a non-revoked validator set.

Both flows ship as a TypeScript library, runnable demo script, and Groth16 ZK circuits. When circuit artifacts are available, the demo generates and verifies real zero-knowledge proofs — not just TypeScript policy checks.

---

## Why "example-origin"

The single primitive shared between Kelp DAO and Drift-class incidents is **origin**: not "did this transaction succeed" but "did this approval / this collateral originate from where it claims to". Lemma's value here is a ZK-attestation handed to the executing protocol *before* it acts — the opposite of forensic tracing.

```
Forensic tracing (post-hoc)             Lemma origin proofs (pre-execution)
─────────────────────────────           ──────────────────────────────────────
Tx executes → bad outcome           Approval issued → ZK origin proof
        ↓                                       ↓
AML / chain-analysis flags it       Bridge / lender verifies proof + policy
        ↓                                       ↓
Funds already gone                  Tx only executes if proof + policy pass
```

---

## What this PoC demonstrates

### Scenario 1 — Bridge approval origin

A bridge or relayer receives an off-chain approval. Before initiating the lock/mint, it asks: *was this approval really endorsed by the multisig the protocol thinks it was, and has it already been consumed?*

The attestation discloses:

| Attribute | Disclosed | Hidden by default |
| --- | --- | --- |
| `approvalId` | ✓ | |
| `signerSet` (DID) | ✓ | |
| `signerThreshold` / `signersPresent` | ✓ | |
| `srcChainId`, `dstChainId`, `asset`, `amount` | ✓ | |
| `recipient` | | ✓ (committed only — recipient may be private) |
| `approvedAt`, `expiresAt` | ✓ | |

The verifier ([`verifyBridgeApproval`](packages/core/src/verify.ts)) layers a domain policy on top: source and destination chain whitelists, amount cap, minimum signer count, maximum approval age, approval expiry, and **replay prevention** (consumed `approvalId` list — the exact vector exploited in the Drift $285M heist where a valid pre-signed authorisation was reused within the validity window).

### Scenario 2 — LST/LRT collateral provenance

A lending market about to accept rsETH (or any LST/LRT) as collateral asks: *was this lot minted by a known operator, did it pass exclusively through trusted custody, and how many times has it been rehypothecated already?*

The attestation discloses:

| Attribute | Disclosed | Hidden by default |
| --- | --- | --- |
| `lotId`, `asset`, `amount` | ✓ | |
| `mintChainId` | ✓ | |
| `mintTxHash` | | ✓ (committed — full tx hash is private) |
| `custodyPath` | ✓ | |
| `validatorSetRoot` | ✓ | |
| `rehypothecationDepth` | ✓ | |

The verifier ([`verifyLstCollateral`](packages/core/src/verify.ts)) checks: mint chain whitelist, validator-set revocation list, maximum rehypothecation depth, **full custody-path verification** (every node must be in the trusted set — not just the final custodian), and freshness of the mint event.

---

## Demo flow

```
fixture (raw approval / collateral lot)
        │
        ▼
issueAttestation()
  ├─ canonical encode attributes
  ├─ Poseidon-style commit per leaf  (PoC: HMAC-SHA256)
  ├─ root = hash(sorted leaves)
  └─ sign(issuerDid, subjectId, schema, root)
        │
        ▼
   { revealed, hidden, commitments, signature }
        │
        ├──────────────────────────────────────────┐
        ▼                                          ▼
verifyBridgeApproval / verifyLstCollateral     ZK proof (if artifacts available)
  ├─ shape (zod)                               ├─ map attributes → circuit witness
  ├─ issuer, signature, validity window        ├─ Poseidon commitment in witness
  ├─ root + per-leaf commitments               ├─ Groth16 fullProve
  ├─ revocation (subject + validator set)      └─ groth16.verify → ✓/✗
  ├─ replay prevention (consumed approvalIds)
  ├─ full custody-path trust check
  └─ domain policy (chain ids, threshold, depth, age)
        │                                          │
        ▼                                          ▼
{ ok, revealed, notes }                      { proof, verified, commitment }
        │                                          │
        └──────────── both must pass ──────────────┘
```

---

## Quick start

### Prerequisites
- Node.js 20+
- pnpm 9+
- **For ZK proofs**: circom 2.x on PATH

```bash
git clone https://github.com/lemmaoracle/example-origin
cd example-origin
pnpm install
```

### Run the demo

```bash
pnpm demo            # both scenarios (TS policy + ZK proof if artifacts available)
pnpm demo:bridge     # bridge approvals only
pnpm demo:collateral # LST/LRT collateral only
```

Without circuit artifacts, the demo runs the TypeScript policy verifier only. With artifacts (from `pnpm circuits:prove`), it also generates and verifies Groth16 proofs for each passing fixture.

### Generate ZK proofs

```bash
pnpm circuits:prove    # full Groth16 pipeline: compile → ptau → setup → prove → verify
pnpm demo              # now includes ZK proof output
```

### Generate preset manifests from build artifacts

```bash
pnpm presets:generate  # write manifests with real artifact hashes + URLs
ARTIFACT_BASE_URL=https://cdn.example.com/circuits/ pnpm presets:generate
```

### Other commands

```bash
pnpm circuits:check  # validate circom manifests + JS-side Poseidon bindings
pnpm presets:dry-run # preview the Lemma circuits.register / schemas.register calls
pnpm test            # run all tests
```

Expected demo output (with ZK artifacts, abridged):

```
example-origin — Lemma origin proof demo
issuer: did:lemma:demo-issuer
now:    1714065000
ZK:     artifacts found — Groth16 proofs enabled

═══════════════════════════════════════════════════════════════
  Scenario 1 — Bridge approval origin (pre-execution)
═══════════════════════════════════════════════════════════════

— well-formed approval — should execute —
  ✓ approved — signer set did:bridge:gov-multisig-v3: 5/4
  [ZK] ✓ Groth16 proof verified
      commitment=1668698262476476…

— drift-style: replay of consumed approval — must reject —
  ✗ rejected — approvalId 0xreplay already consumed (replay prevented)

— drift-style: signer threshold not met — must reject —
  ✗ rejected — only 2 signers present, need 3

═══════════════════════════════════════════════════════════════
  Scenario 2 — LST/LRT collateral provenance (pre-lending)
═══════════════════════════════════════════════════════════════

— rsETH lot from trusted operator — should be accepted —
  ✓ accepted — collateral: rsETH 12500000000000000000 (lot rsETH-2026-04-22-#7)
  [ZK] ✓ Groth16 proof verified
      commitment=1462983756102987…

— kelp-style: untrusted intermediate in custody path — must reject —
  ✗ rejected — custody path contains untrusted node "did:protocol:rogue-lender"

— slashed validator set — must reject via revocation —
  ✗ rejected — validator-set root 0xbadbad… is revoked
```

---

## Project structure

```
packages/
  core/
    src/
      types.ts          zod schemas for attestations + disclosure
      canonical.ts      sorted-key JSON encoder (deterministic hashing)
      crypto.ts         HMAC-SHA256 commit / root / signature helpers
      issue.ts          issueAttestation()
      verify.ts         verifyAttestation + bridge/LST domain wrappers
      prover.ts         Local Groth16 proof generation + verification
      zk-verify.ts      ZK-attestation integration (attrs → circuit → proof)
      demo/run.ts       demo runner (TS policy + ZK proof)
      __tests__/        vitest suite
  circuits/
    src/
      bridge-approval-origin/  Circom source for the bridge proof
      lst-collateral-origin/   Circom source for the LST proof
      inputs.ts                deterministic witness/input builders
      manifest.ts              zod schemas for preset JSON
      cli/                     `circuits:inputs`, `circuits:check`
      __tests__/               vitest suite (manifest + input generation)
presets/
  schemas/                    SchemaMeta JSON for Lemma `schemas.register`
  circuits/                   CircuitMeta JSON for Lemma `circuits.register`
scripts/
  register-presets.ts         dry-run + execute for both API calls
  generate-manifests.ts       build manifests from circuit artifacts + real hashes
data/
  bridge-approvals.json       fixtures for scenario 1
  lst-collateral.json         fixtures for scenario 2
```

---

## What is mocked vs. production

This PoC intentionally swaps Lemma's production primitives for stdlib equivalents so that the example runs with `pnpm install && pnpm demo` and no key material, faucet, or chain endpoint.

| Layer | PoC | Production Lemma |
| --- | --- | --- |
| Attribute commitment | HMAC-SHA256(key, value, randomness) | Poseidon over BN254 |
| Issuer signature | HMAC-SHA256 over canonical(issuer, subject, schema, root) | BBS+ over BLS12-381 |
| Selective disclosure | Per-leaf randomness, omitted for hidden leaves | BBS+ derive-proof |
| Revocation | In-memory list (subjects + validator-set roots + consumed approvalIds) | On-chain revocation registry / accumulator |
| Issuer key handling | Generated per-process | KMS / HSM |
| ZK proof | Groth16 via snarkjs (local wasm + zkey) | Groth16 via Lemma SDK (remote artifacts) |
| Issuance trigger | Static fixtures in `data/` | Bridge / LST operator webhook → Lemma worker |

The verifier API surface (`verifyBridgeApproval`, `verifyLstCollateral`) is shaped so that a production Lemma SDK can be dropped in without changing the demo or the policy types.

---

## ZK circuit boundary — what is proven where

This is a **hybrid ZK + on-chain verification** architecture, not "everything in ZK". The boundary is explicit and intentional:

### In-circuit (zero-knowledge proven)

These constraints are proven by the Groth16 proof. The verifier learns nothing about the hidden witness beyond "it satisfies these constraints":

| Constraint | Bridge | LST |
| --- | --- | --- |
| Commitment binding | `Poseidon(witness) === originCommitment` | `Poseidon(witness) === collateralCommitment` |
| Destination chain | `dstChainId === policyDstChainId` | — |
| Amount cap | `amount <= policyMaxAmount` | — |
| Signer threshold | `signersPresent >= policyMinSigners` | — |
| Approval validity | `nowSec <= validUntil` | — |
| Asset whitelist | — | `assetIdHash === policyAssetIdHash` |
| Validator set not revoked | — | `validatorSetRevoked === 0` |
| Rehypothecation depth | — | `depth <= policyMaxRehypoDepth` |
| Custody hop count | — | `custodyHops <= policyMaxCustodyHops` |
| Mint freshness | — | `mintedAt + minMintAge <= nowSec` |

### Off-circuit (TypeScript / on-chain verification)

These checks don't belong in the circuit — they'd inflate the constraint count without adding privacy value, or they require external state:

| Check | Why off-circuit |
| --- | --- |
| Issuer signature | BBS+ signature is verified by the Lemma protocol layer; duplicating in-circuit is unnecessary |
| Subject revocation | Requires access to an on-chain accumulator; the circuit receives a pre-checked bit |
| Validator-set root revocation | Same — Merkle non-membership proof is an on-chain / protocol concern |
| Consumed approvalIds (replay) | Requires mutable state; ZK proofs are stateless |
| Full custody-path trust | Every DID must be checked against a dynamic trusted set; this is a policy concern, not a ZK constraint |
| Source/mint chain whitelist | Small fixed sets are cheaper as a contract-side equality check |
| Custody-path identities | Only the *count* is in-circuit; the actual DIDs are selective-disclosure leaves |

This split is the **production architecture**, not a shortcut. Positioning it as "ZK + on-chain hybrid" is more honest and more compelling to enterprise customers than claiming everything is in ZK.

---

## Integrating with a real bridge / lending market

The verifier is intentionally a pure function. A real protocol would:

1. Ingest the attestation as a payload alongside the on-chain call (calldata blob, a header, or a separate API request).
2. Run `verifyBridgeApproval(attestation, { issuer, policy, revocations })` (or the LST equivalent) **before** dispatching the inner protocol call.
3. On `ok: true`, proceed to the on-chain execution path. On `ok: false`, refuse and emit the rejection reason for monitoring.
4. Replace the in-memory `revocations` argument with reads against the on-chain Lemma revocation registry.
5. Optionally, also verify the ZK proof via `zkProveBridgeApproval` / `zkProveLstCollateral` for the commitment-binding guarantee.

```ts
import {
  verifyBridgeApproval,
  zkProveBridgeApproval,
  type BridgePolicy,
} from "@example-origin/core";

const policy: BridgePolicy = {
  allowedSrcChainIds: [1, 8453],
  allowedDstChainIds: [42161, 10],
  maxAmount: 5_000_000_000n,
  minSignersPresent: 4,
  maxApprovalAgeSec: 24 * 60 * 60, // 24 hours
};

const revocations = await fetchRevocations();

// Layer 1: off-circuit policy check
const result = verifyBridgeApproval(payloadFromRelayer, {
  issuer: trustedIssuerKey,
  policy,
  revocations,
});
if (!result.ok) throw new Error(`origin rejected: ${result.reason}`);

// Layer 2: ZK proof (commitment binding + in-circuit constraints)
const zkResult = await zkProveBridgeApproval(
  payloadFromRelayer.attributes,
  { policyDstChainId: 42161, policyMaxAmount: "5000000000", policyMinSigners: 4, nowSec },
);
if (!zkResult.proof.verified) throw new Error("ZK proof verification failed");

await bridge.execute(...);
```

---

## Circom circuits (`packages/circuits`)

Two minimal Groth16 circuits demonstrate what is proven in zero knowledge for each scenario. They are intentionally tiny — each has under ten constraints beyond the Poseidon commitment, so the demo compiles in seconds and the policy logic is readable in one screen.

### `bridge-approval-origin`

Public inputs: `originCommitment, policyDstChainId, policyMaxAmount, policyMinSigners, nowSec`.
Private witness: `approvalIdHash, signerSetHash, dstChainId, amount, signersPresent, validUntil, salt`.

Constraints (all must hold for `accepted == 1`):

1. `Poseidon(approvalIdHash, signerSetHash, dstChainId, amount, signersPresent, validUntil, salt) === originCommitment` — binds the public commitment to the hidden witness.
2. `dstChainId === policyDstChainId` — destination matches the policy target.
3. `amount <= policyMaxAmount` — range-checked via `Num2Bits(240)` then `LessEqThan`.
4. `signersPresent >= policyMinSigners`.
5. `nowSec <= validUntil` — approval not expired.

### `lst-collateral-origin`

Public inputs: `collateralCommitment, policyAssetIdHash, policyMaxRehypoDepth, policyMaxCustodyHops, policyMinMintAge, nowSec`.
Private witness: `lotIdHash, assetIdHash, mintChainId, custodyHops, rehypothecationDepth, validatorSetRevoked, mintedAt, salt`.

Constraints:

1. `Poseidon(...) === collateralCommitment` — binds the public commitment.
2. `assetIdHash === policyAssetIdHash` — the lender's accepted asset.
3. `validatorSetRevoked` is boolean and `=== 0` (operator/validator set not slashed).
4. `rehypothecationDepth <= policyMaxRehypoDepth`.
5. `custodyHops <= policyMaxCustodyHops`.
6. `mintedAt + policyMinMintAge <= nowSec` — mint event is at least the policy's minimum age old.

### Running the circuit pipeline

```bash
pnpm circuits:inputs   # write deterministic example inputs to packages/circuits/inputs/
pnpm circuits:check    # validate manifests, regenerate inputs, run `circom --inspect` if installed
pnpm circuits:prove    # full Groth16 pipeline: compile → ptau → setup → prove → verify
```

`circuits:check` is the CI-friendly entry point. It works without `circom` on PATH (manifest validation + JS-side Poseidon binding still run); installing `circom` 2.x lets it additionally syntax-check both `.circom` files.

`circuits:prove` is the full proof-generation pipeline. It requires `circom` on PATH. For each circuit it:

1. Compiles the `.circom` source to R1CS + WASM via `circom`
2. Generates (or reuses) a Powers of Tau ceremony file (2^12, sufficient for the small PoC circuits)
3. Runs Phase 2 setup → `circuit_final.zkey`
4. Exports the verification key
5. Generates a Groth16 proof from the deterministic input
6. Verifies the proof against the verification key

All build artifacts land in `packages/circuits/build/<circuitId>/`. The Powers of Tau file is cached under `build/ptau/` so subsequent runs skip the one-time generation.

To prove only one circuit:

```bash
pnpm --filter @example-origin/circuits circuits:prove:bridge
pnpm --filter @example-origin/circuits circuits:prove:collateral
```

The same Poseidon implementation lives inside the circuit (`circomlib`) and out here in JavaScript (`circomlibjs`), so the JS-computed `originCommitment` always matches what the witness will check — no separate hash to keep in sync.

---

## Lemma preset registration (`scripts/register-presets.ts`)

The repo ships JSON manifests for both schemas and circuits under `presets/`, typed against `SchemaMeta` / `CircuitMeta` from `@lemmaoracle/spec`. A single script registers them through the real `@lemmaoracle/sdk` client:

```bash
pnpm presets:generate  # generate manifests from build artifacts (replaces placeholder URLs)
pnpm presets:dry-run   # preview what would be sent (default — no API calls)
pnpm presets:execute   # actually call schemas.register / circuits.register
```

The `presets:generate` script reads the compiled circuit artifacts and writes manifests with:
- Real SHA-256 hashes of the wasm and zkey files
- Configurable artifact base URL (`ARTIFACT_BASE_URL` env var, defaults to `file://` local path)

The `register-presets` script is wired straight into the SDK:

```ts
import { create, schemas, circuits } from "@lemmaoracle/sdk";
const client = create({
  apiBase: process.env.LEMMA_API_BASE_URL,  // SDK default: https://workers.lemma.workers.dev
  apiKey:  process.env.LEMMA_API_KEY,       // sent as `x-api-key`
});
await schemas.register(client, schemaPayload);
await circuits.register(client, circuitPayload);
```

| SDK call | Wire effect | Payload source |
| --- | --- | --- |
| `schemas.register(client, payload)` | `POST {apiBase}/v1/schemas` | `presets/schemas/*.json` |
| `circuits.register(client, payload)` | `POST {apiBase}/v1/circuits` | `presets/circuits/*.json` |

Schemas are registered first because each circuit references its schema by id (`schema: "bridge-approval-origin-v1"`).

Required env when using `--execute`:

```env
LEMMA_API_BASE_URL=https://workers.lemma.workers.dev   # SDK default
LEMMA_API_KEY=<your key>                               # required for --execute
```

Every payload is validated with zod (`CircuitMetaSchema` / `SchemaMetaSchema` in `packages/circuits/src/manifest.ts`) before it is printed or sent — including a sanity check that the artifact URLs use `https://` or `ipfs://`. The validated objects are then handed to the SDK as `SchemaMeta` / `CircuitMeta`; a static `(m: CircuitManifest) => CircuitMeta` assignment in `manifest.ts` guarantees the manifest types remain assignable to the SDK's authoritative spec — `pnpm build` fails immediately if the SDK shape ever drifts.

The dry-run prints the exact JSON each call would send; nothing leaves the laptop unless `--execute` is passed.

---

## Limitations & next steps

### Current limitations

- **In-memory issuer key.** Demo only — replace with a KMS-backed signer for any real deployment.
- **Single-issuer trust model.** The verifier accepts one issuer DID; a federation registry would be needed for multi-operator settings. See "Issuer federation roadmap" below.
- **Revocation is a flat list.** Production should use a Merkle / sparse-merkle accumulator with on-chain anchoring.
- **Identifier hashing truncation.** `fieldHashOfString` masks the top byte of SHA-256 to fit BN254. This reduces collision resistance. Production should use a purpose-built field hash (e.g. Poseidon-based) or a full Merkle commitment instead of in-circuit hash equality.

### Issuer federation roadmap

The current system's security depends on the issuer's secret key. If an attacker compromises the issuer, they can forge valid attestations that pass all checks. To address this single point of failure, the roadmap includes:

1. **Multi-sig issuer (near-term):** Require attestations to be signed by M-of-N issuer keys. The verifier checks that at least `threshold` signatures from the known issuer set are present. This raises the bar from "compromise one key" to "compromise multiple independent keys."

2. **Federated issuer network (medium-term):** A registry of independent issuers, each with their own key material and attestation policies. Verifiers configure which issuers they trust, and the Lemma protocol routes attestations through the appropriate issuer. This eliminates single-issuer trust and enables multi-tenant deployments.

3. **On-chain issuer governance (long-term):** Issuer set membership and key rotation are governed by an on-chain mechanism (DAO vote, stake-weighted election, etc.). The verifier contract reads the current issuer set from the chain, ensuring that key rotation and revocation are transparent and auditable.

---

## Further reading

- [Lemma Oracle](https://lemma.frame00.com) — ZK-verified data attestations
- [example-x402](https://github.com/lemmaoracle/example-x402) — agent payments + Lemma attestations
- [example-mw](https://github.com/lemmaoracle/example-mw) — public-works data attestations (MizuDAkO)
