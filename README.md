# example-origin — Lemma PoC: pre-execution origin proofs for DeFi bridges & LST/LRT lending

> **Tracing tells you what already happened. Lemma tells you what is allowed to happen next.**

A minimal, runnable PoC that responds to Kelp DAO / Drift–style incidents — where the on-chain transaction is technically valid, but the *origin* of the off-chain approval (or the LST/LRT collateral being deposited) is the actual attack surface.

This repo demonstrates two flows that bridges and lending markets can verify **before they execute**:

1. **Bridge approval origin** — prove an off-chain approval came from a real signer set, on an allowed source/destination chain, within an unexpired window.
2. **LST/LRT collateral provenance** — prove a liquid-staking / restaking lot was minted by a known operator, custodied by a trusted vault, with bounded rehypothecation depth and a non-revoked validator set.

Both flows ship as a single TypeScript library plus a runnable demo script. No on-chain calls are made; the verifier output is the gate that a real relayer or lending market would consult.

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

A bridge or relayer receives an off-chain approval. Before initiating the lock/mint, it asks: *was this approval really endorsed by the multisig the protocol thinks it was?*

The attestation discloses:

| Attribute | Disclosed | Hidden by default |
| --- | --- | --- |
| `signerSet` (DID) | ✓ | |
| `signerThreshold` / `signersPresent` | ✓ | |
| `srcChainId`, `dstChainId`, `asset`, `amount` | ✓ | |
| `recipient` | | ✓ (committed only — recipient may be private) |
| `approvedAt`, `expiresAt` | ✓ | |

The verifier ([`verifyBridgeApproval`](packages/core/src/verify.ts)) layers a domain policy on top: chain whitelist, amount cap, minimum signer count.

### Scenario 2 — LST/LRT collateral provenance

A lending market about to accept rsETH (or any LST/LRT) as collateral asks: *was this lot minted by a known operator, did it pass through trusted custody, and how many times has it been rehypothecated already?*

The attestation discloses:

| Attribute | Disclosed | Hidden by default |
| --- | --- | --- |
| `lotId`, `asset`, `amount` | ✓ | |
| `mintChainId` | ✓ | |
| `mintTxHash` | | ✓ (committed — full tx hash is private) |
| `custodyPath` | ✓ | |
| `validatorSetRoot` | ✓ | |
| `rehypothecationDepth` | ✓ | |

The verifier ([`verifyLstCollateral`](packages/core/src/verify.ts)) checks: mint chain whitelist, validator-set revocation list (slashed / compromised operators), maximum rehypothecation depth, trusted custodians, and freshness of the mint event.

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
        ▼
verifyBridgeApproval / verifyLstCollateral
  ├─ shape (zod)
  ├─ issuer, signature, validity window
  ├─ root + per-leaf commitments
  ├─ revocation (subject + validator set)
  └─ domain policy (chain ids, threshold, depth, custodian, age)
        │
        ▼
{ ok: true, revealed, notes } | { ok: false, reason, notes }
```

---

## Quick start

### Prerequisites
- Node.js 20+
- pnpm 9+

```bash
git clone https://github.com/lemmaoracle/example-origin
cd example-origin
pnpm install
```

### Run the demo

```bash
pnpm demo            # both scenarios
pnpm demo:bridge     # bridge approvals only
pnpm demo:collateral # LST/LRT collateral only
pnpm circuits:check  # validate circom manifests + JS-side Poseidon bindings
pnpm presets:dry-run # preview the Lemma circuits.register / schemas.register calls
```

Expected output (abridged):

```
example-origin — minimal Lemma PoC
issuer: did:lemma:demo-issuer
now:    1714065000

═══════════════════════════════════════════════════════════════
  Scenario 1 — Bridge approval origin (pre-execution)
═══════════════════════════════════════════════════════════════

— well-formed approval — should execute —
    disclosed 9 attr(s); hidden 1: [recipient]
  ✓ approved — signer set did:bridge:gov-multisig-v3: 5/4

— drift-style: signer threshold not met — must reject —
  ✗ rejected — only 2 signers present, need 3

— kelp-style: dst chain not in policy — must reject —
  ✗ rejected — dst chain 999999 not allowed

═══════════════════════════════════════════════════════════════
  Scenario 2 — LST/LRT collateral provenance (pre-lending)
═══════════════════════════════════════════════════════════════

— rsETH lot from trusted operator — should be accepted —
  ✓ accepted — collateral: rsETH 12500000000000000000 (lot rsETH-2026-04-22-#7)

— kelp-style: rehypothecated collateral — must reject —
  ✗ rejected — rehypothecation depth 3 exceeds max 1

— slashed validator set — must reject via revocation —
  ✗ rejected — validator-set root 0xbadbad… is revoked
```

### Run tests

```bash
pnpm test
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
      demo/run.ts       demo runner (loads data/ fixtures)
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
  schemes/                    SchemaMeta JSON for Lemma `schemas.register`
  circuits/                   CircuitMeta JSON for Lemma `circuits.register`
scripts/
  register-presets.ts         dry-run + execute for both API calls
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
| Revocation | In-memory list (subjects + validator-set roots) | On-chain revocation registry / accumulator |
| Issuer key handling | Generated per-process | KMS / HSM |
| ZK proof | None (commitments + signature only) | Groth16 over a domain circuit |
| Issuance trigger | Static fixtures in `data/` | Bridge / LST operator webhook → Lemma worker |

The verifier API surface (`verifyBridgeApproval`, `verifyLstCollateral`) is shaped so that a production Lemma SDK can be dropped in without changing the demo or the policy types.

---

## Integrating with a real bridge / lending market

The verifier is intentionally a pure function. A real protocol would:

1. Ingest the attestation as a payload alongside the on-chain call (calldata blob, a header, or a separate API request).
2. Run `verifyBridgeApproval(attestation, { issuer, policy, revocations })` (or the LST equivalent) **before** dispatching the inner protocol call.
3. On `ok: true`, proceed to the on-chain execution path. On `ok: false`, refuse and emit the rejection reason for monitoring.
4. Replace the in-memory `revocations` argument with reads against the on-chain Lemma revocation registry.

```ts
import {
  verifyBridgeApproval,
  type BridgePolicy,
} from "@example-origin/core";

const policy: BridgePolicy = {
  allowedSrcChainIds: [1, 8453],
  allowedDstChainIds: [42161, 10],
  maxAmount: 5_000_000_000n,
  minSignersPresent: 4,
};

const result = verifyBridgeApproval(payloadFromRelayer, {
  issuer: trustedIssuerKey,
  policy,
  revocations: await fetchRevocations(),
});

if (!result.ok) throw new Error(`origin rejected: ${result.reason}`);
await bridge.execute(...);
```

---

## Circom circuits (`packages/circuits`)

Two minimal Groth16 circuits demonstrate what *should* be proven in zero knowledge for each scenario. They are intentionally tiny — each has under ten constraints beyond the Poseidon commitment, so the demo compiles in seconds and the policy logic is readable in one screen.

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

### What is intentionally off-circuit

The circuits are the *minimum* needed to prove origin policy. The surrounding Lemma flow already covers the rest, so duplicating it in-circuit would only inflate the constraint count:

- **Issuer BBS+ signature** over the disclosure root — checked by the SDK's `verifyAttestation`.
- **Revocation accumulator membership** — production wires a Poseidon-Merkle non-membership proof; here the witness exposes a single `validatorSetRevoked` bit and the off-circuit verifier checks it against the revoked-roots list.
- **On-chain anchoring** of the document hash and proof receipt — handled by the verifier contract registered via `circuits.register`.
- **Source-chain whitelist for bridges, mint-chain whitelist for LST** — small fixed sets are cheaper as a contract-side `eq`-against-list than as a circuit.
- **Custody-path identities** — only the *length* is proven. The DIDs themselves are selective-disclosure leaves bound to the signed disclosure root.

### Running the circuit pipeline

```bash
pnpm circuits:inputs   # write deterministic example inputs to packages/circuits/inputs/
pnpm circuits:check    # validate manifests, regenerate inputs, run `circom --inspect` if installed
```

`circuits:check` is the CI-friendly entry point. It works without `circom` on PATH (manifest validation + JS-side Poseidon binding still run); installing `circom` 2.x lets it additionally syntax-check both `.circom` files.

The same Poseidon implementation lives inside the circuit (`circomlib`) and out here in JavaScript (`circomlibjs`), so the JS-computed `originCommitment` always matches what the witness will check — no separate hash to keep in sync.

---

## Lemma preset registration (`scripts/register-presets.ts`)

The repo ships JSON manifests for both schemes and circuits under `presets/`, mirroring `SchemaMeta` / `CircuitMeta` from `@lemmaoracle/spec`. A single script registers them via Lemma's HTTP API:

```bash
pnpm presets:dry-run    # preview what would be POSTed (default — no API calls)
pnpm presets:execute    # actually POST /v1/schemas and /v1/circuits
```

Endpoints (mirrors `@lemmaoracle/sdk`):

| Call | Method + path | Payload |
| --- | --- | --- |
| `schemas.register` | `POST /v1/schemas` | `presets/schemes/*.json` |
| `circuits.register` | `POST /v1/circuits` | `presets/circuits/*.json` |

Schemes are registered first because each circuit references its scheme by id (`schema: "bridge-approval-origin-v1"`).

Required env when using `--execute`:

```env
LEMMA_API_BASE_URL=https://workers.lemma.workers.dev   # default
LEMMA_API_KEY=<your key>                               # required for --execute
LEMMA_ORG_ID=<optional>
LEMMA_PROJECT_ID=<optional>
```

Every payload is validated with zod (`CircuitMetaSchema` / `SchemaMetaSchema` in `packages/circuits/src/manifest.ts`) before it is printed or sent — including a sanity check that the artifact URLs use `https://` or `ipfs://`. The dry-run prints the exact JSON each call would send; nothing leaves the laptop unless `--execute` is passed.

The script intentionally does not depend on `@lemmaoracle/sdk` so the demo stays installable from scratch. When the SDK is added as a dep, the two `register(...)` calls become one-line `circuits.register(client, payload)` / `schemas.register(client, payload)` calls — the payloads already match the SDK types.

---

## Limitations & next steps

- **No proof generation pipeline.** The circom circuits compile and the inputs match the constraints, but the demo does not yet produce zkeys or witnesses. Adding a one-shot `pnpm circuits:prove` that runs `snarkjs groth16 fullprove` is the natural next step.
- **In-memory issuer key.** Demo only — replace with a KMS-backed signer for any real deployment.
- **Single-issuer trust model.** The verifier accepts one issuer DID; a federation registry would be needed for multi-operator settings.
- **Revocation is a flat list.** Production should use a Merkle / sparse-merkle accumulator with on-chain anchoring.
- **Preset artifact URIs are placeholders.** `https://example.invalid/...` keeps the manifests well-formed without pinning to a specific IPFS pin or HTTPS host. Replace before running `--execute` against a real Lemma deployment.

---

## Further reading

- [Lemma Oracle](https://lemma.frame00.com) — ZK-verified data attestations
- [example-x402](https://github.com/lemmaoracle/example-x402) — agent payments + Lemma attestations
- [example-mw](https://github.com/lemmaoracle/example-mw) — public-works data attestations (MizuDAkO)
