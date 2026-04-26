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
data/
  bridge-approvals.json   fixtures for scenario 1
  lst-collateral.json     fixtures for scenario 2
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

## Limitations & next steps

- **No ZK proof yet.** Commitments + signatures are sufficient to demonstrate the API and the policy decisions. A production version would add a Groth16 circuit per schema (`bridge-approval-v1`, `lst-collateral-v1`) under `packages/circuit`.
- **In-memory issuer key.** Demo only — replace with a KMS-backed signer for any real deployment.
- **Single-issuer trust model.** The verifier accepts one issuer DID; a federation registry would be needed for multi-operator settings.
- **Revocation is a flat list.** Production should use a Merkle / sparse-merkle accumulator with on-chain anchoring.

---

## Further reading

- [Lemma Oracle](https://lemma.frame00.com) — ZK-verified data attestations
- [example-x402](https://github.com/lemmaoracle/example-x402) — agent payments + Lemma attestations
- [example-mw](https://github.com/lemmaoracle/example-mw) — public-works data attestations (MizuDAkO)
