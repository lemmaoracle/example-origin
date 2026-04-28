import { describe, it, expect } from "vitest";
import {
  generateIssuerKey,
  issueAttestation,
  verifyAttestation,
  verifyBridgeApproval,
  verifyLstCollateral,
  type BridgePolicy,
  type LstPolicy,
} from "../index.js";

const NOW = 1714065000;

const issuer = generateIssuerKey("did:lemma:test-issuer");
const otherIssuer = generateIssuerKey("did:lemma:other-issuer");

const bridgeAttrs = {
  kind: "bridge-approval-v1" as const,
  approvalId: "0xtest",
  signerSet: "did:bridge:multisig",
  signerThreshold: 3,
  signersPresent: 4,
  srcChainId: 1,
  dstChainId: 42161,
  asset: "USDC",
  amount: "1000000000",
  recipient: "0xfeedfacefeedfacefeedfacefeedfacefeedface",
  approvedAt: NOW - 100,
  expiresAt: NOW + 1000,
};

const bridgePolicy: BridgePolicy = {
  allowedSrcChainIds: [1],
  allowedDstChainIds: [42161],
  maxAmount: 5_000_000_000n,
  minSignersPresent: 3,
  maxApprovalAgeSec: 86400,
};

const lstAttrs = {
  kind: "lst-collateral-v1" as const,
  lotId: "lot-1",
  asset: "rsETH",
  amount: "1000000000000000000",
  mintChainId: 1,
  mintTxHash: "0xab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34",
  mintedAt: NOW - 1000,
  custodyPath: ["did:operator:kelp", "did:custodian:lemma"],
  validatorSetRoot:
    "0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
  rehypothecationDepth: 0,
};

const lstPolicy: LstPolicy = {
  allowedMintChainIds: [1],
  maxRehypothecationDepth: 1,
  trustedCustodians: ["did:custodian:lemma"],
  maxMintAgeSec: 86400,
};

describe("issueAttestation", () => {
  it("hides requested fields and reveals the rest", () => {
    const att = issueAttestation(issuer, "approval:1", bridgeAttrs, {
      hide: ["recipient", "amount"],
      nowSec: NOW,
    });
    expect(att.disclosure.hidden.sort()).toEqual(["amount", "recipient"]);
    expect(att.disclosure.revealed.recipient).toBeUndefined();
    expect(att.disclosure.revealed.amount).toBeUndefined();
    expect(att.disclosure.revealed.srcChainId).toBe(1);
    const hiddenLeaf = att.disclosure.commitments.leaves.find(
      (l) => l.key === "recipient",
    );
    expect(hiddenLeaf?.randomness).toBeUndefined();
    const revealedLeaf = att.disclosure.commitments.leaves.find(
      (l) => l.key === "srcChainId",
    );
    expect(revealedLeaf?.randomness).toMatch(/^0x[0-9a-f]+$/);
  });
});

describe("verifyAttestation", () => {
  it("accepts a freshly-issued attestation", () => {
    const att = issueAttestation(issuer, "subj:1", bridgeAttrs, { nowSec: NOW });
    const result = verifyAttestation(att, { issuer, nowSec: NOW });
    expect(result.ok).toBe(true);
  });

  it("rejects attestation signed by a different issuer", () => {
    const att = issueAttestation(otherIssuer, "subj:2", bridgeAttrs, {
      nowSec: NOW,
    });
    const result = verifyAttestation(att, { issuer, nowSec: NOW });
    expect(result.ok).toBe(false);
  });

  it("rejects when a revealed attribute has been tampered with", () => {
    const att = issueAttestation(issuer, "subj:3", bridgeAttrs, { nowSec: NOW });
    const tampered = {
      ...att,
      disclosure: {
        ...att.disclosure,
        revealed: { ...att.disclosure.revealed, amount: "9999999999" },
      },
    };
    const result = verifyAttestation(tampered, { issuer, nowSec: NOW });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/commitment mismatch/);
  });

  it("rejects when leaves have been swapped in", () => {
    const att = issueAttestation(issuer, "subj:4", bridgeAttrs, { nowSec: NOW });
    const swapped = {
      ...att,
      disclosure: {
        ...att.disclosure,
        commitments: {
          ...att.disclosure.commitments,
          leaves: [
            ...att.disclosure.commitments.leaves.slice(0, -1),
            {
              key: "extra",
              commitment:
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            },
          ],
        },
      },
    };
    const result = verifyAttestation(swapped, { issuer, nowSec: NOW });
    expect(result.ok).toBe(false);
  });

  it("rejects expired attestations", () => {
    const att = issueAttestation(issuer, "subj:5", bridgeAttrs, {
      nowSec: NOW,
      ttlSec: 60,
    });
    const result = verifyAttestation(att, { issuer, nowSec: NOW + 120 });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/expired/);
  });

  it("rejects revoked subjects", () => {
    const att = issueAttestation(issuer, "subj:6", bridgeAttrs, { nowSec: NOW });
    const result = verifyAttestation(att, {
      issuer,
      nowSec: NOW,
      revocations: { subjects: ["subj:6"], validatorSetRoots: [] },
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/revoked/);
  });
});

describe("verifyBridgeApproval policy", () => {
  it("accepts a compliant approval", () => {
    const att = issueAttestation(issuer, "approval:ok", bridgeAttrs, {
      hide: ["recipient"],
      nowSec: NOW,
    });
    const result = verifyBridgeApproval(att, {
      issuer,
      nowSec: NOW,
      policy: bridgePolicy,
    });
    expect(result.ok).toBe(true);
  });

  it("rejects when amount exceeds policy max", () => {
    const big = { ...bridgeAttrs, amount: "9999999999999" };
    const att = issueAttestation(issuer, "approval:big", big, { nowSec: NOW });
    const result = verifyBridgeApproval(att, {
      issuer,
      nowSec: NOW,
      policy: bridgePolicy,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/amount/);
  });

  it("rejects when signers present is below threshold", () => {
    const thin = { ...bridgeAttrs, signersPresent: 2, signerThreshold: 5 };
    const att = issueAttestation(issuer, "approval:thin", thin, { nowSec: NOW });
    const result = verifyBridgeApproval(att, {
      issuer,
      nowSec: NOW,
      policy: bridgePolicy,
    });
    expect(result.ok).toBe(false);
  });

  it("rejects unknown destination chain", () => {
    const odd = { ...bridgeAttrs, dstChainId: 999999 };
    const att = issueAttestation(issuer, "approval:odd", odd, { nowSec: NOW });
    const result = verifyBridgeApproval(att, {
      issuer,
      nowSec: NOW,
      policy: bridgePolicy,
    });
    expect(result.ok).toBe(false);
  });

  it("rejects stale approval age", () => {
    const stale = { ...bridgeAttrs, approvedAt: NOW - bridgePolicy.maxApprovalAgeSec - 10 };
    const att = issueAttestation(issuer, "approval:stale", stale, { nowSec: NOW });
    const result = verifyBridgeApproval(att, {
      issuer,
      nowSec: NOW,
      policy: bridgePolicy,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/approval age/);
  });

  it("rejects when approval has expired (expiresAt < now)", () => {
    const expired = { ...bridgeAttrs, expiresAt: NOW - 100 };
    const att = issueAttestation(issuer, "approval:expired", expired, { nowSec: NOW });
    const result = verifyBridgeApproval(att, {
      issuer,
      nowSec: NOW,
      policy: bridgePolicy,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/approval expired/);
  });
});

describe("verifyLstCollateral policy", () => {
  it("accepts a compliant rsETH lot", () => {
    const att = issueAttestation(issuer, "lot:ok", lstAttrs, { nowSec: NOW });
    const result = verifyLstCollateral(att, {
      issuer,
      nowSec: NOW,
      policy: lstPolicy,
    });
    expect(result.ok).toBe(true);
  });

  it("rejects when validator-set root is revoked", () => {
    const att = issueAttestation(issuer, "lot:slashed", lstAttrs, { nowSec: NOW });
    const result = verifyLstCollateral(att, {
      issuer,
      nowSec: NOW,
      policy: lstPolicy,
      revocations: {
        subjects: [],
        validatorSetRoots: [lstAttrs.validatorSetRoot],
      },
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/validator-set/);
  });

  it("rejects when rehypothecation depth exceeds policy", () => {
    const looped = { ...lstAttrs, rehypothecationDepth: 4 };
    const att = issueAttestation(issuer, "lot:looped", looped, { nowSec: NOW });
    const result = verifyLstCollateral(att, {
      issuer,
      nowSec: NOW,
      policy: lstPolicy,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/rehypothecation/);
  });

  it("rejects when final custodian is not trusted", () => {
    const evil = {
      ...lstAttrs,
      custodyPath: ["did:operator:kelp", "did:custodian:unknown"],
    };
    const att = issueAttestation(issuer, "lot:evil", evil, { nowSec: NOW });
    const result = verifyLstCollateral(att, {
      issuer,
      nowSec: NOW,
      policy: lstPolicy,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/custodian/);
  });

  it("rejects stale mint events", () => {
    const stale = { ...lstAttrs, mintedAt: NOW - lstPolicy.maxMintAgeSec - 10 };
    const att = issueAttestation(issuer, "lot:stale", stale, { nowSec: NOW });
    const result = verifyLstCollateral(att, {
      issuer,
      nowSec: NOW,
      policy: lstPolicy,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/mint age/);
  });
});
