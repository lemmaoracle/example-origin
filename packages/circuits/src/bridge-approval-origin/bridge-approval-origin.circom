pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * bridge-approval-origin
 *
 * Proves a hidden bridge approval is bound to a public origin commitment and
 * satisfies pre-execution policy.
 *
 * Public:
 *   originCommitment    Poseidon over (approvalIdHash, signerSetHash, dstChainId,
 *                                      amount, signersPresent, validUntil, salt)
 *   policyDstChainId    Destination chain id the executing relayer expects
 *   policyMaxAmount     Maximum amount the policy will execute
 *   policyMinSigners    Minimum signers the policy requires
 *   nowSec              Current timestamp (relayer-provided)
 *
 * Private (witness):
 *   approvalIdHash      keccak/Poseidon hash of the off-chain approval id
 *   signerSetHash       Hash identifying the signer set / multisig DID
 *   dstChainId          Destination chain id from the approval
 *   amount              Approval amount (base units, < 2^240)
 *   signersPresent      Number of signers actually present
 *   validUntil          Approval validity bound (unix seconds)
 *   salt                Per-issuance blinding factor
 *
 * Output / constraint:
 *   accepted == 1 iff all policy checks hold.
 *
 * Off-circuit (intentionally not proved here, but verified by the surrounding
 * Lemma flow):
 *   - issuer BBS+ signature over the attestation root
 *   - revocation accumulator membership
 *   - on-chain anchoring of the document hash
 *   - whitelist of allowed source chains (cheaper as a contract-side check)
 */

template AmountFits() {
    signal input amount;            // assumed < 2^240 (USDC etc. have 6/18 decimals)
    component fits = Num2Bits(240);
    fits.in <== amount;
}

template BridgeApprovalOrigin() {
    // Public inputs
    signal input originCommitment;
    signal input policyDstChainId;
    signal input policyMaxAmount;
    signal input policyMinSigners;
    signal input nowSec;

    // Private inputs
    signal input approvalIdHash;
    signal input signerSetHash;
    signal input dstChainId;
    signal input amount;
    signal input signersPresent;
    signal input validUntil;
    signal input salt;

    signal output accepted;

    // 1. Recompute the origin commitment so the public input is bound to the
    //    private witness. Any tampering with hidden fields breaks this equality.
    component poseidon = Poseidon(7);
    poseidon.inputs[0] <== approvalIdHash;
    poseidon.inputs[1] <== signerSetHash;
    poseidon.inputs[2] <== dstChainId;
    poseidon.inputs[3] <== amount;
    poseidon.inputs[4] <== signersPresent;
    poseidon.inputs[5] <== validUntil;
    poseidon.inputs[6] <== salt;
    originCommitment === poseidon.out;

    // 2. Destination chain must equal the policy target.
    dstChainId === policyDstChainId;

    // 3. amount <= policyMaxAmount  (range-bounded so LessEqThan is sound)
    component fits = AmountFits();
    fits.amount <== amount;
    component capFits = AmountFits();
    capFits.amount <== policyMaxAmount;
    component leAmount = LessEqThan(240);
    leAmount.in[0] <== amount;
    leAmount.in[1] <== policyMaxAmount;
    leAmount.out === 1;

    // 4. signersPresent >= policyMinSigners  (small range, 16 bits is plenty)
    component geSigners = GreaterEqThan(16);
    geSigners.in[0] <== signersPresent;
    geSigners.in[1] <== policyMinSigners;
    geSigners.out === 1;

    // 5. nowSec <= validUntil  (approval not expired)
    component leTime = LessEqThan(64);
    leTime.in[0] <== nowSec;
    leTime.in[1] <== validUntil;
    leTime.out === 1;

    accepted <== 1;
}

component main { public [
    originCommitment,
    policyDstChainId,
    policyMaxAmount,
    policyMinSigners,
    nowSec
] } = BridgeApprovalOrigin();
