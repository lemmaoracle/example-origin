pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * lst-collateral-origin
 *
 * Proves hidden LST/LRT collateral provenance is bound to a public collateral
 * commitment and satisfies a lending market's pre-acceptance policy.
 *
 * Public:
 *   collateralCommitment   Poseidon over (lotIdHash, assetIdHash, mintChainId,
 *                                         custodyHops, rehypothecationDepth,
 *                                         validatorSetRevoked, mintedAt, salt)
 *   policyAssetIdHash      Asset id hash the lender accepts
 *   policyMaxRehypoDepth   Maximum rehypothecation depth allowed
 *   policyMaxCustodyHops   Maximum custody hop count allowed
 *   policyMinMintAge       Minimum age (seconds) the mint event must have
 *   nowSec                 Current timestamp
 *
 * Private (witness):
 *   lotIdHash              Hash of the lot identifier
 *   assetIdHash            Hash of the asset id (e.g. rsETH)
 *   mintChainId            Chain id where the LST/LRT was minted
 *   custodyHops            Number of custody hops
 *   rehypothecationDepth   Rehypothecation depth (0 = no rehypothecation)
 *   validatorSetRevoked    1 iff validator set revoked, 0 otherwise (boolean-constrained)
 *   mintedAt               Mint event timestamp (unix seconds)
 *   salt                   Per-issuance blinding factor
 *
 * Output / constraint:
 *   accepted == 1 iff all policy checks hold.
 *
 * Off-circuit (intentionally not proved here):
 *   - issuer BBS+ signature over the disclosure root
 *   - validator-set revocation accumulator anchoring (the boolean here is a
 *     witness *to* that off-circuit check; production wires a Merkle proof of
 *     non-membership against a revoked-roots accumulator)
 *   - custody-path Merkle proof (we only constrain the length here; full
 *     identities can ride alongside as selective-disclosure leaves)
 *   - mint chain whitelist (cheaper as a contract-side eq check on a small set)
 */

template LstCollateralOrigin() {
    // Public inputs
    signal input collateralCommitment;
    signal input policyAssetIdHash;
    signal input policyMaxRehypoDepth;
    signal input policyMaxCustodyHops;
    signal input policyMinMintAge;
    signal input nowSec;

    // Private inputs
    signal input lotIdHash;
    signal input assetIdHash;
    signal input mintChainId;
    signal input custodyHops;
    signal input rehypothecationDepth;
    signal input validatorSetRevoked;
    signal input mintedAt;
    signal input salt;

    signal output accepted;

    // 1. Recompute the collateral commitment.
    component poseidon = Poseidon(8);
    poseidon.inputs[0] <== lotIdHash;
    poseidon.inputs[1] <== assetIdHash;
    poseidon.inputs[2] <== mintChainId;
    poseidon.inputs[3] <== custodyHops;
    poseidon.inputs[4] <== rehypothecationDepth;
    poseidon.inputs[5] <== validatorSetRevoked;
    poseidon.inputs[6] <== mintedAt;
    poseidon.inputs[7] <== salt;
    collateralCommitment === poseidon.out;

    // 2. assetIdHash must equal the policy's accepted asset.
    assetIdHash === policyAssetIdHash;

    // 3. validatorSetRevoked must be boolean and clear (== 0).
    validatorSetRevoked * (validatorSetRevoked - 1) === 0;
    validatorSetRevoked === 0;

    // 4. rehypothecationDepth <= policyMaxRehypoDepth
    component leDepth = LessEqThan(16);
    leDepth.in[0] <== rehypothecationDepth;
    leDepth.in[1] <== policyMaxRehypoDepth;
    leDepth.out === 1;

    // 5. custodyHops <= policyMaxCustodyHops
    component leHops = LessEqThan(16);
    leHops.in[0] <== custodyHops;
    leHops.in[1] <== policyMaxCustodyHops;
    leHops.out === 1;

    // 6. (nowSec - mintedAt) >= policyMinMintAge  ⇒ mintedAt + policyMinMintAge <= nowSec
    signal mintedAtPlusMin;
    mintedAtPlusMin <== mintedAt + policyMinMintAge;
    component leAge = LessEqThan(64);
    leAge.in[0] <== mintedAtPlusMin;
    leAge.in[1] <== nowSec;
    leAge.out === 1;

    accepted <== 1;
}

component main { public [
    collateralCommitment,
    policyAssetIdHash,
    policyMaxRehypoDepth,
    policyMaxCustodyHops,
    policyMinMintAge,
    nowSec
] } = LstCollateralOrigin();
