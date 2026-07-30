// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SigmaVerifier.sol";
import "./RangeVerifier.sol";

/// @title ComplianceRegistry
/// @notice On-chain, verifiable compliance attestations for AI agent actions. An operator submits a
///         proof-carrying certificate (a spend_cap range proof + an allowlist membership proof); the registry
///         verifies BOTH on-chain via the BN254 precompiles and, only if both pass, records an immutable
///         attestation and emits an event. A relying party (a counterparty, an insurer, an auditor) reads the
///         registry to confirm "this agent action was proven in-policy" without trusting the operator.
///
///         This composes the audited-pending verifiers; it does not itself execute funds (binding a committed
///         amount to an executed transfer is an integration responsibility -- see SECURITY.md).
contract ComplianceRegistry {
    SigmaVerifier public immutable sigma;
    RangeVerifier public immutable range;

    struct Attestation {
        bytes32 policyId; // hash of the policy the certificate was issued under
        uint256 CAx; // committed amount (Pedersen commitment)
        uint256 CAy;
        address attester;
        uint64 time;
    }

    uint256 public count;
    mapping(uint256 => Attestation) public attestations;

    event Attested(uint256 indexed id, bytes32 indexed policyId, address indexed attester);

    constructor(SigmaVerifier _sigma, RangeVerifier _range) {
        sigma = _sigma;
        range = _range;
    }

    /// @notice Verify a proof-carrying certificate and record an attestation. Reverts if either proof fails.
    function attest(bytes32 policyId, RangeVerifier.RangeProof calldata rp, SigmaVerifier.Proof calldata mp)
        external
        returns (uint256 id)
    {
        require(range.verifyRange(rp), "range proof invalid");
        require(sigma.verify(mp), "membership proof invalid");
        id = ++count;
        attestations[id] = Attestation(policyId, rp.CAx, rp.CAy, msg.sender, uint64(block.timestamp));
        emit Attested(id, policyId, msg.sender);
    }

    function isAttested(uint256 id) external view returns (bool) {
        return id != 0 && id <= count;
    }
}
