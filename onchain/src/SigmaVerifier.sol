// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BN254Sigma.sol";

/// @title SigmaVerifier
/// @notice On-chain verifier for a Cramer-Damgard-Schoenmakers Sigma OR-proof over BN254 G1 -- proof that a
///         hidden committed value opens to an element of a public allowed set (e.g. an allowlisted
///         counterparty, or a policy verdict). Same protocol as the off-chain prover (onchain_prove.py).
contract SigmaVerifier is BN254Sigma {
    struct Proof {
        bytes32 domain;
        uint256[] ms;
        uint256 Cx;
        uint256 Cy;
        uint256[] tx;
        uint256[] ty;
        uint256[] e;
        uint256[] z;
    }

    /// Fiat-Shamir challenge over the exact byte layout the prover hashed.
    function _challenge(Proof calldata p) internal pure returns (uint256) {
        bytes memory buf = abi.encodePacked(p.domain, G1X, G1Y, HX, HY, p.Cx, p.Cy);
        for (uint256 i = 0; i < p.ms.length; i++) buf = abi.encodePacked(buf, p.ms[i]);
        for (uint256 i = 0; i < p.tx.length; i++) buf = abi.encodePacked(buf, p.tx[i], p.ty[i]);
        return uint256(sha256(buf)) % R;
    }

    /// @notice Verify a Sigma OR-proof that commitment C opens to some element of `p.ms`.
    function verify(Proof calldata p) external view returns (bool) {
        uint256 n = p.ms.length;
        if (p.tx.length != n || p.ty.length != n || p.e.length != n || p.z.length != n || n == 0) return false;

        uint256 esum;
        for (uint256 i = 0; i < n; i++) {
            if (p.e[i] >= R || p.z[i] >= R) return false;
            esum = addmod(esum, p.e[i], R);
        }
        if (_challenge(p) != esum) return false;

        for (uint256 i = 0; i < n; i++) {
            if (!_clauseOK(p.Cx, p.Cy, p.ms[i], p.tx[i], p.ty[i], p.e[i], p.z[i])) return false;
        }
        return true;
    }
}
