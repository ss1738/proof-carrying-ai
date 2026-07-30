// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BN254Sigma.sol";

/// @title RangeVerifier
/// @notice On-chain verifier for a spend_cap range proof (amount <= limit) over BN254, by bit-decomposition:
///         each bit carries a Sigma OR-proof over {0,1}, and the Pedersen homomorphism binds them --
///         sum_i 2^i * C_bit_i == limit*G - C_amount. This is the on-chain half of the spend_cap rule of a
///         proof-carrying payment certificate. Same protocol as onchain_prove.py's range_prove.
contract RangeVerifier is BN254Sigma {
    struct BitProof {
        uint256 Cx;
        uint256 Cy;
        uint256 t0x;
        uint256 t0y;
        uint256 t1x;
        uint256 t1y;
        uint256 e0;
        uint256 e1;
        uint256 z0;
        uint256 z1;
    }

    struct RangeProof {
        uint256 limit;
        uint256 CAx; // C_amount
        uint256 CAy;
        bytes32[] domains; // per-bit Fiat-Shamir domain
        BitProof[] bits;
    }

    /// One bit is a Sigma OR-proof that C_bit opens to {0,1}.
    function _bitOK(bytes32 dom, BitProof calldata b) internal view returns (bool) {
        if (b.e0 >= R || b.e1 >= R || b.z0 >= R || b.z1 >= R) return false;
        bytes memory buf = abi.encodePacked(
            dom, G1X, G1Y, HX, HY, b.Cx, b.Cy, uint256(0), uint256(1), b.t0x, b.t0y, b.t1x, b.t1y
        );
        if (uint256(sha256(buf)) % R != addmod(b.e0, b.e1, R)) return false;
        if (!_clauseOK(b.Cx, b.Cy, 0, b.t0x, b.t0y, b.e0, b.z0)) return false;
        if (!_clauseOK(b.Cx, b.Cy, 1, b.t1x, b.t1y, b.e1, b.z1)) return false;
        return true;
    }

    /// @notice Verify that C_amount hides a value <= limit (0 <= amount <= limit < 2^nbits).
    function verifyRange(RangeProof calldata p) external view returns (bool) {
        uint256 n = p.bits.length;
        if (n == 0 || p.domains.length != n) return false;

        for (uint256 i = 0; i < n; i++) {
            if (!_bitOK(p.domains[i], p.bits[i])) return false;
        }

        // homomorphic bind: sum_i 2^i * C_bit_i == limit*G - C_amount
        uint256 ax;
        uint256 ay; // accumulator = identity (0,0)
        for (uint256 i = 0; i < n; i++) {
            (uint256 wx, uint256 wy) = _ecMul(p.bits[i].Cx, p.bits[i].Cy, (uint256(1) << i) % R);
            (ax, ay) = _ecAdd(ax, ay, wx, wy);
        }
        (uint256 dx, uint256 dy) = _ecMul(G1X, G1Y, p.limit % R); // limit*G
        (uint256 nx, uint256 ny) = _ecMul(p.CAx, p.CAy, R - 1); // -C_amount
        (dx, dy) = _ecAdd(dx, dy, nx, ny); // limit*G - C_amount
        return ax == dx && ay == dy;
    }
}
