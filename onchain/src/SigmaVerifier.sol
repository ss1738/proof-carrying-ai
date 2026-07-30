// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SigmaVerifier
/// @notice On-chain verifier for a Cramer-Damgard-Schoenmakers Sigma OR-proof over BN254 G1 -- proof that a
///         hidden committed value opens to an element of a public allowed set (e.g. an allowlisted
///         counterparty, or a policy verdict), verified with the alt_bn128 ecAdd/ecMul precompiles and the
///         sha256 precompile. This is the on-chain half of a proof-carrying compliance certificate: a smart
///         account / bundler can gate an action on `verify(...) == true` without learning the hidden value.
///         Same protocol as the off-chain Python prover (onchain_prove.py); a proof made there verifies here.
contract SigmaVerifier {
    uint256 constant G1X = 1;
    uint256 constant G1Y = 2;
    uint256 constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Nothing-up-my-sleeve Pedersen second generator H (hash-to-curve of "pcai/bn254/pedersen-h")
    uint256 constant HX = 7989823128335362891417955879273342583916629391038967513688703484324888442376;
    uint256 constant HY = 8427806557069142398484374507457439931076286578412261432874822667586536160534;

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

    function _ecAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal view returns (uint256 x, uint256 y) {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory out;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x06, input, 0x80, out, 0x40)
        }
        require(ok, "ecAdd");
        return (out[0], out[1]);
    }

    function _ecMul(uint256 x1, uint256 y1, uint256 s) internal view returns (uint256 x, uint256 y) {
        uint256[3] memory input = [x1, y1, s];
        uint256[2] memory out;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x07, input, 0x60, out, 0x40)
        }
        require(ok, "ecMul");
        return (out[0], out[1]);
    }

    /// Fiat-Shamir challenge over the exact byte layout the prover hashed.
    function _challenge(Proof calldata p) internal pure returns (uint256) {
        bytes memory buf = abi.encodePacked(p.domain, G1X, G1Y, HX, HY, p.Cx, p.Cy);
        for (uint256 i = 0; i < p.ms.length; i++) buf = abi.encodePacked(buf, p.ms[i]);
        for (uint256 i = 0; i < p.tx.length; i++) buf = abi.encodePacked(buf, p.tx[i], p.ty[i]);
        return uint256(sha256(buf)) % R;
    }

    /// One clause: check z_i*H == t_i + e_i*(C - ms_i*G).
    function _clauseOK(uint256 Cx, uint256 Cy, uint256 mi, uint256 tix, uint256 tiy, uint256 ei, uint256 zi)
        internal
        view
        returns (bool)
    {
        (uint256 yx, uint256 yy) = _ecMul(G1X, G1Y, (R - (mi % R)) % R); // -ms_i * G
        (yx, yy) = _ecAdd(Cx, Cy, yx, yy); // Y_i = C - ms_i*G
        (uint256 lx, uint256 ly) = _ecMul(HX, HY, zi); // z_i * H
        (uint256 rx, uint256 ry) = _ecMul(yx, yy, ei); // e_i * Y_i
        (rx, ry) = _ecAdd(tix, tiy, rx, ry); // t_i + e_i*Y_i
        return lx == rx && ly == ry;
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
