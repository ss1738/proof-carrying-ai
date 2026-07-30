// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BN254Sigma
/// @notice Shared BN254 (alt_bn128) helpers for the on-chain Sigma-proof verifiers: the ecAdd/ecMul
///         precompiles, the Pedersen generators, and a single OR-proof clause check. Inherited by
///         SigmaVerifier (set membership) and RangeVerifier (spend_cap via bit-decomposition).
abstract contract BN254Sigma {
    uint256 internal constant G1X = 1;
    uint256 internal constant G1Y = 2;
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Nothing-up-my-sleeve Pedersen second generator H (hash-to-curve of "pcai/bn254/pedersen-h")
    uint256 internal constant HX = 7989823128335362891417955879273342583916629391038967513688703484324888442376;
    uint256 internal constant HY = 8427806557069142398484374507457439931076286578412261432874822667586536160534;

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

    /// One OR-proof clause: check z_i*H == t_i + e_i*(C - ms_i*G).
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
}
