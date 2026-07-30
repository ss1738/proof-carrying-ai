// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/RangeVerifier.sol";

/// Verifies a REAL spend_cap range proof (onchain_prove.py range_proof.json) on-chain via BN254 precompiles.
/// Regenerate with: python3 onchain_prove.py
contract RangeVerifierTest is Test {
    RangeVerifier v;
    RangeVerifier.RangeProof rp;

    function setUp() public {
        v = new RangeVerifier();
        string memory js = vm.readFile(string.concat(vm.projectRoot(), "/range_proof.json"));
        rp.limit = vm.parseJsonUint(js, ".limit");
        rp.CAx = vm.parseJsonUint(js, ".CAx");
        rp.CAy = vm.parseJsonUint(js, ".CAy");
        bytes32[] memory doms = vm.parseJsonBytes32Array(js, ".domains");
        uint256[] memory cx = vm.parseJsonUintArray(js, ".bitCx");
        uint256[] memory cy = vm.parseJsonUintArray(js, ".bitCy");
        uint256[] memory t0x = vm.parseJsonUintArray(js, ".t0x");
        uint256[] memory t0y = vm.parseJsonUintArray(js, ".t0y");
        uint256[] memory t1x = vm.parseJsonUintArray(js, ".t1x");
        uint256[] memory t1y = vm.parseJsonUintArray(js, ".t1y");
        uint256[] memory e0 = vm.parseJsonUintArray(js, ".e0");
        uint256[] memory e1 = vm.parseJsonUintArray(js, ".e1");
        uint256[] memory z0 = vm.parseJsonUintArray(js, ".z0");
        uint256[] memory z1 = vm.parseJsonUintArray(js, ".z1");
        for (uint256 i = 0; i < doms.length; i++) {
            rp.domains.push(doms[i]);
            rp.bits.push(RangeVerifier.BitProof(cx[i], cy[i], t0x[i], t0y[i], t1x[i], t1y[i], e0[i], e1[i], z0[i], z1[i]));
        }
    }

    function test_range_proof_verifies_onchain() public view {
        assertTrue(v.verifyRange(rp), "honest range proof must verify");
    }

    function test_gas_report() public view {
        uint256 g0 = gasleft();
        bool ok = v.verifyRange(rp);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        console.log("verifyRange gas (nbits=%s):", rp.bits.length, used);
    }

    function test_tampered_amount_rejected() public {
        // swap in a valid-but-wrong commitment (the generator G1): homomorphic bind must fail -> false.
        RangeVerifier.RangeProof memory bad = rp;
        bad.CAx = 1;
        bad.CAy = 2;
        assertFalse(v.verifyRange(bad), "wrong C_amount must be rejected");
    }

    function test_offcurve_amount_reverts() public {
        // an off-curve point fails closed (the precompile reverts) -- also a rejection, just via revert.
        RangeVerifier.RangeProof memory bad = rp;
        bad.CAx = rp.CAx + 1;
        vm.expectRevert();
        v.verifyRange(bad);
    }

    function test_tampered_limit_rejected() public {
        RangeVerifier.RangeProof memory bad = rp;
        bad.limit = rp.limit + 1; // homomorphic bind no longer holds
        assertFalse(v.verifyRange(bad), "tampered limit must be rejected");
    }

    function test_vacuous_too_many_bits_rejected() public {
        // a range proof over > MAX_BITS (64) bits approaches the group order -> vacuous; must be rejected
        // by the bit-count cap, before any per-bit work. Pad to 65 dummy bits.
        RangeVerifier.RangeProof memory big = rp;
        RangeVerifier.BitProof[] memory bits = new RangeVerifier.BitProof[](65);
        bytes32[] memory doms = new bytes32[](65);
        for (uint256 i = 0; i < 65; i++) {
            bits[i] = rp.bits[0];
            doms[i] = rp.domains[0];
        }
        big.bits = bits;
        big.domains = doms;
        assertFalse(v.verifyRange(big), "range proof over 64 bits must be rejected (vacuous)");
    }
}
