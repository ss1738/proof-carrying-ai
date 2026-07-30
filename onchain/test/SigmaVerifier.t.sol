// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/SigmaVerifier.sol";

/// Verifies a REAL proof produced by onchain_prove.py (proof.json), on-chain, via the BN254 precompiles.
/// Regenerate the proof with: python3 onchain_prove.py
contract SigmaVerifierTest is Test {
    SigmaVerifier v;
    SigmaVerifier.Proof p;

    function setUp() public {
        v = new SigmaVerifier();
        string memory js = vm.readFile(string.concat(vm.projectRoot(), "/proof.json"));
        p.domain = vm.parseJsonBytes32(js, ".domain");
        p.ms = vm.parseJsonUintArray(js, ".ms");
        p.Cx = vm.parseJsonUint(js, ".Cx");
        p.Cy = vm.parseJsonUint(js, ".Cy");
        p.tx = vm.parseJsonUintArray(js, ".tx");
        p.ty = vm.parseJsonUintArray(js, ".ty");
        p.e = vm.parseJsonUintArray(js, ".e");
        p.z = vm.parseJsonUintArray(js, ".z");
    }

    function test_honest_proof_verifies_onchain() public view {
        assertTrue(v.verify(p), "honest proof must verify");
    }

    function test_gas_report() public view {
        uint256 g0 = gasleft();
        bool ok = v.verify(p);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        console.log("verify gas (|ms|=%s):", p.ms.length, used);
    }

    function test_tampered_commitment_rejected() public {
        SigmaVerifier.Proof memory bad = p;
        bad.Cx = p.Cx + 1;
        assertFalse(v.verify(bad), "tampered C must be rejected");
    }

    function test_tampered_challenge_rejected() public {
        SigmaVerifier.Proof memory bad = p;
        bad.e[0] = addmod(bad.e[0], 1, type(uint256).max);
        assertFalse(v.verify(bad), "tampered e must be rejected");
    }

    function test_wrong_allowed_set_rejected() public {
        SigmaVerifier.Proof memory bad = p;
        bad.ms = new uint256[](3);
        bad.ms[0] = 4;
        bad.ms[1] = 5;
        bad.ms[2] = 6;
        assertFalse(v.verify(bad), "wrong allowed set must be rejected");
    }

    /// Fuzz: setting any challenge scalar to a different value must make the proof fail (never verify).
    function testFuzz_mutated_challenge_never_verifies(uint256 idx, uint256 val) public {
        SigmaVerifier.Proof memory bad = p;
        idx = idx % bad.e.length;
        vm.assume(val != bad.e[idx]);
        bad.e[idx] = val;
        assertFalse(v.verify(bad), "mutated challenge must not verify");
    }

    /// Fuzz: replacing the commitment x-coord with any different value must fail (wrong point) or revert
    /// (off-curve -- almost always, since a random x rarely lies on the curve).
    function testFuzz_mutated_commitment_never_verifies(uint256 cx) public {
        vm.assume(cx != p.Cx);
        SigmaVerifier.Proof memory bad = p;
        bad.Cx = cx;
        try v.verify(bad) returns (bool ok) {
            assertFalse(ok, "mutated commitment must not verify");
        } catch {
            // off-curve point -> precompile reverts -> also a rejection (fail closed)
        }
    }
}
