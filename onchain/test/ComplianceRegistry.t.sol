// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ComplianceRegistry.sol";
import "../src/SigmaVerifier.sol";
import "../src/RangeVerifier.sol";

/// Composes the two on-chain verifiers into a registry and attests a REAL certificate (proof.json +
/// range_proof.json from onchain_prove.py). Regenerate with: python3 onchain_prove.py
contract ComplianceRegistryTest is Test {
    ComplianceRegistry reg;
    RangeVerifier.RangeProof rp;
    SigmaVerifier.Proof mp;

    function setUp() public {
        SigmaVerifier sigma = new SigmaVerifier();
        RangeVerifier range = new RangeVerifier();
        reg = new ComplianceRegistry(sigma, range);

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

        string memory ms = vm.readFile(string.concat(vm.projectRoot(), "/proof.json"));
        mp.domain = vm.parseJsonBytes32(ms, ".domain");
        mp.ms = vm.parseJsonUintArray(ms, ".ms");
        mp.Cx = vm.parseJsonUint(ms, ".Cx");
        mp.Cy = vm.parseJsonUint(ms, ".Cy");
        mp.tx = vm.parseJsonUintArray(ms, ".tx");
        mp.ty = vm.parseJsonUintArray(ms, ".ty");
        mp.e = vm.parseJsonUintArray(ms, ".e");
        mp.z = vm.parseJsonUintArray(ms, ".z");
    }

    function test_attest_records_valid_certificate() public {
        bytes32 policyId = keccak256("spend_cap=1000,allow=alice,bob,carol");
        uint256 id = reg.attest(policyId, rp, mp);
        assertEq(id, 1);
        assertTrue(reg.isAttested(1));
        (bytes32 pid,,,, ) = reg.attestations(1);
        assertEq(pid, policyId);
    }

    function test_attest_emits_event() public {
        bytes32 policyId = keccak256("policy");
        vm.expectEmit(true, true, true, false);
        emit ComplianceRegistry.Attested(1, policyId, address(this));
        reg.attest(policyId, rp, mp);
    }

    function test_attest_reverts_on_bad_range() public {
        RangeVerifier.RangeProof memory bad = rp;
        bad.limit = rp.limit + 1; // homomorphic bind breaks
        vm.expectRevert(bytes("range proof invalid"));
        reg.attest(keccak256("policy"), bad, mp);
    }

    function test_attest_reverts_on_bad_membership() public {
        SigmaVerifier.Proof memory bad = mp;
        bad.Cx = mp.Cx + 1; // off-curve / wrong commitment
        vm.expectRevert();
        reg.attest(keccak256("policy"), rp, bad);
    }
}
