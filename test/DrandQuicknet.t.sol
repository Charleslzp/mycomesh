// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DrandQuicknet} from "../contracts/DrandQuicknet.sol";

contract DrandQuicknetHarness {
    function hashToG1(bytes calldata message, bytes calldata dst) external view returns (bytes memory) {
        return DrandQuicknet.hashToG1(message, dst);
    }
    function verify(uint64 round, bytes calldata signature) external view returns (bool) {
        return DrandQuicknet.verify(round, signature);
    }
    function roundAt(uint256 timestamp) external pure returns (uint64) {
        return DrandQuicknet.roundAt(timestamp);
    }
}

contract DrandQuicknetTest {
    DrandQuicknetHarness harness;
    bytes constant QUUX_DST = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    // drand quicknet round 1000000, uncompressed from the published signature
    // 83ad29e4…8abe72.
    bytes constant ROUND_1000000_SIGNATURE =
        hex"0000000000000000000000000000000003ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72"
        hex"0000000000000000000000000000000001776ff7408b39c5f6f9fa50746efd7eea17fbb61f2e7b9c849ff0528e5a3deeedd029d0df345199963d75ba93b5a02a";

    function setUp() public {
        harness = new DrandQuicknetHarness();
    }

    function _padded(bytes memory x, bytes memory y) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes16(0), x, bytes16(0), y);
    }

    /// RFC 9380 Appendix J.9.1, msg = "".
    function test_hash_to_g1_matches_rfc9380_empty_message() public view {
        bytes memory expected = _padded(
            hex"052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
            hex"08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"
        );
        require(keccak256(harness.hashToG1("", QUUX_DST)) == keccak256(expected), "rfc9380 empty vector");
    }

    /// RFC 9380 Appendix J.9.1, msg = "abc".
    function test_hash_to_g1_matches_rfc9380_abc() public view {
        bytes memory expected = _padded(
            hex"03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
            hex"0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"
        );
        require(keccak256(harness.hashToG1("abc", QUUX_DST)) == keccak256(expected), "rfc9380 abc vector");
    }

    function test_verifies_a_real_quicknet_beacon() public view {
        require(harness.verify(1_000_000, ROUND_1000000_SIGNATURE), "real beacon rejected");
    }

    function test_rejects_wrong_round_and_tampered_signature() public view {
        require(!harness.verify(1_000_001, ROUND_1000000_SIGNATURE), "wrong round accepted");
        bytes memory tampered = ROUND_1000000_SIGNATURE;
        tampered[127] = bytes1(uint8(tampered[127]) ^ 1);
        require(!harness.verify(1_000_000, tampered), "tampered signature accepted");
        require(!harness.verify(1_000_000, hex"00"), "short signature accepted");
    }

    function test_round_schedule() public view {
        uint256 genesis = DrandQuicknet.GENESIS_TIME;
        require(harness.roundAt(genesis) == 1, "genesis round");
        require(harness.roundAt(genesis + 1) == 2, "next published round");
        require(harness.roundAt(genesis + 3) == 2, "exact period boundary");
        // round 1000000 was published at genesis + 999999 * 3.
        require(harness.roundAt(genesis + 999_999 * 3) == 1_000_000, "known round time");
    }
}
