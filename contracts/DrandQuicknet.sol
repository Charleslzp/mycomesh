// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice On-chain verification of drand "quicknet" beacons
/// (scheme bls-unchained-g1-rfc9380: signatures on G1, public key on G2).
/// @dev Uses the EIP-2537 BLS12-381 precompiles (Prague) plus SHA-256 and
/// MODEXP. hash_to_curve follows RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_;
/// the MAP_FP_TO_G1 precompile clears the cofactor per point, which is
/// equivalent to clearing it after the addition because clearing is linear.
/// Points use the EIP-2537 uncompressed encoding (64-byte padded Fp limbs).
library DrandQuicknet {
    uint256 internal constant GENESIS_TIME = 1692803367;
    uint256 internal constant PERIOD = 3;

    address private constant SHA256 = address(0x02);
    address private constant MODEXP = address(0x05);
    address private constant BLS12_G1ADD = address(0x0b);
    address private constant BLS12_PAIRING_CHECK = address(0x0f);
    address private constant BLS12_MAP_FP_TO_G1 = address(0x10);

    bytes internal constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    // A failing precompile consumes all gas it is given; bound each call to
    // its EIP-2537 price plus margin so an invalid submission cannot burn a
    // whole transaction's gas.  Pairing: 32600*k + 37700 for k = 2 pairs.
    uint256 private constant PAIRING_GAS = 130_000;
    uint256 private constant MAP_GAS = 10_000;
    uint256 private constant G1ADD_GAS = 1_000;
    uint256 private constant MODEXP_GAS = 10_000;

    // quicknet group public key (chain 52db9ba7…), G2, EIP-2537 encoding x.c0|x.c1|y.c0|y.c1.
    bytes internal constant PUBLIC_KEY =
        hex"000000000000000000000000000000000d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
        hex"0000000000000000000000000000000003cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d106451"
        hex"000000000000000000000000000000000e5db2b6bfbb01c867749cadffca88b36c24f3012ba09fc4d3022c5c37dce0f977d3adb5d183c7477c442b1f04515273"
        hex"0000000000000000000000000000000001a714f2edb74119a2f2b0d5a7c75ba902d163700a61bc224ededd8e63aef7be1aaf8e93d7a9718b047ccddb3eb5d68b";

    // Negated G2 generator, same encoding.
    bytes internal constant NEG_G2_GENERATOR =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa"
        hex"0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @notice The first round published at or after `timestamp`.
    function roundAt(uint256 timestamp) internal pure returns (uint64) {
        require(timestamp >= GENESIS_TIME); // before drand genesis
        uint256 elapsed = timestamp - GENESIS_TIME;
        return uint64(elapsed / PERIOD + (elapsed % PERIOD == 0 ? 1 : 2));
    }

    /// @notice Verify a quicknet signature (128-byte uncompressed G1) for `round`.
    function verify(uint64 round, bytes memory signature) internal view returns (bool) {
        if (signature.length != 128) return false;
        bytes memory message = abi.encodePacked(sha256(abi.encodePacked(round)));
        bytes memory hashed = hashToG1(message, DST);
        // e(sig, -G2) * e(H(m), pk) == 1  <=>  e(sig, G2) == e(H(m), pk)
        (bool ok, bytes memory out) = BLS12_PAIRING_CHECK.staticcall{gas: PAIRING_GAS}(
            abi.encodePacked(signature, NEG_G2_GENERATOR, hashed, PUBLIC_KEY)
        );
        return ok && out.length == 32 && uint256(bytes32(out)) == 1;
    }

    function hashToG1(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        bytes memory uniform = expandMessageXmd(message, dst, 128);
        bytes memory q0 = _mapToG1(_reduceToField(uniform, 0));
        bytes memory q1 = _mapToG1(_reduceToField(uniform, 64));
        (bool ok, bytes memory point) = BLS12_G1ADD.staticcall{gas: G1ADD_GAS}(abi.encodePacked(q0, q1));
        require(ok && point.length == 128); // G1 addition failed
        return point;
    }

    /// @dev RFC 9380 section 5.3.1 with SHA-256 (b_in_bytes 32, s_in_bytes 64).
    function expandMessageXmd(bytes memory message, bytes memory dst, uint16 length)
        internal pure returns (bytes memory uniform)
    {
        require(dst.length <= 255 && length <= 255 * 32 && length > 0); // bad xmd parameters
        uint256 ell = (uint256(length) + 31) / 32;
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, length, uint8(0), dstPrime));
        bytes32 previous = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        uniform = new bytes(ell * 32);
        _store(uniform, 0, previous);
        for (uint256 i = 2; i <= ell; ++i) {
            previous = sha256(abi.encodePacked(b0 ^ previous, uint8(i), dstPrime));
            _store(uniform, (i - 1) * 32, previous);
        }
        assembly ("memory-safe") {
            mstore(uniform, length)
        }
    }

    /// @dev Reduce a 64-byte big-endian integer mod p to a 64-byte padded Fp.
    function _reduceToField(bytes memory uniform, uint256 offset) private view returns (bytes memory element) {
        bytes memory chunk = new bytes(64);
        for (uint256 i; i < 64; ++i) chunk[i] = uniform[offset + i];
        (bool ok, bytes memory reduced) = MODEXP.staticcall{gas: MODEXP_GAS}(
            abi.encodePacked(uint256(64), uint256(1), uint256(48), chunk, uint8(1), FIELD_MODULUS)
        );
        require(ok && reduced.length == 48); // field reduction failed
        element = abi.encodePacked(bytes16(0), reduced);
    }

    function _mapToG1(bytes memory element) private view returns (bytes memory point) {
        bool ok;
        (ok, point) = BLS12_MAP_FP_TO_G1.staticcall{gas: MAP_GAS}(element);
        require(ok && point.length == 128); // map to G1 failed
    }

    function _store(bytes memory target, uint256 offset, bytes32 value) private pure {
        assembly ("memory-safe") {
            mstore(add(add(target, 32), offset), value)
        }
    }
}
