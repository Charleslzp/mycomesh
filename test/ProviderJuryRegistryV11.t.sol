// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV11 as V11} from "../contracts/MycoSettlementV11.sol";
import {ProviderJuryRegistryV11 as Registry} from "../contracts/ProviderJuryRegistryV11.sol";
import {MycoERC1967Proxy} from "../contracts/MycoUpgradeable.sol";
import {DrandQuicknet} from "../contracts/DrandQuicknet.sol";
import {MockExactTokenV9 as Token, VmV9} from "./MycoSettlementV9.t.sol";

contract ProviderJuryRegistryV11Test {
    VmV9 constant vm = VmV9(address(uint160(uint256(keccak256("hevm cheat code")))));
    // drand quicknet round 1000000 (published at genesis + 999999 * 3).
    uint64 constant ROUND = 1_000_000;
    bytes constant ROUND_SIGNATURE =
        hex"0000000000000000000000000000000003ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72"
        hex"0000000000000000000000000000000001776ff7408b39c5f6f9fa50746efd7eea17fbb61f2e7b9c849ff0528e5a3deeedd029d0df345199963d75ba93b5a02a";
    uint64 constant DELAY = 60;
    uint256 constant ROUND_TIME = DrandQuicknet.GENESIS_TIME + 999_999 * 3;

    uint256 constant C1 = 11; uint256 constant C2 = 12;           // consumer payment keys
    uint256 constant PSIGN = 2; uint256 constant RSIGN = 3;       // accused Provider, Relay
    uint256[3] JP = [uint256(21), 22, 23];                         // juror Providers' receipt signers
    uint256[3] JV = [uint256(31), 32, 33];                         // juror vote signers
    address constant CONSUMER1 = address(0xC1);
    address constant CONSUMER2 = address(0xC2);
    address constant PROVIDER = address(0xB0);
    address constant RELAY = address(0xA0);
    address constant PENALTY = address(0x99);
    address constant ADMIN = address(0xAD);

    Token token; V11 s; Registry registry;
    uint256 nonce;

    function _juror(uint256 i) internal pure returns (address) { return address(uint160(0xD0 + i)); }

    function setUp() public {
        vm.warp(ROUND_TIME - DELAY - 5 days);
        token = new Token();
        Registry registryImplementation = new Registry();
        registry = Registry(address(new MycoERC1967Proxy(address(registryImplementation), abi.encodeCall(
            Registry.initialize, (ADMIN, 3, 2, DELAY, Registry.Eligibility(1_000, 2, 1 days, 7 days, 1_000))
        ))));
        V11 settlementImplementation = new V11();
        s = V11(address(new MycoERC1967Proxy(address(settlementImplementation), abi.encodeCall(
            V11.initialize, (address(token), address(registry), ADMIN, V11.Params({
                disputeWindow: 1 days, arbitrationTimeout: 2 days, consumerWithdrawalDelay: 1 hours,
                reporterBond: 100, relayBps: 1000, holdbackBps: 1000, holdbackPeriod: 7 days,
                baseExposureCap: 50_000, exposureGrowthBps: 1000, maxExposureCap: 1_000_000,
                slashBps: 10_000, slashCap: 100_000, reporterBountyBps: 5000, probeVoidsPerDay: 10,
                penaltyRecipient: PENALTY
            }))
        ))));
        vm.prank(ADMIN); registry.bindSettlement(address(s));
        _fundConsumer(CONSUMER1, C1);
        _fundConsumer(CONSUMER2, C2);
        vm.prank(PROVIDER); s.authorizeProviderSigner(vm.addr(PSIGN));
        vm.prank(RELAY); s.authorizeRelaySigner(vm.addr(RSIGN));
        for (uint256 i; i < 3; ++i) {
            vm.prank(_juror(i)); s.authorizeProviderSigner(vm.addr(JP[i]));
            vm.prank(_juror(i));
            registry.register(vm.addr(JV[i]), keccak256(abi.encode("operator", i)), keccak256(abi.encode("peer", i)), bytes32(0));
        }
    }

    function _fundConsumer(address owner, uint256 keyPrivate) internal {
        token.mint(owner, 1_000_000);
        vm.prank(owner); token.approve(address(s), type(uint256).max);
        vm.prank(owner); s.deposit(500_000);
        vm.prank(owner); s.registerKey(vm.addr(keyPrivate), 100_000, 0);
    }

    function _sig(uint256 privateKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, ss, v);
    }

    function _settle(uint256 consumerKey, uint256 providerSigner, uint256 fee) internal returns (bytes32) {
        ++nonce;
        V11.SignedReceipt memory r;
        r.authorization = V11.PaymentAuthorization({
            requestId: bytes32(nonce), requestHash: keccak256(abi.encode("request", nonce)), key: vm.addr(consumerKey),
            providerSigner: vm.addr(providerSigner), relaySigner: vm.addr(RSIGN), maxFee: fee,
            issuedAt: uint64(block.timestamp), executeBy: uint64(block.timestamp + 60), deadline: uint64(block.timestamp + 2 hours)
        });
        bytes32 authHash = s.authorizationStructHash(r.authorization);
        r.receipt = V11.UsageReceipt(authHash, s.dispatchStructHash(authHash), keccak256(abi.encode("response", nonce)), 1, 1, fee);
        r.keySignature = _sig(consumerKey, s.authorizationDigest(r.authorization));
        r.relaySignature = _sig(RSIGN, s.dispatchDigest(authHash));
        r.providerSignature = _sig(providerSigner, s.receiptDigest(r.receipt));
        s.settleReceipt(r);
        return s.settlementKeyFor(r.authorization.key, r.authorization.requestId);
    }

    /// Each juror Provider serves both consumers; counted volume is capped per consumer.
    function _earnJurorReputation() internal {
        bytes32[] memory keys = new bytes32[](9);
        uint256 n;
        for (uint256 i; i < 3; ++i) {
            keys[n++] = _settle(C1, JP[i], 800);
            keys[n++] = _settle(C1, JP[i], 800); // same counterparty: counted only up to 1_000
            keys[n++] = _settle(C2, JP[i], 400);
        }
        vm.warp(block.timestamp + 1 days);
        for (uint256 i; i < n; ++i) s.release(keys[i]);
    }

    function _votes(bytes32 k, bytes32 assignment, bool confirmed, bytes32 reportId, uint256[2] memory judges)
        internal returns (V11.DisputeVotePermit[] memory permits)
    {
        permits = new V11.DisputeVotePermit[](2);
        bytes32 typehash = keccak256("DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)");
        for (uint256 i; i < 2; ++i) {
            uint64 deadline = uint64(block.timestamp + 1 hours);
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", s.DOMAIN_SEPARATOR(), keccak256(abi.encode(
                typehash, k, assignment, confirmed, reportId, keccak256("decision"), uint256(0), deadline))));
            permits[i] = V11.DisputeVotePermit(assignment, confirmed, reportId, keccak256("decision"), 0, deadline, _sig(judges[i], digest));
        }
    }

    function test_reputation_counts_capped_volume_from_distinct_counterparties() public {
        _earnJurorReputation();
        (, Registry.Stats memory stats, bool eligible) = registry.providerOf(_juror(0));
        require(stats.countedVolume == 1_400 && stats.counterparties == 2, "capped counterparty volume");
        require(eligible, "juror should be eligible after age and volume");
    }

    function test_only_settlement_writes_reputation() public {
        vm.expectRevert();
        registry.recordRelease(_juror(0), CONSUMER1, 1_000_000);
        vm.expectRevert();
        registry.recordConfirmedFraud(_juror(0));
    }

    function test_end_to_end_drand_jury_confirms_fraud() public {
        _earnJurorReputation();
        bytes32 accusedEarlier = _settle(C2, PSIGN, 20_000);
        vm.warp(block.timestamp + 1 days);
        s.release(accusedEarlier); // accused Provider now holds 1_800 holdback
        vm.warp(ROUND_TIME - DELAY);
        bytes32 k = _settle(C1, PSIGN, 10_000);
        vm.prank(CONSUMER1);
        s.openDispute(k, keccak256("evidence"));
        (Registry.AssignmentStatus status, uint64 round, , , , , uint256 candidates) = registry.assignmentInfo(k);
        require(status == Registry.AssignmentStatus.Pending && round == ROUND && candidates == 3, "jury request");
        vm.expectRevert();
        registry.finalizeJury(k, hex"00"); // invalid beacon
        registry.finalizeJury(k, ROUND_SIGNATURE);
        bytes32 assignment = registry.assignmentHash(k);
        require(assignment != bytes32(0), "jury not assigned");
        bytes32 reportId = s.reportIdFor(k, CONSUMER1, keccak256("evidence"));
        s.voteDisputeBySig(k, _votes(k, assignment, true, reportId, [JV[0], JV[1]]));
        require(uint8(s.settlementInfo(k).status) == uint8(V11.Status.Confirmed), "fraud not confirmed");
        // Consumer 1 paid 3 juror Providers 2 x 800 each; the disputed 10_000 is refunded.
        require(s.availableBalance(CONSUMER1) == 500_000 - 4_800, "consumer refunded");
        (, Registry.Stats memory accused, ) = registry.providerOf(PROVIDER);
        require(accused.countedVolume == 0 && accused.epoch == 1 && accused.lastFraudAt == block.timestamp, "reputation reset");
        require(s.holdbackBalance(PROVIDER) == 0, "holdback penalized");
    }

    function test_too_few_eligible_jurors_refunds_after_timeout() public {
        // No juror has earned reputation, so no jury can form.
        bytes32 k = _settle(C1, PSIGN, 10_000);
        vm.prank(CONSUMER1);
        s.openDispute(k, keccak256("evidence"));
        (Registry.AssignmentStatus status, , , , , , ) = registry.assignmentInfo(k);
        require(status == Registry.AssignmentStatus.Failed, "jury should be unavailable");
        vm.warp(block.timestamp + 3 days);
        s.resolveTimedOutDispute(k);
        require(uint8(s.settlementInfo(k).status) == uint8(V11.Status.JuryUnavailable), "refund path");
        require(s.availableBalance(CONSUMER1) == 500_000, "consumer refunded");
    }

    function test_case_parties_are_never_candidates() public {
        _earnJurorReputation();
        vm.warp(ROUND_TIME - DELAY);
        // Juror 0 is the accused here, so only two candidates remain (< jury size 3).
        bytes32 k = _settle(C1, JP[0], 900);
        vm.prank(CONSUMER1);
        s.openDispute(k, keccak256("evidence"));
        (Registry.AssignmentStatus status, , , , , , uint256 candidates) = registry.assignmentInfo(k);
        require(status == Registry.AssignmentStatus.Failed && candidates == 2, "accused must be excluded");
    }
}
