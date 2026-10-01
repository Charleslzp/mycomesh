// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV11 as V11} from "../contracts/MycoSettlementV11.sol";
import {MycoReleaseV11} from "../contracts/MycoReleaseV11.sol";
import {MycoSettlementBaseV11 as B} from "../contracts/MycoSettlementBaseV11.sol";
import {MycoSettlementDisputesV11 as D} from "../contracts/MycoSettlementDisputesV11.sol";
import {ProviderJuryRegistryV11 as Registry} from "../contracts/ProviderJuryRegistryV11.sol";
import {MycoERC1967Proxy} from "../contracts/MycoUpgradeable.sol";
import {DrandQuicknet} from "../contracts/DrandQuicknet.sol";
import {MockExactToken as Token, Vm} from "./TestSupport.sol";
import {RelayDirectoryV11, IMycoRelaySignersV11} from "../contracts/RelayDirectoryV11.sol";
import {MycoEmissionV11 as Emission} from "../contracts/MycoEmissionV11.sol";

contract ProviderJuryRegistryV11Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    // drand quicknet round 1000000 (published at genesis + 999999 * 3).
    uint64 constant ROUND = 1_000_000;
    bytes constant ROUND_SIGNATURE =
        hex"0000000000000000000000000000000003ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72"
        hex"0000000000000000000000000000000001776ff7408b39c5f6f9fa50746efd7eea17fbb61f2e7b9c849ff0528e5a3deeedd029d0df345199963d75ba93b5a02a";
    uint64 constant DELAY = 60;
    uint32 constant TIER = 1;
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

    address disputeModule;

    function setUp() public {
        disputeModule = address(new D());
        vm.warp(ROUND_TIME - DELAY - 5 days);
        token = new Token();
        Registry registryImplementation = new Registry();
        registry = Registry(address(new MycoERC1967Proxy(address(registryImplementation), abi.encodeCall(
            Registry.initialize, (ADMIN, 3, 2, DELAY, Registry.Eligibility(1_000, 2, 1 days, 7 days, 1_000))
        ))));
        V11 settlementImplementation = new V11(disputeModule);
        s = V11(address(new MycoERC1967Proxy(address(settlementImplementation), abi.encodeCall(
            V11.initialize, (address(token), address(registry), ADMIN, B.Params({
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
        // Jury tests price every receipt at its Consumer cap: a huge minimum fee makes maxFee bind.
        vm.prank(ADMIN); registry.setTier(TIER, Registry.Tier(1, 1, 1e12, 1e12, 7_000, true));
        vm.prank(PROVIDER); registry.setSignerTier(vm.addr(PSIGN), TIER, 1e12);
        for (uint256 i; i < 3; ++i) {
            vm.prank(_juror(i)); s.authorizeProviderSigner(vm.addr(JP[i]));
            vm.prank(_juror(i)); registry.setSignerTier(vm.addr(JP[i]), TIER, 1e12);
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

    function _keyFor(address key, bytes32 requestId) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, requestId));
    }

    function _reportFor(bytes32 key, address reporter, bytes32 evidence) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, reporter, evidence));
    }

    function _settleOne(B.SignedReceipt memory r) internal {
        B.SignedReceipt[] memory batch = new B.SignedReceipt[](1);
        batch[0] = r;
        s.settleBatch(batch);
    }

    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", s.DOMAIN_SEPARATOR(), structHash));
    }

    function _sig(uint256 privateKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, ss, v);
    }

    function _settle(uint256 consumerKey, uint256 providerSigner, uint256 fee) internal returns (bytes32) {
        return _settleAt(consumerKey, providerSigner, fee, 1, 1);
    }

    function _settleAt(uint256 consumerKey, uint256 providerSigner, uint256 fee, uint256 inputTokens, uint256 outputTokens)
        internal returns (bytes32)
    {
        B.SignedReceipt memory r = _receiptAt(consumerKey, providerSigner, fee, inputTokens, outputTokens);
        _settleOne(r);
        return _keyFor(r.authorization.key, r.authorization.requestId);
    }

    function _receiptAt(uint256 consumerKey, uint256 providerSigner, uint256 fee, uint256 inputTokens, uint256 outputTokens)
        internal returns (B.SignedReceipt memory r)
    {
        ++nonce;
        // via-IR may reuse a block.timestamp read from before a warp; ask the VM.
        uint256 now_ = vm.getBlockTimestamp();
        r.authorization = B.PaymentAuthorization({
            requestId: bytes32(nonce), requestHash: keccak256(abi.encode("request", nonce)), key: vm.addr(consumerKey),
            providerSigner: vm.addr(providerSigner), relaySigner: vm.addr(RSIGN), maxFee: fee,
            issuedAt: uint64(now_), executeBy: uint64(now_ + 60), deadline: uint64(now_ + 2 hours)
        });
        bytes32 authHash = s.authorizationStructHash(r.authorization);
        r.receipt = B.UsageReceipt(authHash, s.dispatchStructHash(authHash), keccak256(abi.encode("response", nonce)),
            inputTokens, outputTokens, fee);
        r.keySignature = _sig(consumerKey, _digest(s.authorizationStructHash(r.authorization)));
        r.relaySignature = _sig(RSIGN, _digest(s.dispatchStructHash(authHash)));
        r.providerSignature = _sig(providerSigner, _digest(s.receiptStructHash(r.receipt)));
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
        vm.warp(vm.getBlockTimestamp() + 1 days);
        for (uint256 i; i < n; ++i) s.release(keys[i]);
    }

    function _votes(bytes32 k, bytes32 assignment, bool confirmed, bytes32 reportId, uint256[2] memory judges)
        internal returns (B.DisputeVotePermit[] memory permits)
    {
        permits = new B.DisputeVotePermit[](2);
        bytes32 typehash = keccak256("DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)");
        for (uint256 i; i < 2; ++i) {
            uint64 deadline = uint64(block.timestamp + 1 hours);
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", s.DOMAIN_SEPARATOR(), keccak256(abi.encode(
                typehash, k, assignment, confirmed, reportId, keccak256("decision"), uint256(0), deadline))));
            permits[i] = B.DisputeVotePermit(assignment, confirmed, reportId, keccak256("decision"), 0, deadline, _sig(judges[i], digest));
        }
    }

    function test_reputation_counts_capped_volume_from_distinct_counterparties() public {
        _earnJurorReputation();
        (, Registry.Stats memory stats, bool eligible) = registry.providerOf(_juror(0));
        require(stats.countedVolume == 1_400 && stats.counterparties == 2, "capped counterparty volume");
        require(eligible, "juror should be eligible after age and volume");
    }

    function test_only_settlement_writes_reputation() public {
        MycoReleaseV11[] memory items = new MycoReleaseV11[](1);
        items[0] = MycoReleaseV11(_juror(0), CONSUMER1, RELAY, 1_000_000, 1);
        vm.expectRevert();
        registry.recordReleases(items, RELAY);
        vm.expectRevert();
        registry.recordConfirmedFraud(_juror(0));
    }

    function test_end_to_end_drand_jury_confirms_fraud() public {
        _earnJurorReputation();
        bytes32 accusedEarlier = _settle(C2, PSIGN, 20_000);
        vm.warp(vm.getBlockTimestamp() + 1 days);
        s.release(accusedEarlier); // accused Provider now holds 1_800 holdback
        vm.warp(ROUND_TIME - DELAY);
        bytes32 k = _settle(C1, PSIGN, 10_000);
        vm.prank(CONSUMER1);
        D(address(s)).openDispute(k, keccak256("evidence"));
        (Registry.AssignmentStatus status, uint64 round, , , , , uint256 candidates) = registry.assignmentInfo(k);
        require(status == Registry.AssignmentStatus.Pending && round == ROUND && candidates == 3, "jury request");
        vm.expectRevert();
        registry.finalizeJury(k, hex"00"); // invalid beacon
        registry.finalizeJury(k, ROUND_SIGNATURE);
        bytes32 assignment = registry.assignmentHash(k);
        require(assignment != bytes32(0), "jury not assigned");
        bytes32 reportId = _reportFor(k, CONSUMER1, keccak256("evidence"));
        D(address(s)).voteDisputeBySig(k, _votes(k, assignment, true, reportId, [JV[0], JV[1]]));
        require(uint8(D(address(s)).settlementInfo(k).status) == uint8(B.Status.Confirmed), "fraud not confirmed");
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
        D(address(s)).openDispute(k, keccak256("evidence"));
        (Registry.AssignmentStatus status, , , , , , ) = registry.assignmentInfo(k);
        require(status == Registry.AssignmentStatus.Failed, "jury should be unavailable");
        vm.warp(vm.getBlockTimestamp() + 3 days);
        D(address(s)).resolveTimedOutDispute(k);
        require(uint8(D(address(s)).settlementInfo(k).status) == uint8(B.Status.JuryUnavailable), "refund path");
        require(s.availableBalance(CONSUMER1) == 500_000, "consumer refunded");
    }

    function test_case_parties_are_never_candidates() public {
        _earnJurorReputation();
        vm.warp(ROUND_TIME - DELAY);
        // Juror 0 is the accused here, so only two candidates remain (< jury size 3).
        bytes32 k = _settle(C1, JP[0], 900);
        vm.prank(CONSUMER1);
        D(address(s)).openDispute(k, keccak256("evidence"));
        (Registry.AssignmentStatus status, , , , , , uint256 candidates) = registry.assignmentInfo(k);
        require(status == Registry.AssignmentStatus.Failed && candidates == 2, "accused must be excluded");
    }

    function test_jury_rules_are_admin_only_and_majority_bound() public {
        vm.expectRevert();
        registry.setJury(5, 3, DELAY, 0);
        vm.prank(ADMIN);
        vm.expectRevert();
        registry.setJury(5, 2, DELAY, 0); // not a majority
        vm.prank(ADMIN);
        registry.setJury(5, 3, DELAY, 50_000);
        require(registry.jurySize() == 5 && registry.threshold() == 3 && registry.maxJuryWeight() == 50_000, "rules");
    }

    /// Juror 0 out-trades the others 100:1, so it sits on (almost) every jury;
    /// many light keys cannot outweigh one Provider with real volume.
    function test_draw_is_weighted_by_counted_volume() public {
        _earnJurorReputation();
        vm.prank(ADMIN);
        registry.setEligibility(Registry.Eligibility(1_000, 2, 1 days, 7 days, 1_000_000));
        vm.prank(ADMIN);
        registry.setJury(2, 2, DELAY, 0);
        // One settlement at a time stays under the new-Provider exposure cap.
        for (uint256 i; i < 2; ++i) {
            bytes32 heavy = _settle(i == 0 ? C1 : C2, JP[0], 40_000);
            vm.warp(vm.getBlockTimestamp() + 1 days);
            s.release(heavy);
        }
        vm.warp(ROUND_TIME - DELAY);
        uint256 picked;
        for (uint256 i; i < 8; ++i) {
            bytes32 k = _settle(C1, PSIGN, 100);
            vm.prank(CONSUMER1);
            D(address(s)).openDispute(k, keccak256(abi.encode("evidence", i)));
            registry.finalizeJury(k, ROUND_SIGNATURE);
            if (registry.isVoteSigner(k, vm.addr(JV[0]))) ++picked;
        }
        require(picked == 8, "heaviest candidate should sit on every jury");
    }

    function test_relay_directory_is_permissionless_and_follows_signer_bindings() public {
        RelayDirectoryV11 directory = new RelayDirectoryV11(IMycoRelaySignersV11(address(s)));
        vm.expectRevert();
        directory.announce(vm.addr(RSIGN), "https://relay.example:10443", "relay.example:10991"); // caller does not own signer
        vm.prank(RELAY);
        directory.announce(vm.addr(RSIGN), "https://relay.example:10443", "relay.example:10991");
        (RelayDirectoryV11.Entry memory entry, bool active) = directory.relayAt(0);
        require(directory.relayCount() == 1 && active && entry.owner == RELAY, "announced");
        vm.prank(RELAY);
        s.revokeRelaySigner(vm.addr(RSIGN));
        (, active) = directory.relayAt(0);
        require(!active, "revoked signer still active");
        vm.prank(RELAY);
        directory.withdraw();
        require(directory.relayCount() == 0, "withdrawn");
    }

    // ---------------- network pricing ----------------

    uint32 constant PRICED = 2;

    /// A tier priced 1 unit per token, minimum fee 0, target 70%, new Providers capped at 10_000 work a day.
    function _pricedTier(uint128 declared) internal returns (address signer) {
        vm.prank(ADMIN);
        registry.setTier(PRICED, Registry.Tier(1_000, 1_000, 0, 10_000, 7_000, true));
        signer = vm.addr(PSIGN);
        vm.prank(PROVIDER);
        registry.setSignerTier(signer, PRICED, declared);
    }

    /// Settle `work` units (half input, half output tokens) at the network price.
    function _settleWork(uint256 work) internal returns (uint256 fee) {
        fee = registry.quote(vm.addr(PSIGN), uint64(vm.getBlockTimestamp()), work / 2, work - work / 2);
        _settleAt(C1, PSIGN, fee, work / 2, work - work / 2);
    }

    function _nextDay() internal {
        vm.warp((vm.getBlockTimestamp() / 1 days + 1) * 1 days + 60);
    }

    function test_price_rises_when_capacity_is_scarce_and_falls_when_idle() public {
        _pricedTier(10_000);
        require(_settleWork(9_000) == 9_000, "day 1 at the base price");       // 90% of 10_000: above the 70% target
        _nextDay();
        require(registry.multiplierFor(PRICED, uint64(vm.getBlockTimestamp() / 1 days)) == 1_100_000, "+10% cap");
        require(_settleWork(1_000) == 1_100, "day 2 costs 10% more");
        _nextDay();
        // Day 2 used 1_000 of 20_000 (capacity doubled with the proven peak): far below target, so -10%.
        require(registry.multiplierFor(PRICED, uint64(vm.getBlockTimestamp() / 1 days)) == 990_000, "-10% floor step");
        _nextDay();
        _nextDay();
        // Idle days count as zero utilisation: the price keeps falling until demand returns.
        require(registry.multiplierFor(PRICED, uint64(vm.getBlockTimestamp() / 1 days)) < 990_000, "idle days lower it");
    }

    function test_adjustment_is_proportional_inside_the_band() public {
        _pricedTier(10_000);
        _settleWork(7_350); // 73.5% utilisation vs a 70% target: +5%
        _nextDay();
        require(registry.multiplierFor(PRICED, uint64(vm.getBlockTimestamp() / 1 days)) == 1_050_000, "proportional step");
    }

    function test_capacity_binds_and_is_capped_by_proven_work() public {
        _pricedTier(1_000_000); // declares far more than it has proven
        require(registry.remainingCapacity(vm.addr(PSIGN)) == 10_000, "new Providers get the base capacity");
        _settleWork(10_000);
        require(registry.remainingCapacity(vm.addr(PSIGN)) == 0, "capacity used");
        uint256 fee = registry.quote(vm.addr(PSIGN), uint64(vm.getBlockTimestamp()), 1, 1);
        B.SignedReceipt memory r = _receiptAt(C1, PSIGN, fee, 1, 1);
        B.SignedReceipt[] memory batch = new B.SignedReceipt[](1);
        batch[0] = r;
        vm.expectRevert();
        s.settleBatch(batch); // beyond its daily capacity
        _nextDay();
        require(registry.remainingCapacity(vm.addr(PSIGN)) == 20_000, "twice the best day");
    }

    function test_only_the_owner_puts_a_signer_in_a_tier() public {
        vm.prank(ADMIN);
        registry.setTier(PRICED, Registry.Tier(1_000, 1_000, 0, 10_000, 7_000, true));
        vm.expectRevert();
        registry.setSignerTier(vm.addr(PSIGN), PRICED, 10_000);
        vm.prank(PROVIDER);
        vm.expectRevert();
        registry.setSignerTier(vm.addr(PSIGN), 9, 10_000); // no such tier
        vm.expectRevert();
        registry.setTier(3, Registry.Tier(1, 1, 0, 1, 7_000, true)); // not admin
    }

    function test_releases_and_frauds_reach_the_emission_schedule() public {
        Emission implementation = new Emission();
        Emission emission = Emission(address(new MycoERC1967Proxy(address(implementation), abi.encodeCall(
            Emission.initialize, (ADMIN, address(registry), address(token), uint64(vm.getBlockTimestamp()), 0, 0)))));
        vm.prank(ADMIN);
        registry.setEmission(address(emission));
        bytes32 k = _settle(C1, JP[0], 4_000);
        vm.warp(vm.getBlockTimestamp() + 1 days);
        // Too little gas for the hooks reverts instead of silently skipping reputation and rewards.
        vm.prank(address(0xEE));
        (bool ok, ) = address(s).call{gas: 300_000}(abi.encodeCall(s.release, (k)));
        require(!ok, "starved release must revert");
        vm.prank(address(0xEE));
        s.release(k); // a keeper releases
        uint64 b = emission.currentBlock();
        require(emission.spendAt(b) == 4_000, "Consumer spend recorded");
        require(emission.points(b, 0, CONSUMER1) == 4_000 && emission.points(b, 1, _juror(0)) == 4_000, "Consumer and Provider");
        require(emission.points(b, 2, RELAY) == 4_000 && emission.points(b, 3, address(0xEE)) == 4_000, "Relay and keeper");
    }

    function _emission(uint256 bounty) internal returns (Emission emission) {
        Emission implementation = new Emission();
        emission = Emission(address(new MycoERC1967Proxy(address(implementation), abi.encodeCall(
            Emission.initialize, (ADMIN, address(registry), address(token), uint64(vm.getBlockTimestamp()), 0, bounty)))));
        vm.prank(ADMIN);
        registry.setEmission(address(emission));
        if (bounty > 0) {
            token.mint(address(this), 1_000_000);
            token.approve(address(emission), type(uint256).max);
            emission.fundBounties(1_000_000);
        }
    }

    function test_release_batch_pays_like_single_releases_and_aggregates_rewards() public {
        Emission emission = _emission(10);
        bytes32[] memory keys = new bytes32[](7);
        keys[0] = _settle(C1, JP[0], 1_000);
        keys[1] = _settle(C1, JP[0], 1_000);
        keys[2] = _settle(C2, JP[0], 2_000);
        keys[3] = _settle(C1, JP[1], 3_000);
        keys[4] = _settle(C1, JP[1], 5_000);
        vm.prank(CONSUMER1);
        D(address(s)).openDispute(keys[4], keccak256("evidence")); // disputed: skipped
        vm.warp(vm.getBlockTimestamp() + 1 days);
        keys[5] = _settle(C2, JP[1], 7_000); // not due yet: skipped
        keys[6] = keys[0];                   // duplicate: released once
        uint256 relayBefore = s.claimableBalance(RELAY);
        vm.prank(address(0xEE));
        require(s.releaseBatch(keys) == 4, "four due receipts released");

        // Split per (Provider, Consumer, Relay) total, exactly as releasing each one: relay 10%, treasury 10%,
        // the Provider's 80% less 10% held back.
        require(s.claimableBalance(_juror(0)) == 1_440 + 1_440 && s.claimableBalance(_juror(1)) == 2_160, "Provider credits");
        require(s.holdbackBalance(_juror(0)) == 320 && s.holdbackBalance(_juror(1)) == 240, "holdback");
        require(s.claimableBalance(RELAY) - relayBefore == 700 && s.claimableBalance(PENALTY) == 700, "Relay and treasury");
        require(s.pendingExposure(_juror(0)) == 0 && s.pendingExposure(_juror(1)) == 12_000, "exposure");
        require(uint8(D(address(s)).settlementInfo(keys[4]).status) == uint8(B.Status.Disputed), "disputed untouched");
        require(uint8(D(address(s)).settlementInfo(keys[5]).status) == uint8(B.Status.Pending), "not due untouched");

        uint64 b = emission.currentBlock();
        require(emission.spendAt(b) == 7_000, "spend");
        require(emission.points(b, 0, CONSUMER1) == 5_000 && emission.points(b, 0, CONSUMER2) == 2_000, "Consumers");
        require(emission.points(b, 1, _juror(0)) == 4_000 && emission.points(b, 1, _juror(1)) == 3_000, "Providers");
        require(emission.points(b, 2, RELAY) == 7_000 && emission.points(b, 3, address(0xEE)) == 7_000, "Relay and keeper");
        require(emission.totalPoints(b, 0) == 7_000 && emission.totalPoints(b, 1) == 7_000, "block totals");
        (uint128 releases, ) = emission.providerRecord(_juror(0));
        require(releases == 3, "success rate counts receipts, not items");
        require(emission.bountyOwed(address(0xEE)) == 10, "one bounty per batch call");
        (, Registry.Stats memory stats, ) = registry.providerOf(_juror(0));
        require(stats.counterparties == 2 && stats.countedVolume == 2_000, "reputation per counterparty, capped");

        bytes32[] memory none = new bytes32[](1);
        none[0] = keys[5];
        vm.expectRevert();
        s.releaseBatch(none); // nothing due
    }

    function test_release_batch_gas_per_receipt() public {
        _emission(10);
        bytes32[] memory keys = new bytes32[](32);
        for (uint256 i; i < 32; ++i) keys[i] = _settle(i % 2 == 0 ? C1 : C2, JP[i % 3], 100);
        bytes32 single = _settle(C2, PSIGN, 100);
        vm.warp(vm.getBlockTimestamp() + 1 days);
        vm.prank(address(0xEE));
        uint256 start = gasleft();
        s.release(single);
        uint256 one = start - gasleft();
        vm.prank(address(0xEE));
        start = gasleft();
        s.releaseBatch(keys);
        uint256 perReceipt = (start - gasleft()) / 32;
        require(perReceipt * 4 < one, "a batch of 32 costs under a quarter per receipt");
        require(perReceipt < 60_000, "under 60k gas per receipt");
    }

    function test_starved_release_batch_reverts() public {
        _emission(0);
        bytes32[] memory keys = new bytes32[](8);
        for (uint256 i; i < 8; ++i) keys[i] = _settle(C1, JP[i % 3], 100);
        vm.warp(vm.getBlockTimestamp() + 1 days);
        // Enough for the payouts and a single hook, not for eight items' hooks: must revert, not skip rewards.
        (bool ok, ) = address(s).call{gas: 1_000_000}(abi.encodeCall(s.releaseBatch, (keys)));
        require(!ok, "starved batch must revert");
        s.releaseBatch(keys);
    }

    /// @dev The invariant behind the gas guards: at any gas limit, a release batch either reverts or
    /// records every receipt's rewards. Fresh accounts everywhere make each hook as expensive as it gets.
    function test_release_batch_never_succeeds_without_its_rewards() public {
        Emission emission = _emission(10);
        uint256 n = 64;
        bytes32[] memory keys = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            uint256 consumerKey = 1_000 + i;
            address owner = address(uint160(0xF000 + i));
            _fundConsumer(owner, consumerKey);
            keys[i] = _settle(consumerKey, JP[i % 3], 100);
        }
        vm.warp(vm.getBlockTimestamp() + 1 days);
        uint64 b = emission.currentBlock();
        uint256 successes;
        for (uint256 limit = 3_000_000; limit <= 16_000_000; limit += 250_000) {
            uint256 snapshot = vm.snapshotState();
            (bool ok, ) = address(s).call{gas: limit}(abi.encodeCall(s.releaseBatch, (keys)));
            if (ok) {
                ++successes;
                require(emission.spendAt(b) == 100 * n, "a successful batch recorded every reward");
            }
            vm.revertToState(snapshot);
        }
        require(successes > 0, "some limit succeeds");
    }
}
