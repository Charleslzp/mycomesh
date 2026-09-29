// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV11 as V11} from "../contracts/MycoSettlementV11.sol";
import {MycoERC1967Proxy} from "../contracts/MycoUpgradeable.sol";
import {MockExactToken as Token, Vm} from "./TestSupport.sol";

contract JuryRegistryMockV11 {
    uint16 public constant threshold = 2;
    mapping(bytes32 => bytes32) public assignmentHash;
    mapping(bytes32 => mapping(address => bool)) public isVoteSigner;
    uint256 public releases;
    uint256 public frauds;
    bytes32 public lastCase;
    bool public failHooks;

    function requestJury(bytes32 caseId, address) external { lastCase = caseId; }
    function assign(bytes32 caseId, bytes32 assignment, address a, address b) external {
        assignmentHash[caseId] = assignment;
        isVoteSigner[caseId][a] = true;
        isVoteSigner[caseId][b] = true;
    }
    function setFailHooks(bool value) external { failHooks = value; }
    function recordRelease(address, address, uint256) external { require(!failHooks); ++releases; }
    function recordConfirmedFraud(address) external { require(!failHooks); ++frauds; }
}

contract MycoSettlementV11Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant KEY = 1; uint256 constant PSIGN = 2; uint256 constant RSIGN = 3; uint256 constant PROBE = 4;
    uint256 constant J1KEY = 81; uint256 constant J2KEY = 82;
    address constant CONSUMER = address(0xC0);
    address constant PROVIDER = address(0xB0);
    address constant RELAY = address(0xA0);
    address constant PENALTY = address(0x99);
    address constant ADMIN = address(0xAD);
    uint64 constant START = 30 days;

    Token token; JuryRegistryMockV11 registry; V11 s; V11 implementation;
    address key; address psigner; address rsigner; address probeKey; address j1; address j2;
    uint256 nonce;

    function _params() internal pure returns (V11.Params memory) {
        return V11.Params({
            disputeWindow: 1 days, arbitrationTimeout: 2 days, consumerWithdrawalDelay: 1 hours,
            reporterBond: 100, relayBps: 1000, holdbackBps: 1000, holdbackPeriod: 7 days,
            baseExposureCap: 50_000, exposureGrowthBps: 1000, maxExposureCap: 1_000_000,
            slashBps: 10_000, slashCap: 100_000, reporterBountyBps: 5000, probeVoidsPerDay: 2,
            penaltyRecipient: PENALTY
        });
    }

    function setUp() public {
        vm.warp(START);
        key = vm.addr(KEY); psigner = vm.addr(PSIGN); rsigner = vm.addr(RSIGN); probeKey = vm.addr(PROBE);
        j1 = vm.addr(J1KEY); j2 = vm.addr(J2KEY);
        token = new Token();
        registry = new JuryRegistryMockV11();
        implementation = new V11();
        MycoERC1967Proxy proxy = new MycoERC1967Proxy(
            address(implementation), abi.encodeCall(V11.initialize, (address(token), address(registry), ADMIN, _params()))
        );
        s = V11(address(proxy));
        token.mint(CONSUMER, 1_000_000);
        vm.prank(CONSUMER); token.approve(address(s), type(uint256).max);
        vm.prank(CONSUMER); s.deposit(500_000);
        vm.prank(CONSUMER); s.registerKey(key, 100_000, 0);
        vm.prank(CONSUMER); s.registerKey(probeKey, 100_000, 0);
        vm.prank(PROVIDER); s.authorizeProviderSigner(psigner);
        vm.prank(RELAY); s.authorizeRelaySigner(rsigner);
    }

    function _sig(uint256 privateKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, ss, v);
    }

    function _receipt(uint256 consumerKey, uint256 fee, uint256 maxFee) internal returns (V11.SignedReceipt memory r) {
        ++nonce;
        r.authorization = V11.PaymentAuthorization({
            requestId: bytes32(nonce), requestHash: keccak256(abi.encode("request", nonce)), key: vm.addr(consumerKey),
            providerSigner: psigner, relaySigner: rsigner, maxFee: maxFee,
            issuedAt: uint64(block.timestamp), executeBy: uint64(block.timestamp + 60), deadline: uint64(block.timestamp + 2 hours)
        });
        bytes32 authHash = s.authorizationStructHash(r.authorization);
        r.receipt = V11.UsageReceipt(authHash, s.dispatchStructHash(authHash), keccak256(abi.encode("response", nonce)), 10, 20, fee);
        r.keySignature = _sig(consumerKey, s.authorizationDigest(r.authorization));
        r.relaySignature = _sig(RSIGN, s.dispatchDigest(authHash));
        r.providerSignature = _sig(PSIGN, s.receiptDigest(r.receipt));
    }

    function _settle(uint256 consumerKey, uint256 fee) internal returns (bytes32 settlementKey) {
        V11.SignedReceipt memory r = _receipt(consumerKey, fee, fee);
        s.settleReceipt(r);
        settlementKey = s.settlementKeyFor(r.authorization.key, r.authorization.requestId);
    }

    function _assertSolvent() internal view {
        require(token.balanceOf(address(s)) == s.stableLiabilities(), "liabilities differ from balance");
    }

    // ---------------- upgradeability ----------------

    function test_implementation_is_not_usable_directly() public {
        vm.expectRevert();
        implementation.initialize(address(token), address(registry), ADMIN, _params());
        vm.expectRevert();
        implementation.deposit(1);
    }

    function test_only_admin_upgrades_and_state_survives() public {
        V11 next = new V11();
        vm.expectRevert();
        s.upgradeToAndCall(address(next), "");
        vm.prank(ADMIN);
        s.upgradeToAndCall(address(next), "");
        require(s.implementation() == address(next), "not upgraded");
        require(s.availableBalance(CONSUMER) == 500_000, "state lost across upgrade");
        vm.expectRevert();
        s.initialize(address(token), address(registry), ADMIN, _params());
    }

    function test_renouncing_upgrades_freezes_code_then_admin() public {
        V11 next = new V11();
        vm.expectRevert();
        s.renounceAdmin(); // not admin
        vm.prank(ADMIN);
        vm.expectRevert();
        s.renounceAdmin(); // upgrades must be frozen first
        vm.prank(ADMIN);
        s.renounceUpgrades();
        require(s.upgradesRenounced(), "not frozen");
        vm.prank(ADMIN);
        vm.expectRevert();
        s.upgradeToAndCall(address(next), "");
        vm.prank(ADMIN);
        s.renounceAdmin();
        require(s.admin() == address(0), "admin kept");
        require(s.availableBalance(CONSUMER) == 500_000, "state changed");
    }

    // ---------------- money flow ----------------

    function test_settle_release_splits_fee_with_holdback() public {
        bytes32 k = _settle(KEY, 10_000);
        require(s.availableBalance(CONSUMER) == 490_000, "consumer not charged");
        require(s.pendingExposure(PROVIDER) == 10_000, "exposure not tracked");
        vm.expectRevert();
        s.release(k);
        vm.warp(block.timestamp + 1 days);
        s.release(k);
        // relay 10%; provider gross 9000; holdback 10% of gross = 900.
        require(s.claimableBalance(RELAY) == 1_000, "relay share");
        require(s.claimableBalance(PROVIDER) == 8_100, "provider share");
        require(s.holdbackBalance(PROVIDER) == 900, "holdback");
        require(s.cleanVolume(PROVIDER) == 10_000 && registry.releases() == 1, "clean volume");
        _assertSolvent();
    }

    function test_holdback_matures_after_the_period() public {
        bytes32 k = _settle(KEY, 10_000);
        vm.warp(block.timestamp + 1 days);
        s.release(k);
        s.releaseHoldback(PROVIDER);
        require(s.holdbackBalance(PROVIDER) == 900, "holdback matured early");
        vm.warp(block.timestamp + 7 days);
        s.releaseHoldback(PROVIDER);
        require(s.holdbackBalance(PROVIDER) == 0 && s.claimableBalance(PROVIDER) == 9_000, "holdback not matured");
        vm.prank(PROVIDER);
        s.claim();
        require(token.balanceOf(PROVIDER) == 9_000, "claim");
        _assertSolvent();
    }

    function test_new_provider_exposure_cap_grows_only_with_clean_volume() public {
        _settle(KEY, 30_000);
        bytes32 second = _settle(KEY, 20_000);
        V11.SignedReceipt memory over = _receipt(KEY, 1, 1);
        vm.expectRevert();
        s.settleReceipt(over);
        vm.warp(block.timestamp + 1 days);
        s.release(second);
        // 50_000 base + 10% of 20_000 clean volume, minus 30_000 still pending.
        require(s.exposureCap(PROVIDER) == 52_000, "cap growth");
        _settle(KEY, 22_000);
        _assertSolvent();
    }

    function test_rejects_bad_fee_signatures_replay_and_empty_deposit() public {
        V11.SignedReceipt memory r = _receipt(KEY, 2_000, 1_000);
        vm.expectRevert();
        s.settleReceipt(r);
        r = _receipt(KEY, 1_000, 1_000);
        r.providerSignature = _sig(RSIGN, s.receiptDigest(r.receipt));
        vm.expectRevert();
        s.settleReceipt(r);
        r = _receipt(KEY, 1_000, 1_000);
        s.settleReceipt(r);
        vm.expectRevert();
        s.settleReceipt(r);
        vm.prank(CONSUMER); s.requestWithdrawal(499_000);
        vm.warp(block.timestamp + 1 hours);
        vm.prank(CONSUMER); s.withdraw();
        r = _receipt(KEY, 1_000, 1_000);
        vm.expectRevert();
        s.settleReceipt(r);
        _assertSolvent();
    }

    // ---------------- probes ----------------

    function _commitProbeKey() internal returns (uint256 index) {
        vm.prank(RELAY);
        index = s.commitProbeKeys(keccak256(abi.encode(probeKey)));
        vm.warp(block.timestamp + 1);
    }

    function test_relay_voids_committed_probes_and_provider_bears_cost() public {
        uint256 index = _commitProbeKey();
        bytes32 k = _settle(PROBE, 5_000);
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert();
        s.voidProbe(k, index, proof); // not the Relay
        vm.prank(RELAY);
        s.voidProbe(k, index, proof);
        require(uint8(s.settlementInfo(k).status) == uint8(V11.Status.Voided), "not voided");
        require(s.availableBalance(CONSUMER) == 500_000 && s.pendingExposure(PROVIDER) == 0, "probe not refunded");
        require(s.claimableBalance(PROVIDER) == 0 && s.cleanVolume(PROVIDER) == 0, "provider paid for a probe");
        _assertSolvent();
    }

    function test_probe_voiding_requires_prior_commitment_and_respects_daily_cap() public {
        bytes32 early = _settle(PROBE, 1_000);
        uint256 index = _commitProbeKey();
        bytes32[] memory proof = new bytes32[](0);
        vm.prank(RELAY);
        vm.expectRevert();
        s.voidProbe(early, index, proof); // committed after issuance
        bytes32 real = _settle(KEY, 1_000);
        vm.prank(RELAY);
        vm.expectRevert();
        s.voidProbe(real, index, proof); // not a committed probe key
        // Settle first: vm.prank applies to the next external call only.
        bytes32 first = _settle(PROBE, 1_000);
        vm.prank(RELAY); s.voidProbe(first, index, proof);
        bytes32 second = _settle(PROBE, 1_000);
        vm.prank(RELAY); s.voidProbe(second, index, proof);
        bytes32 third = _settle(PROBE, 1_000);
        vm.prank(RELAY);
        vm.expectRevert();
        s.voidProbe(third, index, proof); // daily cap of 2
        vm.warp(block.timestamp + 1 days);
        vm.prank(RELAY);
        vm.expectRevert();
        s.voidProbe(third, index, proof); // dispute window over
        _assertSolvent();
    }

    // ---------------- disputes ----------------

    function _votes(bytes32 k, bytes32 assignment, bool confirmed, bytes32 reportId)
        internal returns (V11.DisputeVotePermit[] memory permits)
    {
        permits = new V11.DisputeVotePermit[](2);
        uint256[2] memory judges = [J1KEY, J2KEY];
        bytes32 typehash = keccak256("DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)");
        for (uint256 i; i < 2; ++i) {
            uint64 deadline = uint64(block.timestamp + 1 hours);
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", s.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(typehash, k, assignment, confirmed, reportId, keccak256("decision"), uint256(0), deadline))));
            permits[i] = V11.DisputeVotePermit(assignment, confirmed, reportId, keccak256("decision"), 0, deadline, _sig(judges[i], digest));
        }
    }

    function _disputed(bytes32 k) internal returns (bytes32 reportId) {
        vm.prank(CONSUMER);
        s.openDispute(k, keccak256("evidence"));
        reportId = s.reportIdFor(k, CONSUMER, keccak256("evidence"));
        registry.assign(k, keccak256("assignment"), j1, j2);
    }

    function test_confirmed_fraud_refunds_consumer_and_penalizes_holdback() public {
        bytes32 earlier = _settle(KEY, 20_000);
        vm.warp(block.timestamp + 1 days);
        s.release(earlier); // provider now has 1_800 holdback
        bytes32 k = _settle(KEY, 10_000);
        bytes32 reportId = _disputed(k);
        s.voteDisputeBySig(k, _votes(k, keccak256("assignment"), true, reportId));
        require(uint8(s.settlementInfo(k).status) == uint8(V11.Status.Confirmed), "not confirmed");
        // The reporter bond comes from the wallet, not from the custodied deposit.
        require(s.availableBalance(CONSUMER) == 480_000, "consumer not refunded");
        // penalty = min(fee, cap, holdback) = 1_800; half to the reporter.
        require(s.holdbackBalance(PROVIDER) == 0 && s.disputeInfo(k).penalty == 1_800, "holdback penalty");
        require(s.claimableBalance(CONSUMER) == 900 && s.claimableBalance(PENALTY) == 900, "bounty split");
        require(s.cleanVolume(PROVIDER) == 0 && registry.frauds() == 1, "earned trust not reset");
        s.claimDisputeBond(k, reportId);
        require(s.claimableBalance(CONSUMER) == 1_000, "bond not returned");
        _assertSolvent();
    }

    function test_dismissed_dispute_pays_provider_and_forfeits_bond() public {
        bytes32 k = _settle(KEY, 10_000);
        _disputed(k);
        s.voteDisputeBySig(k, _votes(k, keccak256("assignment"), false, bytes32(0)));
        require(uint8(s.settlementInfo(k).status) == uint8(V11.Status.Dismissed), "not dismissed");
        require(s.claimableBalance(PROVIDER) == 8_100 && s.claimableBalance(PENALTY) == 100, "dismissal payouts");
        _assertSolvent();
    }

    function test_votes_from_unselected_or_conflicted_judges_are_rejected() public {
        bytes32 k = _settle(KEY, 10_000);
        bytes32 reportId = _disputed(k);
        V11.DisputeVotePermit[] memory permits = _votes(k, keccak256("other-assignment"), true, reportId);
        vm.expectRevert();
        s.voteDisputeBySig(k, permits);
        // A juror who is also a signer of the accused Provider is not independent.
        vm.prank(PROVIDER); s.authorizeProviderSigner(j1);
        permits = _votes(k, keccak256("assignment"), true, reportId);
        vm.expectRevert();
        s.voteDisputeBySig(k, permits);
    }

    function test_timeouts_refund_without_jury_and_release_with_silent_jury() public {
        bytes32 unassigned = _settle(KEY, 10_000);
        vm.prank(CONSUMER); s.openDispute(unassigned, keccak256("e1"));
        bytes32 silent = _settle(KEY, 10_000);
        _disputed(silent);
        vm.warp(block.timestamp + 3 days);
        s.resolveTimedOutDispute(unassigned);
        s.resolveTimedOutDispute(silent);
        require(uint8(s.settlementInfo(unassigned).status) == uint8(V11.Status.JuryUnavailable), "unassigned");
        require(uint8(s.settlementInfo(silent).status) == uint8(V11.Status.TimedOut), "silent");
        require(s.claimableBalance(PROVIDER) == 8_100, "silent jury releases");
        _assertSolvent();
    }

    function test_failing_registry_hooks_never_block_payouts() public {
        registry.setFailHooks(true);
        bytes32 k = _settle(KEY, 10_000);
        vm.warp(block.timestamp + 1 days);
        s.release(k);
        require(s.claimableBalance(PROVIDER) == 8_100, "release blocked by registry");
        _assertSolvent();
    }
}
