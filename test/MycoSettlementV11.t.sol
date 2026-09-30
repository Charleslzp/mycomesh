// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV11 as V11} from "../contracts/MycoSettlementV11.sol";
import {MycoSettlementBaseV11 as B} from "../contracts/MycoSettlementBaseV11.sol";
import {MycoSettlementDisputesV11 as D} from "../contracts/MycoSettlementDisputesV11.sol";
import {MycoERC1967Proxy} from "../contracts/MycoUpgradeable.sol";
import {MycoReleaseV11} from "../contracts/MycoReleaseV11.sol";
import {MockExactToken as Token, Vm} from "./TestSupport.sol";
import {ProbeLedgerV11, IMycoSettlementProbesV11} from "../contracts/ProbeLedgerV11.sol";

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
    uint256 public price = type(uint256).max; // the network price; by default the Consumer's cap binds
    function setPrice(uint256 value) external { price = value; }
    function priceAndRecord(address, uint64, uint256, uint256) external view returns (uint256) { return price; }
    function recordReleases(MycoReleaseV11[] calldata items, address) external {
        require(!failHooks);
        for (uint256 i; i < items.length; ++i) releases += items[i].count;
    }
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

    function _params() internal pure returns (B.Params memory) {
        return B.Params({
            disputeWindow: 1 days, arbitrationTimeout: 2 days, consumerWithdrawalDelay: 1 hours,
            reporterBond: 100, relayBps: 1000, holdbackBps: 1000, holdbackPeriod: 7 days,
            baseExposureCap: 50_000, exposureGrowthBps: 1000, maxExposureCap: 1_000_000,
            slashBps: 10_000, slashCap: 100_000, reporterBountyBps: 5000, probeVoidsPerDay: 2,
            penaltyRecipient: PENALTY
        });
    }

    address disputeModule;

    function setUp() public {
        disputeModule = address(new D());
        vm.warp(START);
        key = vm.addr(KEY); psigner = vm.addr(PSIGN); rsigner = vm.addr(RSIGN); probeKey = vm.addr(PROBE);
        j1 = vm.addr(J1KEY); j2 = vm.addr(J2KEY);
        token = new Token();
        registry = new JuryRegistryMockV11();
        implementation = new V11(disputeModule);
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

    function _receipt(uint256 consumerKey, uint256 fee, uint256 maxFee) internal returns (B.SignedReceipt memory r) {
        ++nonce;
        r.authorization = B.PaymentAuthorization({
            requestId: bytes32(nonce), requestHash: keccak256(abi.encode("request", nonce)), key: vm.addr(consumerKey),
            providerSigner: psigner, relaySigner: rsigner, maxFee: maxFee,
            issuedAt: uint64(block.timestamp), executeBy: uint64(block.timestamp + 60), deadline: uint64(block.timestamp + 2 hours)
        });
        bytes32 authHash = s.authorizationStructHash(r.authorization);
        r.receipt = B.UsageReceipt(authHash, s.dispatchStructHash(authHash), keccak256(abi.encode("response", nonce)), 10, 20, fee);
        r.keySignature = _sig(consumerKey, _digest(s.authorizationStructHash(r.authorization)));
        r.relaySignature = _sig(RSIGN, _digest(s.dispatchStructHash(authHash)));
        r.providerSignature = _sig(PSIGN, _digest(s.receiptStructHash(r.receipt)));
    }

    function _settle(uint256 consumerKey, uint256 fee) internal returns (bytes32 settlementKey) {
        B.SignedReceipt memory r = _receipt(consumerKey, fee, fee);
        _settleOne(r);
        settlementKey = _keyFor(r.authorization.key, r.authorization.requestId);
    }

    function _expectRevertSettle(B.SignedReceipt memory r) internal {
        B.SignedReceipt[] memory batch = new B.SignedReceipt[](1);
        batch[0] = r;
        vm.expectRevert();
        s.settleBatch(batch);
    }

    function _expectSettleRevert(uint256 consumerKey, uint256 fee) internal {
        B.SignedReceipt memory r = _receipt(consumerKey, fee, fee);
        vm.expectRevert();
        _settleOne(r);
    }

    function _assertSolvent() internal view {
        require(token.balanceOf(address(s)) == s.totalAvailable() + s.totalClaimable() + s.totalPendingFees()
            + s.totalHoldback() + s.totalReporterBonds(), "liabilities differ from balance");
    }

    // ---------------- upgradeability ----------------

    function test_implementation_is_not_usable_directly() public {
        vm.expectRevert();
        implementation.initialize(address(token), address(registry), ADMIN, _params());
        vm.expectRevert();
        implementation.deposit(1);
    }

    function test_only_admin_upgrades_and_state_survives() public {
        V11 next = new V11(disputeModule);
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
        V11 next = new V11(disputeModule);
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
        // relay 10%, treasury 10%; provider gross 8000; holdback 10% of gross = 800.
        require(s.claimableBalance(RELAY) == 1_000, "relay share");
        require(s.claimableBalance(PENALTY) == 1_000, "treasury share");
        require(s.claimableBalance(PROVIDER) == 7_200, "provider share");
        require(s.holdbackBalance(PROVIDER) == 800, "holdback");
        require(s.cleanVolume(PROVIDER) == 10_000 && registry.releases() == 1, "clean volume");
        _assertSolvent();
    }

    function test_holdback_matures_after_the_period() public {
        bytes32 k = _settle(KEY, 10_000);
        vm.warp(block.timestamp + 1 days);
        s.release(k);
        s.releaseHoldback(PROVIDER);
        require(s.holdbackBalance(PROVIDER) == 800, "holdback matured early");
        vm.warp(block.timestamp + 7 days);
        s.releaseHoldback(PROVIDER);
        require(s.holdbackBalance(PROVIDER) == 0 && s.claimableBalance(PROVIDER) == 8_000, "holdback not matured");
        vm.prank(PROVIDER);
        s.claim();
        require(token.balanceOf(PROVIDER) == 8_000, "claim");
        _assertSolvent();
    }

    function test_new_provider_exposure_cap_grows_only_with_clean_volume() public {
        _settle(KEY, 30_000);
        bytes32 second = _settle(KEY, 20_000);
        B.SignedReceipt memory over = _receipt(KEY, 1, 1);
        vm.expectRevert();
        _settleOne(over);
        vm.warp(block.timestamp + 1 days);
        s.release(second);
        // 50_000 base + 10% of 20_000 clean volume, minus 30_000 still pending.
        require(s.exposureCap(PROVIDER) == 52_000, "cap growth");
        _settle(KEY, 22_000);
        _assertSolvent();
    }

    function test_rejects_bad_fee_signatures_replay_and_empty_deposit() public {
        B.SignedReceipt memory r = _receipt(KEY, 2_000, 1_000);
        vm.expectRevert();
        _settleOne(r);
        r = _receipt(KEY, 1_000, 1_000);
        r.providerSignature = _sig(RSIGN, _digest(s.receiptStructHash(r.receipt)));
        vm.expectRevert();
        _settleOne(r);
        r = _receipt(KEY, 1_000, 1_000);
        _settleOne(r);
        vm.expectRevert();
        _settleOne(r);
        vm.prank(CONSUMER); s.requestWithdrawal(499_000);
        vm.warp(block.timestamp + 1 hours);
        vm.prank(CONSUMER); s.withdraw();
        r = _receipt(KEY, 1_000, 1_000);
        vm.expectRevert();
        _settleOne(r);
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
        require(uint8(D(address(s)).settlementInfo(k).status) == uint8(B.Status.Voided), "not voided");
        require(s.availableBalance(CONSUMER) == 500_000 && s.pendingExposure(PROVIDER) == 0, "probe not refunded");
        require(s.claimableBalance(PROVIDER) == 0 && s.cleanVolume(PROVIDER) == 0, "provider paid for a probe");
        _assertSolvent();
    }

    // ---------------- network price ----------------

    function test_fee_must_equal_the_network_price_capped_by_the_consumer() public {
        registry.setPrice(700);
        _expectRevertSettle(_receipt(KEY, 1_000, 1_000)); // overcharging the network price
        _expectRevertSettle(_receipt(KEY, 600, 1_000)); // undercutting is not allowed either: one price for all
        _settleOne(_receipt(KEY, 700, 1_000));
        _settleOne(_receipt(KEY, 500, 500)); // the Consumer's maxFee caps the price
        _assertSolvent();
    }

    // ---------------- multi-tenant key budgets ----------------

    function test_key_budget_caps_a_tenant_and_refunds_restore_it() public {
        address tenant = vm.addr(KEY);
        vm.expectRevert();
        s.setKeyBudget(tenant, 10_000); // only the key's owner
        vm.prank(CONSUMER);
        s.setKeyBudget(tenant, 10_000);
        _settle(KEY, 6_000);
        (uint128 limit, uint128 spent) = s.keyBudgets(tenant);
        require(limit == 10_000 && spent == 6_000, "budget not tracked");
        _expectSettleRevert(KEY, 5_000); // 6_000 + 5_000 > 10_000
        bytes32 k = _settle(KEY, 4_000);
        (, spent) = s.keyBudgets(tenant);
        require(spent == 10_000, "budget not exhausted");
        vm.prank(CONSUMER);
        D(address(s)).openDispute(k, keccak256("evidence"));
        vm.warp(block.timestamp + 4 days);
        D(address(s)).resolveTimedOutDispute(k); // no jury was assigned: refunded
        (, spent) = s.keyBudgets(tenant);
        require(spent == 6_000, "refund did not restore the budget");
        vm.prank(CONSUMER);
        s.setKeyBudget(tenant, 20_000); // topping a tenant up
        _settle(KEY, 5_000);
        _assertSolvent();
    }

    function test_unbudgeted_keys_are_unlimited_and_untracked() public {
        _settle(KEY, 40_000);
        (uint128 limit, uint128 spent) = s.keyBudgets(vm.addr(KEY));
        require(limit == 0 && spent == 0, "unbudgeted key tracked");
    }

    // ---------------- upgrade sunset ----------------

    function test_upgrade_sunset_only_moves_earlier_and_then_freezes_code() public {
        V11 next = new V11(disputeModule);
        vm.expectRevert();
        s.setUpgradeSunset(uint64(block.timestamp + 30 days)); // not admin
        vm.prank(ADMIN);
        s.setUpgradeSunset(uint64(block.timestamp + 30 days));
        vm.prank(ADMIN);
        vm.expectRevert();
        s.setUpgradeSunset(uint64(block.timestamp + 60 days)); // may never be pushed back
        vm.prank(ADMIN);
        s.setUpgradeSunset(uint64(block.timestamp + 10 days));
        require(s.upgradeSunset() == block.timestamp + 10 days, "sunset");
        vm.prank(ADMIN);
        s.upgradeToAndCall(address(next), ""); // still allowed before the sunset
        V11 later = new V11(disputeModule); // created first: prank and expectRevert apply to the next call
        vm.warp(block.timestamp + 10 days);
        vm.prank(ADMIN);
        vm.expectRevert();
        s.upgradeToAndCall(address(later), "");
        require(s.availableBalance(CONSUMER) == 500_000, "state lost");
    }

    // ---------------- probe ledger ----------------

    function test_probe_ledger_accepts_one_verdict_from_the_voiding_relay_only() public {
        ProbeLedgerV11 ledger = new ProbeLedgerV11(IMycoSettlementProbesV11(address(s)));
        uint256 index = _commitProbeKey();
        bytes32 k = _settle(PROBE, 5_000);
        vm.prank(RELAY);
        vm.expectRevert();
        ledger.record(k, keccak256("evidence"), 1); // not voided yet
        vm.prank(RELAY);
        s.voidProbe(k, index, new bytes32[](0));
        vm.expectRevert();
        ledger.record(k, keccak256("evidence"), 1); // not the dispatching Relay
        vm.prank(RELAY);
        vm.expectRevert();
        ledger.record(k, keccak256("evidence"), 5); // no such verdict (1-2 basic, 3-4 capability)
        vm.prank(RELAY);
        ledger.record(k, keccak256("evidence"), 2);
        require(ledger.verdictOf(k) == 2, "verdict not recorded");
        vm.prank(RELAY);
        vm.expectRevert();
        ledger.record(k, keccak256("evidence"), 1); // once only
        bytes32 paid = _settle(KEY, 1_000);
        vm.prank(RELAY);
        vm.expectRevert();
        ledger.record(paid, keccak256("evidence"), 2); // a paid request is not a probe
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
        internal returns (B.DisputeVotePermit[] memory permits)
    {
        permits = new B.DisputeVotePermit[](2);
        uint256[2] memory judges = [J1KEY, J2KEY];
        bytes32 typehash = keccak256("DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)");
        for (uint256 i; i < 2; ++i) {
            uint64 deadline = uint64(block.timestamp + 1 hours);
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", s.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(typehash, k, assignment, confirmed, reportId, keccak256("decision"), uint256(0), deadline))));
            permits[i] = B.DisputeVotePermit(assignment, confirmed, reportId, keccak256("decision"), 0, deadline, _sig(judges[i], digest));
        }
    }

    function _disputed(bytes32 k) internal returns (bytes32 reportId) {
        vm.prank(CONSUMER);
        D(address(s)).openDispute(k, keccak256("evidence"));
        reportId = _reportFor(k, CONSUMER, keccak256("evidence"));
        registry.assign(k, keccak256("assignment"), j1, j2);
    }

    function test_confirmed_fraud_refunds_consumer_and_penalizes_holdback() public {
        bytes32 earlier = _settle(KEY, 20_000);
        vm.warp(block.timestamp + 1 days);
        s.release(earlier); // provider now has 1_600 holdback (gross 16_000 after Relay and treasury)
        bytes32 k = _settle(KEY, 10_000);
        bytes32 reportId = _disputed(k);
        D(address(s)).voteDisputeBySig(k, _votes(k, keccak256("assignment"), true, reportId));
        require(uint8(D(address(s)).settlementInfo(k).status) == uint8(B.Status.Confirmed), "not confirmed");
        // The reporter bond comes from the wallet, not from the custodied deposit.
        require(s.availableBalance(CONSUMER) == 480_000, "consumer not refunded");
        // penalty = min(fee, cap, holdback) = 1_600; half to the reporter.
        require(s.holdbackBalance(PROVIDER) == 0 && D(address(s)).disputeInfo(k).penalty == 1_600, "holdback penalty");
        // The penalty recipient is the treasury: 800 of penalty plus 2_000 treasury share of the earlier release.
        require(s.claimableBalance(CONSUMER) == 800 && s.claimableBalance(PENALTY) == 2_800, "bounty split");
        require(s.cleanVolume(PROVIDER) == 0 && registry.frauds() == 1, "earned trust not reset");
        D(address(s)).claimDisputeBond(k, reportId);
        require(s.claimableBalance(CONSUMER) == 900, "bond not returned");
        _assertSolvent();
    }

    function test_dismissed_dispute_pays_provider_and_forfeits_bond() public {
        bytes32 k = _settle(KEY, 10_000);
        _disputed(k);
        D(address(s)).voteDisputeBySig(k, _votes(k, keccak256("assignment"), false, bytes32(0)));
        require(uint8(D(address(s)).settlementInfo(k).status) == uint8(B.Status.Dismissed), "not dismissed");
        require(s.claimableBalance(PROVIDER) == 7_200 && s.claimableBalance(PENALTY) == 1_100, "dismissal payouts");
        _assertSolvent();
    }

    function test_votes_from_unselected_or_conflicted_judges_are_rejected() public {
        bytes32 k = _settle(KEY, 10_000);
        bytes32 reportId = _disputed(k);
        B.DisputeVotePermit[] memory permits = _votes(k, keccak256("other-assignment"), true, reportId);
        vm.expectRevert();
        D(address(s)).voteDisputeBySig(k, permits);
        // A juror who is also a signer of the accused Provider is not independent.
        vm.prank(PROVIDER); s.authorizeProviderSigner(j1);
        permits = _votes(k, keccak256("assignment"), true, reportId);
        vm.expectRevert();
        D(address(s)).voteDisputeBySig(k, permits);
    }

    function test_timeouts_refund_without_jury_and_release_with_silent_jury() public {
        bytes32 unassigned = _settle(KEY, 10_000);
        vm.prank(CONSUMER); D(address(s)).openDispute(unassigned, keccak256("e1"));
        bytes32 silent = _settle(KEY, 10_000);
        _disputed(silent);
        vm.warp(block.timestamp + 3 days);
        D(address(s)).resolveTimedOutDispute(unassigned);
        D(address(s)).resolveTimedOutDispute(silent);
        require(uint8(D(address(s)).settlementInfo(unassigned).status) == uint8(B.Status.JuryUnavailable), "unassigned");
        require(uint8(D(address(s)).settlementInfo(silent).status) == uint8(B.Status.TimedOut), "silent");
        require(s.claimableBalance(PROVIDER) == 7_200, "silent jury releases");
        _assertSolvent();
    }

    function test_failing_registry_hooks_never_block_payouts() public {
        registry.setFailHooks(true);
        bytes32 k = _settle(KEY, 10_000);
        vm.warp(block.timestamp + 1 days);
        s.release(k);
        require(s.claimableBalance(PROVIDER) == 7_200, "release blocked by registry");
        _assertSolvent();
    }
}
