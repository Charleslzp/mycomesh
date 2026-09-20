// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV9} from "../contracts/MycoSettlementV9.sol";

interface VmV9 {
    function addr(uint256 privateKey) external returns (address);
    function expectRevert() external;
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function chainId(uint256 chainId) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

/// @dev Adversarial test token, local only. Never deployed by this test suite.
contract MockExactTokenV9 {
    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public feeOnTransfer;
    bool public extraSenderDebit;
    bool public blocked;
    bool public returnFalse;
    address public hookTarget;
    bytes public hookData;
    bool public hookSucceeded;

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        require(!blocked, "token blocked");
        return balances[account];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function setModes(bool fee, bool debit, bool blocked_, bool false_) external {
        feeOnTransfer = fee;
        extraSenderDebit = debit;
        blocked = blocked_;
        returnFalse = false_;
    }

    function setHook(address target, bytes calldata data) external {
        hookTarget = target;
        hookData = data;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return !returnFalse;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        if (allowance[from][msg.sender] != type(uint256).max) allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return !returnFalse;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(!blocked, "token blocked");
        uint256 debit = amount + (extraSenderDebit && amount > 0 ? 1 : 0);
        uint256 credit = amount - (feeOnTransfer && amount > 0 ? 1 : 0);
        require(balances[from] >= debit, "balance");
        balances[from] -= debit;
        balances[to] += credit;
        if (hookTarget != address(0)) (hookSucceeded,) = hookTarget.call(hookData);
    }
}

contract MycoSettlementV9Test {
    // Test-only deterministic signing fixtures, unrelated to workspace wallets.
    uint256 internal constant KEY = 0xC001;
    uint256 internal constant PROVIDER_SIGNER_KEY = 0xC002;
    uint256 internal constant RELAY_SIGNER_KEY = 0xC003;
    bytes32 internal constant CHANNEL = keccak256("v9-local-test");
    bytes32 internal constant EVIDENCE = keccak256("independently verifiable evidence");
    bytes32 internal constant DECISION = keccak256("independent reasons");
    VmV9 internal constant vm = VmV9(address(uint160(uint256(keccak256("hevm cheat code")))));

    MockExactTokenV9 internal usdc;
    MockExactTokenV9 internal reward;
    MycoSettlementV9 internal settlement;
    address internal consumer = address(0x2001);
    address internal provider = address(0x2002);
    address internal relay = address(0x2003);
    address internal pool = address(0x2004);
    address internal treasury = address(0x2005);
    address internal reporter = address(0x2006);
    address internal penalty = address(0x2007);
    address internal secondReporter = address(0x2008);
    address internal judgeA = address(0x3001);
    address internal judgeB = address(0x3002);
    address internal judgeC = address(0x3003);
    address internal key;
    address internal providerSigner;
    address internal relaySigner;
    uint256 internal nonce;

    function setUp() public {
        vm.warp(1_000);
        key = vm.addr(KEY);
        providerSigner = vm.addr(PROVIDER_SIGNER_KEY);
        relaySigner = vm.addr(RELAY_SIGNER_KEY);
        usdc = new MockExactTokenV9();
        reward = new MockExactTokenV9();
        settlement = _deploy(_config(), _policy(), address(reward), _judges(), 2);
        _initialize(settlement);
    }

    function _deploy(
        MycoSettlementV9.ChannelConfig memory config,
        MycoSettlementV9.DisputePolicy memory policy,
        address rewardAddress,
        address[] memory judges,
        uint16 threshold
    ) internal returns (MycoSettlementV9) {
        return new MycoSettlementV9(
            address(usdc), rewardAddress, treasury, address(this), CHANNEL, config, policy, judges, threshold
        );
    }

    function _initialize(MycoSettlementV9 target) internal {
        usdc.mint(consumer, 100_000);
        vm.prank(consumer);
        usdc.approve(address(target), type(uint256).max);
        vm.prank(consumer);
        target.deposit(100_000);
        vm.prank(consumer);
        target.registerKey(key, 50_000, 0);
        usdc.mint(provider, 50_000);
        vm.prank(provider);
        usdc.approve(address(target), type(uint256).max);
        vm.prank(provider);
        target.depositStake(50_000);
        vm.prank(provider);
        target.authorizeProviderSigner(providerSigner);
        _fundReporter(reporter, target);
        _fundReporter(secondReporter, target);
        reward.mint(address(this), 30 ether);
        reward.approve(address(target), type(uint256).max);
    }

    function _fundReporter(address account, MycoSettlementV9 target) internal {
        usdc.mint(account, 20_000);
        vm.prank(account);
        usdc.approve(address(target), type(uint256).max);
    }

    function _config() internal pure returns (MycoSettlementV9.ChannelConfig memory) {
        return MycoSettlementV9.ChannelConfig(1_000, 4_000, 2_000, 8_500, 300, 200, 1_000, true);
    }

    function _policy() internal view returns (MycoSettlementV9.DisputePolicy memory) {
        return MycoSettlementV9.DisputePolicy({
            disputeWindow: 100,
            arbitrationTimeout: 200,
            consumerWithdrawalDelay: 30,
            reporterBond: 1_000,
            slashBps: 5_000,
            slashCap: 2_000,
            reporterBountyBps: 5_000,
            stableBountyCap: 600,
            tokenReward: 10 ether,
            tokenRewardCap: 30 ether,
            tokenMinimumExposure: 1_000,
            tokenMinimumPenalty: 100,
            bondPenaltyRecipient: penalty
        });
    }

    function _judges() internal view returns (address[] memory result) {
        result = new address[](3);
        result[0] = judgeA;
        result[1] = judgeB;
        result[2] = judgeC;
    }

    function _input() internal returns (MycoSettlementV9.SignedReceipt memory result) {
        ++nonce;
        result.authorization = MycoSettlementV9.PaymentAuthorization({
            requestId: keccak256(abi.encode("request", nonce)),
            requestHash: keccak256(abi.encode("input", nonce)),
            key: key,
            relay: relay,
            relaySigner: relaySigner,
            channel: CHANNEL,
            pricingVersion: 1,
            pricingHash: settlement.channelPricingHash(CHANNEL, 1),
            maxFee: 50_000,
            issuedAt: uint64(block.timestamp),
            deadline: uint64(block.timestamp + 1_000)
        });
        result.receipt = MycoSettlementV9.UsageReceipt({
            authorizationHash: bytes32(0),
            responseHash: keccak256(abi.encode("response", nonce)),
            provider: provider,
            providerSigner: providerSigner,
            relay: relay,
            pool: pool,
            inputTokens: 1_000,
            outputTokens: 500,
            actualFee: 3_000
        });
        return _resign(result);
    }

    function _resign(MycoSettlementV9.SignedReceipt memory result)
        internal
        returns (MycoSettlementV9.SignedReceipt memory)
    {
        result.receipt.authorizationHash = settlement.authorizationStructHash(result.authorization);
        result.keySignature = _sign(KEY, settlement.authorizationDigest(result.authorization));
        bytes32 digest = settlement.receiptDigest(result.receipt);
        result.providerSignature = _sign(PROVIDER_SIGNER_KEY, digest);
        result.relaySignature = _sign(RELAY_SIGNER_KEY, digest);
        return result;
    }

    function _sign(uint256 signingKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _settle() internal returns (bytes32 id) {
        MycoSettlementV9.SignedReceipt memory input = _input();
        settlement.settleSignedReceipt(input);
        return settlement.settlementKeyFor(consumer, key, input.authorization.requestId);
    }

    function testThreeHourAuthorizationCanSettleAfterTwoHours() public {
        require(settlement.MAX_AUTHORIZATION_TTL() == 3 hours, "wrong ttl");
        MycoSettlementV9.SignedReceipt memory input = _input();
        input.authorization.deadline = uint64(block.timestamp + 3 hours);
        input = _resign(input);
        vm.warp(block.timestamp + 2 hours);
        settlement.settleSignedReceipt(input);
        bytes32 id = settlement.settlementKeyFor(consumer, key, input.authorization.requestId);
        require(settlement.settlementInfo(id).grossFee == 3_000, "long authorization did not settle");
    }

    function testAuthorizationOverThreeHoursStillReverts() public {
        MycoSettlementV9.SignedReceipt memory input = _input();
        input.authorization.deadline = uint64(block.timestamp + 3 hours + 1);
        input = _resign(input);
        vm.expectRevert(bytes("authorization ttl"));
        settlement.settleSignedReceipt(input);
    }

    function _open(bytes32 id) internal returns (bytes32 reportId) {
        vm.prank(reporter);
        settlement.openDispute(id, EVIDENCE);
        return settlement.reportIdFor(id, reporter, EVIDENCE);
    }

    function _vote(bytes32 id, address judge, bool confirmed, bytes32 reportId) internal {
        vm.prank(judge);
        settlement.voteDispute(id, confirmed, reportId, DECISION);
    }

    function _confirm(bytes32 id, bytes32 reportId) internal {
        vm.warp(settlement.settlementInfo(id).releaseAt);
        _vote(id, judgeA, true, reportId);
        _vote(id, judgeB, true, reportId);
    }

    function _assertSolvent() internal view {
        require(usdc.balanceOf(address(settlement)) == settlement.stableLiabilities(), "stable accounting");
        require(settlement.lockedStake(provider) <= settlement.providerStake(provider), "stake undercollateralized");
        if (address(settlement.rewardToken()) != address(0)) {
            require(
                reward.balanceOf(address(settlement)) == settlement.rewardReserve() + settlement.totalTokenClaimable(),
                "reward accounting"
            );
        }
    }

    function testEscrowLocksFullFeeAndPreventsPrematurePayoutOrStakeWithdrawal() public {
        bytes32 id = _settle();
        require(settlement.availableBalance(consumer) == 97_000, "consumer debit");
        require(settlement.totalPendingFees() == 3_000, "pending fee");
        require(settlement.lockedStake(provider) == 3_000, "stake lock");
        require(settlement.totalClaimable() == 0, "premature credit");
        vm.expectRevert(bytes("release pending"));
        settlement.release(id);
        vm.prank(provider);
        vm.expectRevert(bytes("no claimable balance"));
        settlement.claim();
        vm.prank(provider);
        vm.expectRevert(bytes("stake encumbered"));
        settlement.withdrawStake(47_001);
        vm.prank(provider);
        settlement.withdrawStake(47_000);
        require(settlement.providerStake(provider) == 3_000, "unlocked withdrawal");
        _assertSolvent();
    }

    function testPermissionlessReleaseSplitsOnceAtDeadline() public {
        bytes32 id = _settle();
        vm.warp(settlement.settlementInfo(id).releaseAt);
        settlement.release(id);
        require(settlement.claimableBalance(provider) == 2_550, "provider share");
        require(settlement.claimableBalance(relay) == 90, "relay share");
        require(settlement.claimableBalance(pool) == 60, "pool share");
        require(settlement.claimableBalance(treasury) == 300, "treasury share");
        require(settlement.totalPendingFees() == 0 && settlement.lockedStake(provider) == 0, "not released");
        vm.expectRevert(bytes("not pending"));
        settlement.release(id);
        vm.prank(provider);
        settlement.claim();
        require(usdc.balanceOf(provider) == 2_550, "pull payout");
        _assertSolvent();
    }

    function testConfirmedFraudRefundsFullFeeAndBountyOnlyUsesCappedStakeSlash() public {
        settlement.fundTokenRewards(30 ether);
        bytes32 id = _settle();
        bytes32 reportId = _open(id);
        _confirm(id, reportId);
        require(settlement.availableBalance(consumer) == 100_000, "full refund missing");
        require(settlement.claimableBalance(provider) == 0 && settlement.claimableBalance(relay) == 0, "fraud paid");
        require(settlement.providerStake(provider) == 48_500, "slash");
        require(settlement.claimableBalance(reporter) == 600, "bounty cap");
        require(settlement.claimableBalance(penalty) == 900, "non-returned slash");
        require(settlement.tokenClaimableBalance(reporter) == 10 ether, "token reward");
        require(settlement.totalReporterBonds() == 1_000, "bond silently spent");
        settlement.claimDisputeBond(id, reportId);
        require(settlement.claimableBalance(reporter) == 1_600, "bond return");
        vm.prank(reporter);
        settlement.claimTokenReward();
        require(reward.balanceOf(reporter) == 10 ether, "token pull");
        _assertSolvent();
    }

    function testJunkFirstReportCannotCensorEvidenceOrStealBounty() public {
        settlement.fundTokenRewards(30 ether);
        bytes32 id = _settle();
        bytes32 junkReport = _open(id);
        uint256 deadline = settlement.disputeInfo(id).resolveAt;
        vm.warp(settlement.settlementInfo(id).releaseAt - 1);
        // Even a copied commitment cannot censor the other report's authorship.
        vm.prank(secondReporter);
        settlement.submitEvidence(id, EVIDENCE);
        bytes32 realReport = settlement.reportIdFor(id, secondReporter, EVIDENCE);
        require(settlement.disputeInfo(id).reportCount == 2, "second report excluded");
        require(settlement.disputeInfo(id).resolveAt == deadline, "late report extended deadline");
        vm.expectRevert(bytes("evidence window open"));
        _vote(id, judgeA, false, bytes32(0));
        _confirm(id, realReport);
        require(settlement.claimableBalance(reporter) == 0, "junk reporter stole bounty");
        require(settlement.tokenClaimableBalance(reporter) == 0, "junk reporter stole token");
        require(settlement.claimableBalance(secondReporter) == 600, "valid reporter not rewarded");
        require(settlement.tokenClaimableBalance(secondReporter) == 10 ether, "wrong reward recipient");
        settlement.claimDisputeBond(id, realReport);
        settlement.claimDisputeBond(id, junkReport);
        require(settlement.claimableBalance(reporter) == 1_000, "return-only junk bond");
        _assertSolvent();
    }

    function testDismissalWaitsFullWindowAndPenalizesAllBonds() public {
        bytes32 id = _settle();
        bytes32 reportId = _open(id);
        vm.prank(secondReporter);
        settlement.submitEvidence(id, keccak256("second allegation"));
        vm.expectRevert(bytes("evidence window open"));
        _vote(id, judgeA, false, bytes32(0));
        vm.warp(settlement.settlementInfo(id).releaseAt);
        _vote(id, judgeA, false, bytes32(0));
        _vote(id, judgeB, false, bytes32(0));
        require(settlement.settlementInfo(id).status == MycoSettlementV9.Status.Dismissed, "not dismissed");
        require(settlement.claimableBalance(penalty) == 2_000, "bond penalty recipient");
        require(settlement.claimableBalance(provider) == 2_550, "honest earnings withheld");
        require(settlement.providerStake(provider) == 50_000, "honest stake slashed");
        require(settlement.totalReporterBonds() == 0, "bond liabilities linger");
        vm.expectRevert(bytes("bond not refundable"));
        settlement.claimDisputeBond(id, reportId);
        _assertSolvent();
    }

    function testTimeoutHasFixedDeadlineReturnsBondsAndDoesNotPunish() public {
        bytes32 id = _settle();
        bytes32 reportId = _open(id);
        vm.expectRevert(bytes("adjudication pending"));
        settlement.resolveTimedOutDispute(id);
        vm.warp(settlement.disputeInfo(id).resolveAt);
        vm.expectRevert(bytes("adjudication expired"));
        _vote(id, judgeA, true, reportId);
        settlement.resolveTimedOutDispute(id);
        settlement.claimDisputeBond(id, reportId);
        require(settlement.settlementInfo(id).status == MycoSettlementV9.Status.TimedOut, "timeout status");
        require(settlement.claimableBalance(reporter) == 1_000, "bond not returned");
        require(settlement.providerStake(provider) == 50_000, "timeout punished provider");
        require(settlement.tokenClaimableBalance(reporter) == 0, "timeout token reward");
        require(settlement.claimableBalance(provider) == 2_550, "timeout earnings");
        _assertSolvent();
    }

    function testAllTerminalActionsCannotRepeat() public {
        bytes32 id = _settle();
        bytes32 reportId = _open(id);
        _confirm(id, reportId);
        settlement.claimDisputeBond(id, reportId);
        vm.expectRevert(bytes("bond already returned"));
        settlement.claimDisputeBond(id, reportId);
        vm.expectRevert(bytes("not pending"));
        settlement.openDispute(id, keccak256("again"));
        vm.expectRevert(bytes("not pending"));
        settlement.release(id);
        vm.expectRevert(bytes("not disputed"));
        settlement.resolveTimedOutDispute(id);
        vm.expectRevert(bytes("not disputed"));
        _vote(id, judgeC, true, reportId);
        vm.expectRevert(bytes("not disputed"));
        settlement.submitEvidence(id, keccak256("again"));
        _assertSolvent();
    }

    function testVotesMustAgreeOnExactReportAndCannotBeChanged() public {
        bytes32 id = _settle();
        bytes32 firstReport = _open(id);
        bytes32 otherEvidence = keccak256("other");
        vm.prank(secondReporter);
        settlement.submitEvidence(id, otherEvidence);
        bytes32 secondReport = settlement.reportIdFor(id, secondReporter, otherEvidence);
        vm.warp(settlement.settlementInfo(id).releaseAt);
        _vote(id, judgeA, true, firstReport);
        _vote(id, judgeB, true, secondReport);
        require(settlement.settlementInfo(id).status == MycoSettlementV9.Status.Disputed, "mixed report quorum");
        vm.expectRevert(bytes("already voted"));
        _vote(id, judgeA, false, bytes32(0));
        _vote(id, judgeC, true, secondReport);
        require(settlement.disputeInfo(id).winningReportId == secondReport, "wrong winner");
        _assertSolvent();
    }

    function testSplitReportVotesCannotInventQuorumAndRemainTimeoutLive() public {
        bytes32 id = _settle();
        bytes32 first = _open(id);
        vm.prank(secondReporter);
        settlement.submitEvidence(id, keccak256("second"));
        address thirdReporter = address(0x2009);
        _fundReporter(thirdReporter, settlement);
        vm.prank(thirdReporter);
        settlement.submitEvidence(id, keccak256("third"));
        bytes32 second = settlement.reportIdFor(id, secondReporter, keccak256("second"));
        bytes32 third = settlement.reportIdFor(id, thirdReporter, keccak256("third"));
        vm.warp(settlement.settlementInfo(id).releaseAt);
        _vote(id, judgeA, true, first);
        _vote(id, judgeB, true, second);
        _vote(id, judgeC, true, third);
        require(settlement.settlementInfo(id).status == MycoSettlementV9.Status.Disputed, "invented split quorum");
        vm.warp(settlement.disputeInfo(id).resolveAt);
        settlement.resolveTimedOutDispute(id);
        settlement.claimDisputeBond(id, first);
        settlement.claimDisputeBond(id, second);
        settlement.claimDisputeBond(id, third);
        require(settlement.totalReporterBonds() == 0, "split vote bonds locked");
        require(settlement.totalRewardAwarded() == 0, "split vote paid bounty");
        _assertSolvent();
    }

    function testAbsoluteSlashCapCannotConsumeRefundOrUnrelatedStake() public {
        MycoSettlementV9.SignedReceipt memory input = _input();
        input.receipt.inputTokens = 10_000;
        input.receipt.outputTokens = 0;
        input.receipt.actualFee = 10_000;
        input = _resign(input);
        settlement.settleSignedReceipt(input);
        bytes32 id = settlement.settlementKeyFor(consumer, key, input.authorization.requestId);
        bytes32 reportId = _open(id);
        _confirm(id, reportId);
        require(settlement.disputeInfo(id).slashAmount == 2_000, "absolute slash cap");
        require(settlement.providerStake(provider) == 48_000, "over-slashing");
        require(settlement.availableBalance(consumer) == 100_000, "bounty consumed refund");
        require(settlement.claimableBalance(reporter) == 600, "absolute bounty cap");
        _assertSolvent();
    }

    function testReporterJudgesSelfReportAndMissingEvidenceRejected() public {
        bytes32 id = _settle();
        vm.prank(judgeA);
        vm.expectRevert(bytes("judge cannot report"));
        settlement.openDispute(id, EVIDENCE);
        vm.prank(provider);
        vm.expectRevert(bytes("provider self report"));
        settlement.openDispute(id, EVIDENCE);
        vm.prank(providerSigner);
        vm.expectRevert(bytes("provider self report"));
        settlement.openDispute(id, EVIDENCE);
        vm.prank(reporter);
        vm.expectRevert(bytes("empty evidence"));
        settlement.openDispute(id, bytes32(0));
        _open(id);
        vm.prank(reporter);
        vm.expectRevert(bytes("reporter already submitted"));
        settlement.submitEvidence(id, keccak256("changed report"));
        vm.warp(settlement.settlementInfo(id).releaseAt);
        vm.expectRevert(bytes("not independent judge"));
        _vote(id, reporter, false, bytes32(0));
    }

    function testParticipantJudgeExcludedAndAdmissionRequiresQuorum() public {
        MycoSettlementV9.SignedReceipt memory input = _input();
        input.authorization.relay = judgeA;
        input.receipt.relay = judgeA;
        input = _resign(input);
        settlement.settleSignedReceipt(input);
        bytes32 id = settlement.settlementKeyFor(consumer, key, input.authorization.requestId);
        bytes32 reportId = _open(id);
        vm.warp(settlement.settlementInfo(id).releaseAt);
        vm.expectRevert(bytes("not independent judge"));
        _vote(id, judgeA, true, reportId);
        _vote(id, judgeB, true, reportId);
        _vote(id, judgeC, true, reportId);

        input = _input();
        input.authorization.relay = judgeA;
        input.receipt.relay = judgeA;
        input.receipt.pool = judgeB;
        input = _resign(input);
        vm.expectRevert(bytes("insufficient independent judges"));
        settlement.settleSignedReceipt(input);
        _assertSolvent();
    }

    function testEvidenceWindowBoundaryAndUnknownVotes() public {
        bytes32 undisputed = _settle();
        bytes32 disputed = _settle();
        _open(disputed);
        vm.warp(settlement.settlementInfo(undisputed).releaseAt);
        vm.prank(reporter);
        vm.expectRevert(bytes("dispute window closed"));
        settlement.openDispute(undisputed, EVIDENCE);
        vm.prank(secondReporter);
        vm.expectRevert(bytes("dispute window closed"));
        settlement.submitEvidence(disputed, EVIDENCE);
        vm.expectRevert(bytes("unknown report"));
        _vote(disputed, judgeA, true, keccak256("unknown"));
        vm.expectRevert(bytes("unexpected report"));
        _vote(disputed, judgeA, false, keccak256("unknown"));
        vm.prank(judgeA);
        vm.expectRevert(bytes("empty decision"));
        settlement.voteDispute(disputed, false, bytes32(0), bytes32(0));
        settlement.release(undisputed);
        _assertSolvent();
    }

    function testMultiplePendingReceiptsKeepTheirOwnStakeExposure() public {
        bytes32 first = _settle();
        bytes32 second = _settle();
        require(settlement.lockedStake(provider) == 6_000, "aggregate exposure");
        vm.prank(provider);
        settlement.withdrawStake(44_000);
        bytes32 reportId = _open(first);
        _confirm(first, reportId);
        require(settlement.providerStake(provider) == 4_500, "slash first exposure");
        require(settlement.lockedStake(provider) == 3_000, "second exposure lost");
        vm.prank(provider);
        vm.expectRevert(bytes("stake encumbered"));
        settlement.withdrawStake(1_501);
        settlement.release(second);
        require(settlement.lockedStake(provider) == 0, "second not released");
        _assertSolvent();
    }

    function testInsufficientStakeAndRevokedSignerRejected() public {
        MycoSettlementV9.SignedReceipt memory input = _input();
        vm.prank(provider);
        settlement.withdrawStake(49_000);
        vm.expectRevert(bytes("insufficient unlocked stake"));
        settlement.settleSignedReceipt(input);
        vm.prank(provider);
        settlement.depositStake(49_000);
        vm.prank(provider);
        settlement.revokeProviderSigner(providerSigner);
        vm.expectRevert(bytes("provider signer unauthorized"));
        settlement.settleSignedReceipt(input);
        _assertSolvent();
    }

    function testReplayTamperedSignatureFeeAndBatchRollback() public {
        MycoSettlementV9.SignedReceipt memory input = _input();
        settlement.settleSignedReceipt(input);
        vm.expectRevert(bytes("request settled"));
        settlement.settleSignedReceipt(input);
        input = _input();
        input.authorization.requestHash = keccak256("tampered");
        vm.expectRevert(bytes("authorization hash"));
        settlement.settleSignedReceipt(input);
        input = _input();
        input.receipt.actualFee = 1;
        input = _resign(input);
        vm.expectRevert(bytes("fee mismatch"));
        settlement.settleSignedReceipt(input);

        MycoSettlementV9.SignedReceipt[] memory inputs = new MycoSettlementV9.SignedReceipt[](2);
        inputs[0] = _input();
        inputs[1] = inputs[0];
        vm.expectRevert(bytes("request settled"));
        settlement.settleSignedBatch(inputs);
        require(
            !settlement.settled(settlement.settlementKeyFor(consumer, key, inputs[0].authorization.requestId)),
            "batch partial commit"
        );
        require(settlement.totalPendingFees() == 3_000, "batch changed escrow");
        _assertSolvent();
    }

    function testDomainVersionNineAndChainBoundSignatures() public {
        MycoSettlementV9.SignedReceipt memory input = _input();
        bytes32 expected = keccak256(
            abi.encode(
                settlement.DOMAIN_TYPEHASH(),
                keccak256("MycoMesh Settlement"),
                keccak256("9"),
                block.chainid,
                address(settlement)
            )
        );
        require(settlement.DOMAIN_SEPARATOR() == expected, "wrong domain");
        vm.chainId(block.chainid + 1);
        require(settlement.DOMAIN_SEPARATOR() != expected, "domain not chain bound");
        vm.expectRevert(bytes("bad key signature"));
        settlement.settleSignedReceipt(input);
    }

    function testConsumerWithdrawalOnlySpendsAvailableNotEscrow() public {
        _settle();
        vm.prank(consumer);
        vm.expectRevert(bytes("bad withdrawal"));
        settlement.requestWithdrawal(100_000);
        vm.prank(consumer);
        settlement.requestWithdrawal(97_000);
        vm.prank(consumer);
        vm.expectRevert(bytes("withdrawal pending"));
        settlement.withdraw();
        vm.warp(block.timestamp + 30);
        vm.prank(consumer);
        settlement.withdraw();
        require(settlement.totalPendingFees() == 3_000, "escrow withdrawn");
        _assertSolvent();
    }

    function testOldPricingAndTreasuryRemainPinnedWhilePending() public {
        bytes32 id = _settle();
        settlement.setTreasury(address(0x9999));
        MycoSettlementV9.ChannelConfig memory config = _config();
        config.providerBps = 5_000;
        config.treasuryBps = 4_500;
        settlement.addChannelVersion(CHANNEL, config);
        vm.warp(settlement.settlementInfo(id).releaseAt);
        settlement.release(id);
        require(settlement.claimableBalance(treasury) == 300, "old treasury changed");
        require(settlement.claimableBalance(address(0x9999)) == 0, "new treasury stole old fee");
        require(settlement.claimableBalance(provider) == 2_550, "old shares changed");
        vm.expectRevert(bytes("bad governance"));
        settlement.transferGovernance(judgeA);
        _assertSolvent();
    }

    function testRewardUnavailableNeverBlocksFullRefund() public {
        bytes32 id = _settle();
        bytes32 reportId = _open(id);
        _confirm(id, reportId);
        require(settlement.availableBalance(consumer) == 100_000, "dry reward blocked refund");
        require(settlement.tokenClaimableBalance(reporter) == 0, "unfunded reward created");
        _assertSolvent();
    }

    function testMaliciousRewardTokenCannotBlockJudgmentOrStableRefund() public {
        settlement.fundTokenRewards(30 ether);
        bytes32 id = _settle();
        bytes32 reportId = _open(id);
        reward.setModes(false, false, true, false);
        _confirm(id, reportId);
        require(settlement.availableBalance(consumer) == 100_000, "reward token blocked refund");
        vm.prank(reporter);
        vm.expectRevert(bytes("token blocked"));
        settlement.claimTokenReward();
        require(settlement.tokenClaimableBalance(reporter) == 10 ether, "failed claim lost token credit");
        reward.setModes(false, false, false, false);
        _assertSolvent();
    }

    function testTokenLifetimeCapAndSeparateClaims() public {
        settlement.fundTokenRewards(30 ether);
        vm.expectRevert(bytes("reward funding cap"));
        settlement.fundTokenRewards(1);
        for (uint256 i; i < 4; ++i) {
            bytes32 id = _settle();
            bytes32 reportId = _open(id);
            _confirm(id, reportId);
            settlement.claimDisputeBond(id, reportId);
        }
        require(settlement.totalRewardAwarded() == 30 ether, "lifetime reward cap");
        require(settlement.tokenClaimableBalance(reporter) == 30 ether, "token claim total");
        vm.prank(reporter);
        settlement.claimTokenReward();
        vm.prank(reporter);
        vm.expectRevert(bytes("no token reward"));
        settlement.claimTokenReward();
        _assertSolvent();
    }

    function testRoundingToZeroSlashCannotEarnTokens() public {
        MycoSettlementV9.ChannelConfig memory config = _config();
        config.inputPer1K = 0;
        config.outputPer1K = 0;
        config.minimumFee = 1;
        settlement = _deploy(config, _policy(), address(reward), _judges(), 2);
        _initialize(settlement);
        settlement.fundTokenRewards(30 ether);
        MycoSettlementV9.SignedReceipt memory input = _input();
        input.receipt.actualFee = 1;
        input = _resign(input);
        settlement.settleSignedReceipt(input);
        bytes32 id = settlement.settlementKeyFor(consumer, key, input.authorization.requestId);
        bytes32 reportId = _open(id);
        _confirm(id, reportId);
        require(settlement.disputeInfo(id).slashAmount == 0, "fixture rounding");
        require(settlement.tokenClaimableBalance(reporter) == 0, "zero-cost token farming");
        require(settlement.availableBalance(consumer) == 100_000, "tiny full refund");
        _assertSolvent();
    }

    function testRewardDisabledConstructorMode() public {
        MycoSettlementV9.DisputePolicy memory policy = _policy();
        policy.tokenReward = 0;
        policy.tokenRewardCap = 0;
        policy.tokenMinimumExposure = 0;
        policy.tokenMinimumPenalty = 0;
        MycoSettlementV9 target = _deploy(_config(), policy, address(0), _judges(), 2);
        vm.expectRevert(bytes("reward disabled"));
        target.fundTokenRewards(1);
    }

    function testExactTransferRejectsFeeSenderDebitAndFalseReturn() public {
        usdc.mint(consumer, 1_000);
        usdc.setModes(true, false, false, false);
        vm.prank(consumer);
        vm.expectRevert(bytes("unsupported token"));
        settlement.deposit(100);
        usdc.setModes(false, true, false, false);
        vm.prank(consumer);
        vm.expectRevert(bytes("unsupported token"));
        settlement.deposit(100);
        usdc.setModes(false, false, false, true);
        vm.prank(consumer);
        vm.expectRevert(bytes("transferFrom failed"));
        settlement.deposit(100);
        usdc.setModes(false, false, false, false);
        require(settlement.availableBalance(consumer) == 100_000, "failed transfer credited");
        _assertSolvent();
    }

    function testOutgoingFeeCannotSilentlyUnderpayAndFailureRollsBackCredit() public {
        bytes32 id = _settle();
        vm.warp(settlement.settlementInfo(id).releaseAt);
        settlement.release(id);
        usdc.setModes(true, false, false, false);
        vm.prank(provider);
        vm.expectRevert(bytes("unsupported token"));
        settlement.claim();
        require(settlement.claimableBalance(provider) == 2_550, "claim not rolled back");
        usdc.setModes(false, false, false, false);
        _assertSolvent();
    }

    function testTokenHookCannotReenterAnyMoneyEntryPoint() public {
        usdc.mint(consumer, 100);
        usdc.setHook(address(settlement), abi.encodeWithSelector(settlement.depositStake.selector, 1));
        vm.prank(consumer);
        settlement.deposit(100);
        require(!usdc.hookSucceeded(), "reentered depositStake");
        require(settlement.providerStake(address(usdc)) == 0, "reentrant stake created");
        _assertSolvent();
    }

    function testConstructorRejectsDuplicateWeakOrConflictedQuorums() public {
        address[] memory judges = _judges();
        judges[1] = judges[0];
        vm.expectRevert(bytes("duplicate adjudicator"));
        _deploy(_config(), _policy(), address(reward), judges, 2);
        judges = _judges();
        vm.expectRevert(bytes("bad judge quorum"));
        _deploy(_config(), _policy(), address(reward), judges, 1);
        judges[0] = address(this);
        vm.expectRevert(bytes("bad adjudicator"));
        _deploy(_config(), _policy(), address(reward), judges, 2);
        judges = new address[](4);
        judges[0] = judgeA;
        judges[1] = judgeB;
        judges[2] = judgeC;
        judges[3] = address(0x3004);
        vm.expectRevert(bytes("bad judge quorum"));
        _deploy(_config(), _policy(), address(reward), judges, 2);
    }

    function testConstructorRejectsUnsafeOrImplicitEconomicPolicies() public {
        MycoSettlementV9.DisputePolicy memory policy = _policy();
        policy.disputeWindow = 0;
        vm.expectRevert(bytes("bad dispute window"));
        _deploy(_config(), policy, address(reward), _judges(), 2);
        policy = _policy();
        policy.arbitrationTimeout = 0;
        vm.expectRevert(bytes("bad arbitration timeout"));
        _deploy(_config(), policy, address(reward), _judges(), 2);
        policy = _policy();
        policy.reporterBountyBps = 10_000;
        vm.expectRevert(bytes("bad bounty policy"));
        _deploy(_config(), policy, address(reward), _judges(), 2);
        policy = _policy();
        policy.tokenMinimumPenalty = 0;
        vm.expectRevert(bytes("bad reward policy"));
        _deploy(_config(), policy, address(reward), _judges(), 2);
        vm.expectRevert(bytes("bad reward token"));
        _deploy(_config(), _policy(), address(usdc), _judges(), 2);
    }

    function testFuzzResolutionConservesAllLiabilities(uint64 seed, uint8 action) public {
        settlement.fundTokenRewards(30 ether);
        MycoSettlementV9.SignedReceipt memory input = _input();
        input.receipt.inputTokens = uint256(seed) % 5_000;
        input.receipt.outputTokens = uint256(seed / 13) % 5_000;
        uint256 fee = settlement.quote(CHANNEL, 1, input.receipt.inputTokens, input.receipt.outputTokens);
        input.receipt.actualFee = fee;
        input = _resign(input);
        settlement.settleSignedReceipt(input);
        bytes32 id = settlement.settlementKeyFor(consumer, key, input.authorization.requestId);
        _assertSolvent();
        uint256 mode = action % 4;
        if (mode == 0) {
            vm.warp(settlement.settlementInfo(id).releaseAt);
            settlement.release(id);
        } else {
            bytes32 reportId = _open(id);
            _assertSolvent();
            if (mode == 1) {
                _confirm(id, reportId);
                require(settlement.availableBalance(consumer) == 100_000, "fuzz full refund");
                settlement.claimDisputeBond(id, reportId);
            } else if (mode == 2) {
                vm.warp(settlement.settlementInfo(id).releaseAt);
                _vote(id, judgeA, false, bytes32(0));
                _vote(id, judgeB, false, bytes32(0));
            } else {
                vm.warp(settlement.disputeInfo(id).resolveAt);
                settlement.resolveTimedOutDispute(id);
                settlement.claimDisputeBond(id, reportId);
            }
        }
        _assertSolvent();
        require(settlement.totalPendingFees() == 0 && settlement.totalReporterBonds() == 0, "terminal escrow lingered");
        require(settlement.lockedStake(provider) == 0, "terminal lock lingered");
        address[6] memory recipients = [provider, relay, pool, treasury, reporter, penalty];
        for (uint256 i; i < recipients.length; ++i) {
            if (settlement.claimableBalance(recipients[i]) > 0) {
                vm.prank(recipients[i]);
                settlement.claim();
                _assertSolvent();
            }
        }
        uint256 stake = settlement.providerStake(provider);
        if (stake > 0) {
            vm.prank(provider);
            settlement.withdrawStake(stake);
        }
        uint256 available = settlement.availableBalance(consumer);
        vm.prank(consumer);
        settlement.requestWithdrawal(available);
        vm.warp(block.timestamp + 30);
        vm.prank(consumer);
        settlement.withdraw();
        require(settlement.stableLiabilities() == 0, "unclaimed stable liability");
        _assertSolvent();
    }
}
