// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV4} from "../contracts/MycoSettlementV4.sol";
import {TestUSDC} from "../contracts/TestUSDC.sol";

interface VmV4 {
    function addr(uint256 privateKey) external returns (address);
    function expectRevert() external;
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
}

contract MockRewardTokenV4 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

contract RevertingRewardTokenV4 {
    function mint(address, uint256) external pure {
        revert("mint disabled");
    }
}

contract MycoSettlementV4Test {
    bytes32 internal constant CHANNEL = keccak256("codex-standard-v1");
    uint256 internal constant CONSUMER_KEY = 0xA11CE;
    uint256 internal constant PROVIDER_KEY = 0xB0B;
    uint256 internal constant OTHER_PROVIDER_KEY = 0xB0C;
    uint256 internal constant SESSION_KEY = 0x5E5510;
    VmV4 internal constant vm = VmV4(address(uint160(uint256(keccak256("hevm cheat code")))));

    TestUSDC internal usdc;
    MockRewardTokenV4 internal reward;
    MycoSettlementV4 internal settlement;
    address internal consumer;
    address internal provider;
    address internal relay = address(0x1002);
    address internal pool = address(0x1003);
    address internal treasury = address(0x1004);

    function setUp() public {
        consumer = vm.addr(CONSUMER_KEY);
        provider = vm.addr(PROVIDER_KEY);
        usdc = new TestUSDC();
        reward = new MockRewardTokenV4();
        settlement = new MycoSettlementV4(
            address(usdc), address(reward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        usdc.mint(consumer, 100_000);
        vm.prank(consumer);
        usdc.approve(address(settlement), type(uint256).max);
        vm.prank(consumer);
        settlement.deposit(100_000);
    }

    function testSessionSettlesSequentialReceiptsAndRefundsOnlyAtClose() public {
        bytes32 sessionId = _openSession(10_000);
        MycoSettlementV4.SessionReceipt memory first = _receipt(sessionId, 0, 1_000, 500);
        MycoSettlementV4.SessionReceipt memory second = _receipt(sessionId, 1, 2_000, 500);

        settlement.settleSignedReceipt(_signed(first));
        settlement.settleSignedReceipt(_signed(second));

        require(settlement.availableBalance(consumer) == 90_000, "available changed before close");
        require(settlement.lockedBalance(consumer) == 10_000, "session lock released early");
        MycoSettlementV4.Session memory state = settlement.sessionInfo(sessionId);
        require(
            state.maxAmount == 10_000 && state.spent == 7_000 && state.nextSequence == 2 && !state.closed,
            "session state mismatch"
        );

        vm.prank(consumer);
        settlement.requestClose(sessionId);
        vm.warp(block.timestamp + settlement.CLOSE_GRACE_SECONDS());
        settlement.closeSession(sessionId);

        require(settlement.availableBalance(consumer) == 93_000, "refund mismatch");
        require(settlement.lockedBalance(consumer) == 0, "lock not released");
        require(usdc.balanceOf(provider) == 5_950, "provider split mismatch");
    }

    function testDuplicateReceiptAndSequenceReplayRejected() public {
        bytes32 sessionId = _openSession(5_000);
        MycoSettlementV4.SignedSessionReceipt memory signed = _signed(_receipt(sessionId, 0, 1_000, 500));
        settlement.settleSignedReceipt(signed);

        vm.expectRevert(bytes("receipt settled"));
        settlement.settleSignedReceipt(signed);

        MycoSettlementV4.SignedSessionReceipt memory next = _signed(_receipt(sessionId, 2, 1_000, 500));
        vm.expectRevert(bytes("bad sequence"));
        settlement.settleSignedReceipt(next);
    }

    function testSessionCumulativeCapIsEnforced() public {
        bytes32 sessionId = _openSession(5_000);
        MycoSettlementV4.SessionReceipt memory receipt = _receipt(sessionId, 0, 10_000, 10_000);
        MycoSettlementV4.SignedSessionReceipt memory signed = _signed(receipt);
        vm.expectRevert(bytes("session amount"));
        settlement.settleSignedReceipt(signed);
    }

    function testBadSignatureAndExpiredReceiptRejected() public {
        bytes32 sessionId = _openSession(5_000);
        MycoSettlementV4.SessionReceipt memory receipt = _receipt(sessionId, 0, 1_000, 500);
        MycoSettlementV4.SignedSessionReceipt memory bad = _signedWithKeys(receipt, OTHER_PROVIDER_KEY, PROVIDER_KEY);
        vm.expectRevert(bytes("bad session signature"));
        settlement.settleSignedReceipt(bad);

        receipt = _receipt(sessionId, 0, 1_000, 500);
        vm.warp(block.timestamp + 2 days);
        MycoSettlementV4.SignedSessionReceipt memory expired = _signed(receipt);
        vm.expectRevert(bytes("receipt expired"));
        settlement.settleSignedReceipt(expired);
    }

    function testRequestCloseHasGraceAndPreventsPostCloseSettlement() public {
        bytes32 sessionId = _openSession(5_000);
        MycoSettlementV4.SessionReceipt memory receipt = _receipt(sessionId, 0, 1_000, 500);
        MycoSettlementV4.SignedSessionReceipt memory signed = _signed(receipt);

        vm.prank(consumer);
        settlement.requestClose(sessionId);
        vm.expectRevert(bytes("close pending"));
        settlement.closeSession(sessionId);

        vm.warp(block.timestamp + settlement.CLOSE_GRACE_SECONDS());
        settlement.closeSession(sessionId);
        require(settlement.availableBalance(consumer) == 100_000, "full refund mismatch");

        vm.expectRevert(bytes("session closed"));
        settlement.settleSignedReceipt(signed);
    }

    function testExpiryAllowsPermissionlessRefund() public {
        bytes32 sessionId = _openSession(5_000);
        MycoSettlementV4.Session memory opened = settlement.sessionInfo(sessionId);
        vm.warp(uint256(opened.expiresAt) + 1);
        settlement.closeSession(sessionId);
        require(settlement.availableBalance(consumer) == 100_000, "expiry refund mismatch");
        require(settlement.lockedBalance(consumer) == 0, "expiry lock mismatch");
    }

    function testBatchSettlementUsesOneSubmissionForMultipleReceipts() public {
        bytes32 sessionId = _openSession(10_000);
        MycoSettlementV4.SignedSessionReceipt[] memory batch = new MycoSettlementV4.SignedSessionReceipt[](2);
        batch[0] = _signed(_receipt(sessionId, 0, 1_000, 500));
        batch[1] = _signed(_receipt(sessionId, 1, 1_000, 500));
        settlement.settleSignedBatch(batch);
        MycoSettlementV4.Session memory state = settlement.sessionInfo(sessionId);
        require(state.nextSequence == 2, "batch sequence mismatch");
        require(state.spent == 6_000, "batch spend mismatch");
    }

    function testRewardsCannotExceedEpochCap() public {
        // Make the treasury reward unit large enough to hit the emission cap in one receipt.
        MycoSettlementV4.ChannelConfig memory config = _defaultConfig();
        config.rewardPerTreasuryUnit = type(uint256).max;
        settlement.scheduleChannelVersion(CHANNEL, config);
        vm.warp(block.timestamp + settlement.GOVERNANCE_DELAY_SECONDS());
        uint64 version = settlement.addChannelVersion(CHANNEL, config);
        settlement.scheduleRewardEnable();
        vm.warp(block.timestamp + settlement.GOVERNANCE_DELAY_SECONDS());
        settlement.enableRewards();

        bytes32 sessionId = _openSessionAtVersion(10_000, version);
        MycoSettlementV4.SessionReceipt memory receipt = _receiptAtVersion(sessionId, 0, 1_000, 500, version);
        settlement.settleSignedReceipt(_signed(receipt));
        require(settlement.epochMinted(settlement.currentEpoch()) <= settlement.currentEpochEmission(), "emission cap");
    }

    function testRewardMintFailureDoesNotBlockPayment() public {
        RevertingRewardTokenV4 reverting = new RevertingRewardTokenV4();
        MycoSettlementV4 fresh = new MycoSettlementV4(
            address(usdc), address(reverting), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        usdc.mint(consumer, 10_000);
        vm.prank(consumer);
        usdc.approve(address(fresh), type(uint256).max);
        vm.prank(consumer);
        fresh.deposit(10_000);
        fresh.scheduleRewardEnable();
        vm.warp(block.timestamp + fresh.GOVERNANCE_DELAY_SECONDS());
        fresh.enableRewards();
        bytes32 salt = keccak256("reverting-reward-session");
        vm.prank(consumer);
        bytes32 id = fresh.openSession(
            salt, provider, vm.addr(SESSION_KEY), CHANNEL, 1, 5_000, uint64(block.timestamp + 5 days)
        );
        MycoSettlementV4.SessionReceipt memory receipt = _receiptForSettlement(fresh, id, 0, 1_000, 500);
        fresh.settleSignedReceipt(_signedForSettlement(fresh, receipt));
        require(usdc.balanceOf(provider) == 2_550, "payment blocked by reward");
    }

    function _openSession(uint256 amount) internal returns (bytes32) {
        return _openSessionAtVersion(amount, 1);
    }

    function _openSessionAtVersion(uint256 amount, uint64 version) internal returns (bytes32 id) {
        vm.prank(consumer);
        id = settlement.openSession(
            keccak256(abi.encode("session", amount, version, block.timestamp)),
            provider,
            vm.addr(SESSION_KEY),
            CHANNEL,
            version,
            amount,
            uint64(block.timestamp + 5 days)
        );
    }

    function _receipt(bytes32 sessionId, uint256 sequence, uint256 inputTokens, uint256 outputTokens)
        internal
        view
        returns (MycoSettlementV4.SessionReceipt memory)
    {
        return _receiptAtVersion(sessionId, sequence, inputTokens, outputTokens, 1);
    }

    function _receiptAtVersion(
        bytes32 sessionId,
        uint256 sequence,
        uint256 inputTokens,
        uint256 outputTokens,
        uint64 version
    ) internal view returns (MycoSettlementV4.SessionReceipt memory receipt) {
        uint256 fee = settlement.quote(CHANNEL, version, inputTokens, outputTokens);
        receipt = MycoSettlementV4.SessionReceipt({
            receiptHash: keccak256(abi.encode("receipt", sessionId, sequence)),
            acceptedHash: keccak256(abi.encode("accepted", sessionId, sequence)),
            sessionId: sessionId,
            requestHash: keccak256(abi.encode("request", sessionId, sequence)),
            responseHash: keccak256(abi.encode("response", sessionId, sequence)),
            channel: CHANNEL,
            pricingVersion: version,
            pricingHash: settlement.channelPricingHash(CHANNEL, version),
            consumer: consumer,
            provider: provider,
            relay: relay,
            pool: pool,
            inputTokens: inputTokens,
            outputTokens: outputTokens,
            sequence: sequence,
            quotedFee: fee,
            deadline: block.timestamp + 1 days
        });
    }

    function _signed(MycoSettlementV4.SessionReceipt memory receipt)
        internal
        returns (MycoSettlementV4.SignedSessionReceipt memory)
    {
        return _signedWithKeys(receipt, SESSION_KEY, PROVIDER_KEY);
    }

    function _signedWithKeys(
        MycoSettlementV4.SessionReceipt memory receipt,
        uint256 sessionKey,
        uint256 providerKey
    ) internal returns (MycoSettlementV4.SignedSessionReceipt memory) {
        bytes32 digest = settlement.receiptDigest(receipt);
        return MycoSettlementV4.SignedSessionReceipt({
            receipt: receipt,
            sessionKeySignature: _sign(sessionKey, digest),
            providerSignature: _sign(providerKey, digest)
        });
    }

    function _receiptForSettlement(
        MycoSettlementV4 target,
        bytes32 id,
        uint256 sequence,
        uint256 inputTokens,
        uint256 outputTokens
    ) internal view returns (MycoSettlementV4.SessionReceipt memory receipt) {
        uint256 fee = target.quote(CHANNEL, 1, inputTokens, outputTokens);
        receipt = MycoSettlementV4.SessionReceipt({
            receiptHash: keccak256(abi.encode("receipt", id, sequence)),
            acceptedHash: keccak256(abi.encode("accepted", id, sequence)),
            sessionId: id,
            requestHash: keccak256(abi.encode("request", id, sequence)),
            responseHash: keccak256(abi.encode("response", id, sequence)),
            channel: CHANNEL,
            pricingVersion: 1,
            pricingHash: target.channelPricingHash(CHANNEL, 1),
            consumer: consumer,
            provider: provider,
            relay: relay,
            pool: pool,
            inputTokens: inputTokens,
            outputTokens: outputTokens,
            sequence: sequence,
            quotedFee: fee,
            deadline: block.timestamp + 1 days
        });
    }

    function _signedForSettlement(MycoSettlementV4 target, MycoSettlementV4.SessionReceipt memory receipt)
        internal
        returns (MycoSettlementV4.SignedSessionReceipt memory)
    {
        bytes32 digest = target.receiptDigest(receipt);
        return MycoSettlementV4.SignedSessionReceipt({
            receipt: receipt,
            sessionKeySignature: _sign(SESSION_KEY, digest),
            providerSignature: _sign(PROVIDER_KEY, digest)
        });
    }

    function _defaultConfig() internal pure returns (MycoSettlementV4.ChannelConfig memory) {
        return MycoSettlementV4.ChannelConfig({
            inputPer1K: 1_000,
            outputPer1K: 4_000,
            minimumFee: 2_000,
            providerBps: 8_500,
            relayBps: 300,
            poolBps: 200,
            treasuryBps: 1_000,
            providerRewardBps: 9_000,
            consumerRewardBps: 1_000,
            rewardPerTreasuryUnit: 1e12,
            active: true
        });
    }

    function _sign(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }
}
