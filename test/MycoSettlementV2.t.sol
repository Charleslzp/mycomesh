// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../contracts/MycoSettlementV2.sol";
import "../contracts/MycoTestnetDeployer.sol";
import "../contracts/MycoToken.sol";
import "../contracts/TestUSDC.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
}

contract MycoSettlementV2Test {
    bytes32 internal constant CHANNEL = keccak256(bytes("codex-standard-v1"));
    uint256 internal constant SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 internal constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testDepositAndSettleFromPrepaidBalance() public {
        address consumer = address(this);
        address provider = address(0x1001);
        address relay = address(0x1002);
        address pool = address(0x1003);
        address treasury = address(0x1004);

        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), treasury);
        token.setMinter(address(settlement));
        settlement.setChannel(CHANNEL, _defaultConfig());
        settlement.setTrustedSettlementEnabled(true);

        usdc.mint(consumer, 10_000_000);
        usdc.approve(address(settlement), 10_000_000);
        settlement.deposit(10_000_000);

        settlement.settleReceiptFromBalance(
            MycoSettlementV2.ReceiptInput({
                receiptHash: keccak256(bytes("receipt-1")),
                acceptedHash: bytes32(0),
                channel: CHANNEL,
                consumer: consumer,
                provider: provider,
                relay: relay,
                pool: pool,
                inputTokens: 1000,
                outputTokens: 500,
                pricingHash: bytes32(0),
                deadline: 0
            })
        );

        require(settlement.prepaidBalance(consumer) == 9_997_000, "prepaid debit");
        require(usdc.balanceOf(provider) == 2550, "provider split");
        require(usdc.balanceOf(relay) == 90, "relay split");
        require(usdc.balanceOf(pool) == 60, "pool split");
        require(usdc.balanceOf(treasury) == 300, "treasury split");
        require(token.balanceOf(provider) == 270 * 1e12, "provider reward");
        require(token.balanceOf(consumer) == 30 * 1e12, "consumer reward");
    }

    function testEpochEmissionCapsRewards() public {
        address consumer = address(this);
        address provider = address(0x1101);
        address treasury = address(0x1104);

        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), treasury);
        token.setMinter(address(settlement));
        settlement.setChannel(CHANNEL, _defaultConfig());
        settlement.setTrustedSettlementEnabled(true);
        settlement.setEconomics(
            MycoSettlementV2.EconomicsConfig({
                epochSeconds: 7 days,
                epochEmission: 100,
                halvingIntervalEpochs: 0,
                maxConsumerRebateBps: 2_000
            })
        );

        usdc.mint(consumer, 10_000_000);
        usdc.approve(address(settlement), 10_000_000);
        settlement.deposit(10_000_000);

        settlement.settleReceiptFromBalance(
            MycoSettlementV2.ReceiptInput({
                receiptHash: keccak256(bytes("receipt-cap-1")),
                acceptedHash: bytes32(0),
                channel: CHANNEL,
                consumer: consumer,
                provider: provider,
                relay: address(0),
                pool: address(0),
                inputTokens: 1000,
                outputTokens: 500,
                pricingHash: bytes32(0),
                deadline: 0
            })
        );
        settlement.settleReceiptFromBalance(
            MycoSettlementV2.ReceiptInput({
                receiptHash: keccak256(bytes("receipt-cap-2")),
                acceptedHash: bytes32(0),
                channel: CHANNEL,
                consumer: consumer,
                provider: provider,
                relay: address(0),
                pool: address(0),
                inputTokens: 1000,
                outputTokens: 500,
                pricingHash: bytes32(0),
                deadline: 0
            })
        );

        require(token.balanceOf(provider) == 90, "provider capped reward");
        require(token.balanceOf(consumer) == 10, "consumer capped reward");
        require(settlement.remainingEpochEmission(settlement.currentEpoch()) == 0, "cap consumed");
    }

    function testWithdrawPrepaidBalance() public {
        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), address(0x2004));

        usdc.mint(address(this), 1_000_000);
        usdc.approve(address(settlement), 1_000_000);
        settlement.deposit(1_000_000);
        settlement.withdraw(400_000);

        require(settlement.prepaidBalance(address(this)) == 600_000, "remaining balance");
        require(usdc.balanceOf(address(this)) == 400_000, "withdraw returned");
    }

    function testGovernanceCanBurnTreasuryRewards() public {
        address treasury = address(0x2204);
        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), treasury);

        token.mint(treasury, 1000);
        token.setMinter(address(settlement));
        settlement.treasuryBuybackBurn(400);

        require(token.balanceOf(treasury) == 600, "treasury burned");
        require(token.totalSupply() == 600, "supply burned");
    }

    function testDelegateControlsCanBeSet() public {
        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), address(0x2304));

        settlement.setSettlementDelegate(address(0x2305), true);

        require(settlement.settlementDelegates(address(this), address(0x2305)), "delegate set");
    }

    function testDelegatedSettlementFromPrepaidBalance() public {
        uint256 consumerKey = 0xA11CE;
        uint256 providerKey = 0xB0B;
        address consumer = vm.addr(consumerKey);
        address provider = vm.addr(providerKey);
        address treasury = address(0x2404);

        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), treasury);
        token.setMinter(address(settlement));
        settlement.setChannel(CHANNEL, _defaultConfig());
        _fundAndDelegate(settlement, usdc, consumer, provider);

        MycoSettlementV2.ReceiptInput memory receipt = _delegatedReceipt(settlement, consumer, provider);
        MycoSettlementV2.SignatureInput memory emptySignature = MycoSettlementV2.SignatureInput({
            r: bytes32(0),
            s: bytes32(0),
            v: 0
        });

        settlement.settleDelegatedReceiptFromBalance(
            MycoSettlementV2.SignedReceiptInput({
                receipt: receipt,
                consumerSignature: emptySignature,
                providerSignature: emptySignature,
                operatorSignature: emptySignature,
                operatorSigned: false
            }),
            _signDigest(consumerKey, settlement.delegateDigest(consumer, address(this), receipt, 3000, 0, 10)),
            _signDigest(providerKey, settlement.delegateDigest(provider, address(this), receipt, 3000, 0, 11)),
            3000,
            0,
            10,
            11
        );

        require(settlement.prepaidBalance(consumer) == 9_997_000, "consumer debited");
        require(usdc.balanceOf(provider) == 2550, "provider paid");
        require(usdc.balanceOf(treasury) == 450, "treasury paid");
        require(settlement.usedDelegateNonces(consumer, 10), "consumer nonce used");
        require(settlement.usedDelegateNonces(provider, 11), "provider nonce used");
    }

    function testDelegatedSettlementRejectsHighSSignature() public {
        uint256 consumerKey = 0xA11CE;
        uint256 providerKey = 0xB0B;
        address consumer = vm.addr(consumerKey);
        address provider = vm.addr(providerKey);
        address treasury = address(0x2504);

        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), treasury);
        token.setMinter(address(settlement));
        settlement.setChannel(CHANNEL, _defaultConfig());
        _fundAndDelegate(settlement, usdc, consumer, provider);

        MycoSettlementV2.ReceiptInput memory receipt = _delegatedReceipt(settlement, consumer, provider);
        MycoSettlementV2.SignatureInput memory emptySignature = MycoSettlementV2.SignatureInput({
            r: bytes32(0),
            s: bytes32(0),
            v: 0
        });
        MycoSettlementV2.SignatureInput memory highSConsumerSignature = _highSSignDigest(
            consumerKey,
            settlement.delegateDigest(consumer, address(this), receipt, 3000, 0, 10)
        );
        MycoSettlementV2.SignatureInput memory providerSignature = _signDigest(
            providerKey,
            settlement.delegateDigest(provider, address(this), receipt, 3000, 0, 11)
        );

        vm.expectRevert(bytes("bad signature s"));
        settlement.settleDelegatedReceiptFromBalance(
            MycoSettlementV2.SignedReceiptInput({
                receipt: receipt,
                consumerSignature: emptySignature,
                providerSignature: emptySignature,
                operatorSignature: emptySignature,
                operatorSigned: false
            }),
            highSConsumerSignature,
            providerSignature,
            3000,
            0,
            10,
            11
        );
    }

    function testTestnetDeployerWiresMycoV2() public {
        MycoTestnetDeployer deployer = new MycoTestnetDeployer(address(0x3004));

        MycoToken token = deployer.token();
        MycoSettlementV2 settlement = deployer.settlement();

        require(keccak256(bytes(token.symbol())) == keccak256(bytes("MYCO")), "symbol");
        require(token.owner() == address(this), "token owner");
        require(settlement.pendingOwner() == address(this), "settlement pending owner");
        require(token.minter() == address(settlement), "settlement minter");
        require(settlement.quote(CHANNEL, 1000, 500) == 3000, "default quote");
    }

    function testGovernanceDelayRequiresScheduledAction() public {
        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), address(0x3304));

        uint256 delay = settlement.MIN_GOVERNANCE_DELAY_SECONDS();
        settlement.setGovernanceDelay(delay);
        bytes32 action = settlement.trustedSettlementActionHash(true);
        settlement.scheduleGovernanceAction(action);
        vm.warp(block.timestamp + delay);
        settlement.setTrustedSettlementEnabled(true);

        require(settlement.trustedSettlementEnabled(), "trusted settlement enabled");
    }

    function testGovernanceDelayProtectsOperatorAndExecutor() public {
        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), address(0x3504));

        uint256 delay = settlement.MIN_GOVERNANCE_DELAY_SECONDS();
        settlement.setGovernanceDelay(delay);

        vm.expectRevert(bytes("governance action not scheduled"));
        settlement.setOperator(address(0x3505), true);

        bytes32 operatorAction = settlement.operatorActionHash(address(0x3505), true);
        settlement.scheduleGovernanceAction(operatorAction);
        vm.warp(block.timestamp + delay);
        settlement.setOperator(address(0x3505), true);
        require(settlement.operators(address(0x3505)), "operator enabled");

        vm.expectRevert(bytes("governance action not scheduled"));
        settlement.setGovernanceExecutor(address(0x3506));
    }

    function testGovernanceDelayRejectsTooShortDelay() public {
        TestUSDC usdc = new TestUSDC();
        MycoToken token = new MycoToken(address(this));
        MycoSettlementV2 settlement = new MycoSettlementV2(address(usdc), address(token), address(0x3404));

        vm.expectRevert(bytes("delay too short"));
        settlement.setGovernanceDelay(1);
    }

    function _defaultConfig() internal pure returns (MycoSettlementV2.ChannelConfig memory) {
        return
            MycoSettlementV2.ChannelConfig({
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

    function _fundAndDelegate(
        MycoSettlementV2 settlement,
        TestUSDC usdc,
        address consumer,
        address provider
    ) internal {
        usdc.mint(consumer, 10_000_000);
        vm.prank(consumer);
        usdc.approve(address(settlement), 10_000_000);
        vm.prank(consumer);
        settlement.deposit(10_000_000);
        vm.prank(consumer);
        settlement.setSettlementDelegate(address(this), true);
        vm.prank(provider);
        settlement.setSettlementDelegate(address(this), true);
    }

    function _delegatedReceipt(
        MycoSettlementV2 settlement,
        address consumer,
        address provider
    ) internal view returns (MycoSettlementV2.ReceiptInput memory) {
        return
            MycoSettlementV2.ReceiptInput({
                receiptHash: keccak256(bytes("delegated-receipt-1")),
                acceptedHash: keccak256(bytes("accepted")),
                channel: CHANNEL,
                consumer: consumer,
                provider: provider,
                relay: address(0),
                pool: address(0),
                inputTokens: 1000,
                outputTokens: 500,
                pricingHash: settlement.channelPricingHash(CHANNEL),
                deadline: 0
            });
    }

    function _signDigest(uint256 signerKey, bytes32 digest) internal returns (MycoSettlementV2.SignatureInput memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return MycoSettlementV2.SignatureInput({r: r, s: s, v: v});
    }

    function _highSSignDigest(uint256 signerKey, bytes32 digest) internal returns (MycoSettlementV2.SignatureInput memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        uint256 value = uint256(s);
        if (value > SECP256K1_HALF_ORDER) {
            return MycoSettlementV2.SignatureInput({r: r, s: s, v: v});
        }
        return MycoSettlementV2.SignatureInput({r: r, s: bytes32(SECP256K1_ORDER - value), v: v == 27 ? 28 : 27});
    }
}
