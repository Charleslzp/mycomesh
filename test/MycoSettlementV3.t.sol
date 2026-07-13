// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1271, MycoSettlementV3} from "../contracts/MycoSettlementV3.sol";
import {MycoTokenV2} from "../contracts/MycoTokenV2.sol";
import {TestUSDC} from "../contracts/TestUSDC.sol";

interface VmV3 {
    function addr(uint256 privateKey) external returns (address);
    function chainId(uint256 newChainId) external;
    function expectRevert() external;
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
}

contract MockRewardTokenV3 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

contract RevertingRewardTokenV3 {
    function mint(address, uint256) external pure {
        revert("mint disabled");
    }
}

contract FeeTokenV3 {
    uint256 public constant FEE_BPS = 1_000;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public feeEnabled = true;

    function setFeeEnabled(bool enabled) external {
        feeEnabled = enabled;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        uint256 received = feeEnabled ? amount - ((amount * FEE_BPS) / 10_000) : amount;
        balanceOf[from] -= amount;
        balanceOf[to] += received;
    }
}

contract Mock1271Wallet is IERC1271 {
    bytes4 private constant MAGIC_VALUE = 0x1626ba7e;
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function execute(address target, bytes calldata data) external returns (bytes memory result) {
        require(msg.sender == owner, "not owner");
        (bool ok, bytes memory returned) = target.call(data);
        require(ok, "call failed");
        return returned;
    }

    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        if (_recover(digest, signature) == owner) return MAGIC_VALUE;
        return bytes4(0xffffffff);
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address recovered) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if ((v != 27 && v != 28) || uint256(s) > HALF_ORDER) return address(0);
        return ecrecover(digest, v, r, s);
    }
}

contract MycoSettlementV3Test {
    bytes32 internal constant CHANNEL = keccak256("codex-standard-v1");
    uint256 internal constant CONSUMER_KEY = 0xA11CE;
    uint256 internal constant PROVIDER_KEY = 0xB0B;
    uint256 internal constant WALLET_OWNER_KEY = 0xCAFE;
    uint256 internal constant ATTACKER_CONSUMER_KEY = 0xA77AC;
    uint256 internal constant ATTACKER_PROVIDER_KEY = 0xA77AF;
    VmV3 internal constant vm = VmV3(address(uint160(uint256(keccak256("hevm cheat code")))));

    TestUSDC internal usdc;
    MockRewardTokenV3 internal reward;
    MycoSettlementV3 internal settlement;
    address internal consumer;
    address internal provider;
    address internal relay = address(0x1002);
    address internal pool = address(0x1003);
    address internal treasury = address(0x1004);

    function setUp() public {
        consumer = vm.addr(CONSUMER_KEY);
        provider = vm.addr(PROVIDER_KEY);
        usdc = new TestUSDC();
        reward = new MockRewardTokenV3();
        settlement = new MycoSettlementV3(
            address(usdc), address(reward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        settlement.scheduleRewardEnable();
        vm.warp(block.timestamp + settlement.GOVERNANCE_DELAY_SECONDS());
        settlement.enableRewards();

        usdc.mint(consumer, 100_000);
        vm.prank(consumer);
        usdc.approve(address(settlement), type(uint256).max);
        vm.prank(consumer);
        settlement.deposit(100_000);
    }

    function testPermissionlessSubmitPaysSignedReceipt() public {
        bytes32 reservationId = keccak256("permissionless-reservation");
        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(reservationId, 5_000);
        MycoSettlementV3.SignedReceiptInput memory signedReceipt = _signReceipt(receipt);

        vm.prank(provider);
        settlement.settleSignedReceipt(signedReceipt);

        require(settlement.availableBalance(consumer) == 97_000, "available after settlement");
        require(settlement.lockedBalance(consumer) == 0, "lock consumed");
        require(usdc.balanceOf(provider) == 2_550, "provider paid");
        require(usdc.balanceOf(relay) == 90, "relay paid");
        require(usdc.balanceOf(pool) == 60, "pool paid");
        require(usdc.balanceOf(treasury) == 300, "treasury paid");
        require(reward.balanceOf(provider) == 270 * 1e12, "provider reward");
        require(reward.balanceOf(consumer) == 30 * 1e12, "consumer reward");
        require(settlement.epochMinted(settlement.currentEpoch()) == 300 * 1e12, "successful rewards counted");
    }

    function testRewardsStartDisabledAndEnableRequiresTypedDelay() public {
        MycoSettlementV3 fresh = new MycoSettlementV3(
            address(usdc), address(reward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        require(!fresh.rewardsEnabled(), "rewards enabled by default");

        fresh.scheduleRewardEnable();
        vm.expectRevert(bytes("action pending"));
        fresh.enableRewards();
        vm.warp(block.timestamp + fresh.GOVERNANCE_DELAY_SECONDS());
        fresh.enableRewards();
        require(fresh.rewardsEnabled(), "rewards not enabled");
    }

    function testImmediateRewardPauseControlsExistingReservationAndCancelsPendingEnable() public {
        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(keccak256("pause-existing"), 5_000);
        MycoSettlementV3.SignedReceiptInput memory signedReceipt = _signReceipt(receipt);

        settlement.pauseRewards();
        settlement.settleSignedReceipt(signedReceipt);
        MycoSettlementV3.Settlement memory item = settlement.settlement(receipt.reservationId, receipt.receiptHash);
        require(item.providerReward == 0 && item.consumerReward == 0, "paused reservation rewarded");
        require(settlement.epochMinted(settlement.currentEpoch()) == 0, "paused reward consumed cap");

        settlement.scheduleRewardEnable();
        vm.warp(block.timestamp + settlement.GOVERNANCE_DELAY_SECONDS());
        settlement.pauseRewards();
        vm.expectRevert(bytes("action not scheduled"));
        settlement.enableRewards();
    }

    function testProviderFallbackPaysOnlyMinimumProviderShareAndTreasury() public {
        MycoSettlementV3.ReceiptInput memory receipt =
            _reserveAndReceiptWithFallback(keccak256("provider-fallback"), 5_000, true);
        receipt.acceptedHash = bytes32(0);
        bytes32 digest = settlement.receiptDigest(receipt);

        vm.prank(address(0xBEEF));
        settlement.settleProviderFallback(receipt, _sign(PROVIDER_KEY, digest));

        require(settlement.availableBalance(consumer) == 98_000, "unused reservation not returned");
        require(settlement.lockedBalance(consumer) == 0, "fallback lock retained");
        require(usdc.balanceOf(provider) == 1_700, "provider fallback share");
        require(usdc.balanceOf(relay) == 0 && usdc.balanceOf(pool) == 0, "fallback intermediary paid");
        require(usdc.balanceOf(treasury) == 300, "fallback treasury share");
        require(reward.balanceOf(provider) == 0 && reward.balanceOf(consumer) == 0, "fallback rewarded");

        MycoSettlementV3.Settlement memory item = settlement.settlement(receipt.reservationId, receipt.receiptHash);
        require(item.providerFallback, "fallback not recorded");
        require(item.grossFee == 2_000, "fallback did not use minimum");
        require(item.relayAmount == 0 && item.poolAmount == 0, "fallback split recorded");
    }

    function testProviderFallbackRequiresBoundProviderSignatureAndRequest() public {
        MycoSettlementV3.ReceiptInput memory receipt =
            _reserveAndReceiptWithFallback(keccak256("fallback-auth"), 5_000, true);
        receipt.acceptedHash = bytes32(0);
        bytes32 digest = settlement.receiptDigest(receipt);

        vm.expectRevert(bytes("bad provider signature"));
        settlement.settleProviderFallback(receipt, _sign(CONSUMER_KEY, digest));

        receipt.requestHash = keccak256("different-request");
        bytes memory mismatchedSignature = _sign(PROVIDER_KEY, settlement.receiptDigest(receipt));
        vm.expectRevert(bytes("reservation request"));
        settlement.settleProviderFallback(receipt, mismatchedSignature);
        require(settlement.lockedBalance(consumer) == 5_000, "failed fallback consumed reservation");
    }

    function testProviderFallbackRequiresExplicitConsumerOptInAndZeroAcceptance() public {
        MycoSettlementV3.ReceiptInput memory disabled = _reserveAndReceipt(keccak256("fallback-disabled"), 5_000);
        disabled.acceptedHash = bytes32(0);
        bytes memory disabledSignature = _sign(PROVIDER_KEY, settlement.receiptDigest(disabled));
        vm.expectRevert(bytes("fallback not allowed"));
        settlement.settleProviderFallback(disabled, disabledSignature);

        MycoSettlementV3.ReceiptInput memory accepted =
            _reserveAndReceiptWithFallback(keccak256("fallback-with-acceptance"), 5_000, true);
        bytes memory acceptedSignature = _sign(PROVIDER_KEY, settlement.receiptDigest(accepted));
        vm.expectRevert(bytes("unexpected acceptance"));
        settlement.settleProviderFallback(accepted, acceptedSignature);

        require(settlement.lockedBalance(consumer) == 10_000, "rejected fallback consumed reservation");
    }

    function testReservationRequiresAndStoresRequestHash() public {
        bytes32 salt = keccak256("request-binding");
        uint64 expiresAt = uint64(block.timestamp + 1 days);
        vm.prank(consumer);
        vm.expectRevert(bytes("zero request hash"));
        settlement.createReservation(salt, provider, CHANNEL, bytes32(0), 1, 5_000, expiresAt, false);

        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(salt, 5_000);
        (,,, bytes32 storedRequestHash,,,,,) = settlement.reservations(receipt.reservationId);
        require(storedRequestHash == receipt.requestHash, "request hash not stored");
    }

    function testDomainSeparatorTracksChainIdAndEpochsStartAtDeployment() public {
        uint256 deployedChainId = block.chainid;
        bytes32 initialDomain = settlement.DOMAIN_SEPARATOR();
        require(settlement.currentEpoch() == 0, "epoch inherited wall clock");

        vm.chainId(deployedChainId + 1);
        bytes32 forkDomain = settlement.DOMAIN_SEPARATOR();
        require(forkDomain != initialDomain, "fork domain replayable");
        bytes32 expected = keccak256(
            abi.encode(
                settlement.DOMAIN_TYPEHASH(),
                keccak256(bytes("MycoMesh Settlement")),
                keccak256(bytes("3")),
                deployedChainId + 1,
                address(settlement)
            )
        );
        require(forkDomain == expected, "fork domain mismatch");

        vm.warp(settlement.emissionStartedAt() + settlement.HALVING_INTERVAL_EPOCHS() * settlement.EPOCH_SECONDS());
        require(settlement.currentEpoch() == 208, "relative epoch mismatch");
        require(settlement.currentEpochEmission() == settlement.EPOCH_EMISSION() / 2, "four-year halving missing");
    }

    function testConstructorRejectsNonContractStablecoin() public {
        vm.expectRevert(bytes("stablecoin not contract"));
        new MycoSettlementV3(
            address(0x1234), address(reward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
    }

    function testLockedReservationCannotBeWithdrawn() public {
        _reserveAndReceipt(keccak256("locked-reservation"), 5_000);

        vm.prank(consumer);
        vm.expectRevert(bytes("available balance"));
        settlement.withdraw(95_001);

        vm.prank(consumer);
        settlement.withdraw(95_000);
        require(settlement.availableBalance(consumer) == 0, "available withdrawn");
        require(settlement.lockedBalance(consumer) == 5_000, "reservation still funded");
        require(usdc.balanceOf(address(settlement)) == 5_000, "locked tokens retained");
    }

    function testExpiredReservationCanOnlyReturnFundsToConsumer() public {
        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(keccak256("expiring-reservation"), 5_000);
        bytes32 reservationId = receipt.reservationId;
        (,,,,, uint64 expiresAt,,,) = settlement.reservations(reservationId);
        vm.warp(uint256(expiresAt) + 1);

        vm.prank(address(0xBAD));
        settlement.releaseExpiredReservation(reservationId);

        require(settlement.availableBalance(consumer) == 100_000, "funds returned");
        require(settlement.lockedBalance(consumer) == 0, "lock released");
        require(usdc.balanceOf(address(0xBAD)) == 0, "caller not paid");
    }

    function testCopiedReservationSaltCannotFrontRunConsumer() public {
        address attacker = address(0xA77A);
        bytes32 reservationSalt = keccak256("public-mempool-salt");
        bytes32 requestHash = keccak256("public-mempool-request");
        uint64 expiresAt = uint64(block.timestamp + 1 days);

        usdc.mint(attacker, 5_000);
        vm.prank(attacker);
        usdc.approve(address(settlement), 5_000);
        vm.prank(attacker);
        settlement.deposit(5_000);

        bytes32 attackerId = settlement.reservationIdFor(attacker, reservationSalt);
        bytes32 consumerId = settlement.reservationIdFor(consumer, reservationSalt);
        require(attackerId != consumerId, "consumer namespace missing");

        vm.prank(attacker);
        bytes32 createdAttackerId =
            settlement.createReservation(reservationSalt, provider, CHANNEL, requestHash, 1, 2_000, expiresAt, false);
        vm.prank(consumer);
        bytes32 createdConsumerId =
            settlement.createReservation(reservationSalt, provider, CHANNEL, requestHash, 1, 5_000, expiresAt, false);

        require(createdAttackerId == attackerId, "attacker id mismatch");
        require(createdConsumerId == consumerId, "consumer id mismatch");
        (address attackerOwner,,,,,,,,) = settlement.reservations(attackerId);
        (address consumerOwner,,,,,,,,) = settlement.reservations(consumerId);
        require(attackerOwner == attacker, "attacker reservation missing");
        require(consumerOwner == consumer, "consumer reservation blocked");
    }

    function testCopiedReceiptHashCannotBlockAnotherReservation() public {
        MycoSettlementV3.ReceiptInput memory victimReceipt = _reserveAndReceipt(keccak256("victim-receipt"), 5_000);
        MycoSettlementV3.SignedReceiptInput memory signedVictimReceipt = _signReceipt(victimReceipt);

        address attackerConsumer = vm.addr(ATTACKER_CONSUMER_KEY);
        address attackerProvider = vm.addr(ATTACKER_PROVIDER_KEY);
        usdc.mint(attackerConsumer, 5_000);
        vm.prank(attackerConsumer);
        usdc.approve(address(settlement), 5_000);
        vm.prank(attackerConsumer);
        settlement.deposit(5_000);

        bytes32 attackerSalt = keccak256("attacker-receipt");
        bytes32 attackerReservationId = settlement.reservationIdFor(attackerConsumer, attackerSalt);
        bytes32 attackerRequestHash = keccak256(abi.encode("request", attackerReservationId));
        uint64 expiresAt = uint64(block.timestamp + 1 days);
        vm.prank(attackerConsumer);
        settlement.createReservation(
            attackerSalt, attackerProvider, CHANNEL, attackerRequestHash, 1, 5_000, expiresAt, true
        );

        MycoSettlementV3.ReceiptInput memory attackerReceipt =
            _receiptFor(attackerReservationId, attackerConsumer, attackerProvider, 1, expiresAt);
        attackerReceipt.receiptHash = victimReceipt.receiptHash;
        attackerReceipt.acceptedHash = bytes32(0);
        settlement.settleProviderFallback(
            attackerReceipt, _sign(ATTACKER_PROVIDER_KEY, settlement.receiptDigest(attackerReceipt))
        );

        require(
            settlement.receiptSettled(attackerReservationId, victimReceipt.receiptHash), "attacker settlement missing"
        );
        require(
            !settlement.receiptSettled(victimReceipt.reservationId, victimReceipt.receiptHash),
            "victim receipt globally blocked"
        );
        require(
            settlement.settlementKeyFor(attackerReservationId, victimReceipt.receiptHash)
                != settlement.settlementKeyFor(victimReceipt.reservationId, victimReceipt.receiptHash),
            "settlement key not reservation-bound"
        );

        settlement.settleSignedReceipt(signedVictimReceipt);
        require(
            settlement.receiptSettled(victimReceipt.reservationId, victimReceipt.receiptHash),
            "victim settlement failed"
        );
        MycoSettlementV3.Settlement memory attackerItem =
            settlement.settlement(attackerReservationId, victimReceipt.receiptHash);
        MycoSettlementV3.Settlement memory victimItem =
            settlement.settlement(victimReceipt.reservationId, victimReceipt.receiptHash);
        require(attackerItem.providerFallback, "attacker fallback record lost");
        require(!victimItem.providerFallback && victimItem.grossFee == 3_000, "victim record overwritten");
    }

    function testSignedReceiptRejectsRelayPoolAndEvidenceMutation() public {
        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(keccak256("field-mutation"), 5_000);
        MycoSettlementV3.SignedReceiptInput memory signedReceipt = _signReceipt(receipt);

        signedReceipt.receipt.relay = address(0xDEAD);
        vm.expectRevert(bytes("bad consumer signature"));
        settlement.settleSignedReceipt(signedReceipt);

        signedReceipt.receipt.relay = receipt.relay;
        signedReceipt.receipt.pool = address(0xDEAD);
        vm.expectRevert(bytes("bad consumer signature"));
        settlement.settleSignedReceipt(signedReceipt);

        signedReceipt.receipt.pool = receipt.pool;
        bytes32 requestHash = signedReceipt.receipt.requestHash;
        signedReceipt.receipt.requestHash = keccak256("mutated-request");
        vm.expectRevert(bytes("reservation request"));
        settlement.settleSignedReceipt(signedReceipt);

        signedReceipt.receipt.requestHash = requestHash;
        signedReceipt.receipt.outputTokens += 1;
        vm.expectRevert(bytes("bad consumer signature"));
        settlement.settleSignedReceipt(signedReceipt);
    }

    function testFuzzEveryReceiptFieldMutationIsRejected(uint8 field, bytes32 entropy) public {
        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(keccak256("fuzz-field-mutation"), 5_000);
        MycoSettlementV3.SignedReceiptInput memory signedReceipt = _signReceipt(receipt);
        uint8 selected = field % 15;

        if (selected == 0) signedReceipt.receipt.receiptHash = _different(entropy, receipt.receiptHash);
        else if (selected == 1) signedReceipt.receipt.acceptedHash = _different(entropy, receipt.acceptedHash);
        else if (selected == 2) signedReceipt.receipt.reservationId = _different(entropy, receipt.reservationId);
        else if (selected == 3) signedReceipt.receipt.requestHash = _different(entropy, receipt.requestHash);
        else if (selected == 4) signedReceipt.receipt.responseHash = _different(entropy, receipt.responseHash);
        else if (selected == 5) signedReceipt.receipt.channel = _different(entropy, receipt.channel);
        else if (selected == 6) signedReceipt.receipt.pricingVersion = receipt.pricingVersion + 1;
        else if (selected == 7) signedReceipt.receipt.pricingHash = _different(entropy, receipt.pricingHash);
        else if (selected == 8) signedReceipt.receipt.consumer = _differentAddress(entropy, receipt.consumer);
        else if (selected == 9) signedReceipt.receipt.provider = _differentAddress(entropy, receipt.provider);
        else if (selected == 10) signedReceipt.receipt.relay = _differentAddress(entropy, receipt.relay);
        else if (selected == 11) signedReceipt.receipt.pool = _differentAddress(entropy, receipt.pool);
        else if (selected == 12) signedReceipt.receipt.inputTokens = receipt.inputTokens + 1;
        else if (selected == 13) signedReceipt.receipt.outputTokens = receipt.outputTokens + 1;
        else signedReceipt.receipt.deadline = receipt.deadline - 1;

        vm.expectRevert();
        settlement.settleSignedReceipt(signedReceipt);
        require(settlement.lockedBalance(consumer) == 5_000, "mutation consumed reservation");
    }

    function testDelegatedReceiptRejectsRelayPoolMutationAndRoleSwap() public {
        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(keccak256("delegated-mutation"), 5_000);
        MycoSettlementV3.DelegatedReceiptInput memory delegated = _delegateReceipt(receipt, 10, 11);

        delegated.receipt.relay = address(0xDEAD);
        vm.expectRevert(bytes("bad delegate signature"));
        settlement.settleDelegatedReceipt(delegated);

        delegated.receipt.relay = receipt.relay;
        delegated.receipt.pool = address(0xDEAD);
        vm.expectRevert(bytes("bad delegate signature"));
        settlement.settleDelegatedReceipt(delegated);

        delegated.receipt.pool = receipt.pool;
        MycoSettlementV3.DelegateAuthorizationInput memory consumerAuthorization = delegated.consumerAuthorization;
        delegated.consumerAuthorization = delegated.providerAuthorization;
        delegated.providerAuthorization = consumerAuthorization;
        vm.expectRevert(bytes("bad delegate signature"));
        settlement.settleDelegatedReceipt(delegated);
    }

    function testDelegatedReceiptCanBeSubmittedOnlyByBoundDelegate() public {
        MycoSettlementV3.ReceiptInput memory receipt = _reserveAndReceipt(keccak256("bound-delegate"), 5_000);
        MycoSettlementV3.DelegatedReceiptInput memory delegated = _delegateReceipt(receipt, 20, 21);

        vm.prank(address(0xBEEF));
        vm.expectRevert(bytes("bad delegate signature"));
        settlement.settleDelegatedReceipt(delegated);

        settlement.settleDelegatedReceipt(delegated);
        require(usdc.balanceOf(provider) == 2_550, "provider paid");
        require(settlement.usedDelegateNonces(consumer, 20), "consumer nonce used");
        require(settlement.usedDelegateNonces(provider, 21), "provider nonce used");
    }

    function testExistingReservationSettlesAfterNewPricingVersion() public {
        MycoSettlementV3.ReceiptInput memory oldReceipt = _reserveAndReceipt(keccak256("old-price"), 5_000);
        MycoSettlementV3.SignedReceiptInput memory signedOldReceipt = _signReceipt(oldReceipt);

        MycoSettlementV3.ChannelConfig memory newConfig = _defaultConfig();
        newConfig.outputPer1K = 8_000;
        _addVersion(newConfig);
        require(settlement.latestChannelVersion(CHANNEL) == 2, "new version active");
        require(settlement.quote(CHANNEL, 2, 1_000, 500) == 5_000, "new quote");

        vm.prank(address(0xBEEF));
        settlement.settleSignedReceipt(signedOldReceipt);
        require(usdc.balanceOf(provider) == 2_550, "old quote paid");
        MycoSettlementV3.Settlement memory item =
            settlement.settlement(oldReceipt.reservationId, oldReceipt.receiptHash);
        require(item.pricingVersion == 1, "old version retained");
        require(item.grossFee == 3_000, "old fee retained");
    }

    function testNewReservationCannotSelectStalePricing() public {
        MycoSettlementV3.ChannelConfig memory newConfig = _defaultConfig();
        newConfig.outputPer1K = 8_000;
        _addVersion(newConfig);

        vm.prank(consumer);
        vm.expectRevert(bytes("not latest pricing"));
        settlement.createReservation(
            keccak256("stale-price"),
            provider,
            CHANNEL,
            keccak256("stale-request"),
            1,
            5_000,
            uint64(block.timestamp + 1 days),
            false
        );
    }

    function testGovernanceTransferIsDelayedAndOldGovernanceLosesAuthority() public {
        address nextGovernance = address(0x9001);
        settlement.beginGovernanceTransfer(nextGovernance);

        vm.prank(nextGovernance);
        vm.expectRevert(bytes("governance transfer pending"));
        settlement.acceptGovernance();

        vm.warp(block.timestamp + settlement.GOVERNANCE_DELAY_SECONDS());
        vm.prank(nextGovernance);
        settlement.acceptGovernance();
        require(settlement.governance() == nextGovernance, "governance transferred");

        vm.expectRevert(bytes("not governance"));
        settlement.scheduleTreasuryUpdate(address(0x9002));

        vm.prank(nextGovernance);
        settlement.scheduleTreasuryUpdate(address(0x9002));
    }

    function testGovernanceActionsCannotBypassDelay() public {
        address nextTreasury = address(0x9003);
        settlement.scheduleTreasuryUpdate(nextTreasury);

        vm.expectRevert(bytes("action pending"));
        settlement.setTreasury(nextTreasury);

        vm.warp(block.timestamp + settlement.GOVERNANCE_DELAY_SECONDS());
        settlement.setTreasury(nextTreasury);
        require(settlement.treasury() == nextTreasury, "treasury updated");
    }

    function testChannelRejectsConsumerRewardAboveProtocolCap() public {
        MycoSettlementV3.ChannelConfig memory invalid = _defaultConfig();
        invalid.providerRewardBps = 7_999;
        invalid.consumerRewardBps = 2_001;
        vm.expectRevert(bytes("consumer rebate too high"));
        settlement.scheduleChannelVersion(CHANNEL, invalid);
    }

    function testQuoteHandlesFullWidthProductsAndExplicitlyRejectsResultOverflow() public {
        MycoSettlementV3.ChannelConfig memory config = _defaultConfig();
        config.inputPer1K = type(uint256).max;
        config.outputPer1K = 0;
        config.minimumFee = 0;
        _addVersion(config);

        uint64 version = settlement.latestChannelVersion(CHANNEL);
        uint256 expected = ((type(uint256).max / 1000) * 999) + (((type(uint256).max % 1000) * 999) / 1000);
        require(settlement.quote(CHANNEL, version, 999, 0) == expected, "full-width quote");

        vm.expectRevert(bytes("quote overflow"));
        settlement.quote(CHANNEL, version, 1_001, 0);
    }

    function testBatchLengthIsCapped() public {
        MycoSettlementV3.SignedReceiptInput[] memory receipts =
            new MycoSettlementV3.SignedReceiptInput[](settlement.MAX_BATCH_SIZE() + 1);
        vm.expectRevert(bytes("bad batch length"));
        settlement.settleSignedBatch(receipts);
    }

    function testEIP1271ConsumerWalletCanSignReceipt() public {
        address walletOwner = vm.addr(WALLET_OWNER_KEY);
        Mock1271Wallet wallet = new Mock1271Wallet(walletOwner);
        usdc.mint(address(wallet), 10_000);

        vm.prank(walletOwner);
        wallet.execute(address(usdc), abi.encodeCall(TestUSDC.approve, (address(settlement), type(uint256).max)));
        vm.prank(walletOwner);
        wallet.execute(address(settlement), abi.encodeCall(MycoSettlementV3.deposit, (10_000)));

        bytes32 reservationSalt = keccak256("contract-wallet-reservation");
        bytes32 reservationId = settlement.reservationIdFor(address(wallet), reservationSalt);
        bytes32 requestHash = keccak256(abi.encode("request", reservationId));
        uint64 expiresAt = uint64(block.timestamp + 5 days);
        vm.prank(walletOwner);
        wallet.execute(
            address(settlement),
            abi.encodeCall(
                MycoSettlementV3.createReservation,
                (reservationSalt, provider, CHANNEL, requestHash, uint64(1), 5_000, expiresAt, false)
            )
        );

        MycoSettlementV3.ReceiptInput memory receipt =
            _receiptFor(reservationId, address(wallet), provider, 1, expiresAt);
        bytes32 digest = settlement.receiptDigest(receipt);
        MycoSettlementV3.SignedReceiptInput memory signedReceipt = MycoSettlementV3.SignedReceiptInput({
            receipt: receipt,
            consumerSignature: _sign(WALLET_OWNER_KEY, digest),
            providerSignature: _sign(PROVIDER_KEY, digest)
        });

        vm.prank(address(0xBEEF));
        settlement.settleSignedReceipt(signedReceipt);
        require(usdc.balanceOf(provider) == 2_550, "contract signature accepted");
    }

    function testDepositRejectsFeeOnTransferToken() public {
        FeeTokenV3 feeToken = new FeeTokenV3();
        MycoSettlementV3 feeSettlement = new MycoSettlementV3(
            address(feeToken), address(reward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        feeToken.mint(address(this), 10_000);
        feeToken.approve(address(feeSettlement), 10_000);

        vm.expectRevert(bytes("unsupported token behavior"));
        feeSettlement.deposit(10_000);
        require(feeSettlement.availableBalance(address(this)) == 0, "fee deposit credited");
    }

    function testWithdrawRejectsTokenThatAddsOutgoingFee() public {
        FeeTokenV3 feeToken = new FeeTokenV3();
        MycoSettlementV3 feeSettlement = new MycoSettlementV3(
            address(feeToken), address(reward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        feeToken.setFeeEnabled(false);
        feeToken.mint(address(this), 10_000);
        feeToken.approve(address(feeSettlement), 10_000);
        feeSettlement.deposit(10_000);

        feeToken.setFeeEnabled(true);
        vm.expectRevert(bytes("unsupported token behavior"));
        feeSettlement.withdraw(10_000);
        require(feeSettlement.availableBalance(address(this)) == 10_000, "withdraw accounting changed");
    }

    function testRewardFailureCannotBlockStablecoinSettlement() public {
        RevertingRewardTokenV3 revertingReward = new RevertingRewardTokenV3();
        MycoSettlementV3 paymentSettlement = new MycoSettlementV3(
            address(usdc), address(revertingReward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        paymentSettlement.scheduleRewardEnable();
        vm.warp(block.timestamp + paymentSettlement.GOVERNANCE_DELAY_SECONDS());
        paymentSettlement.enableRewards();

        bytes32 reservationSalt = keccak256("reward-failure");
        bytes32 reservationId = paymentSettlement.reservationIdFor(consumer, reservationSalt);
        bytes32 requestHash = keccak256(abi.encode("request", reservationId));
        uint64 expiresAt = uint64(block.timestamp + 1 days);
        usdc.mint(consumer, 10_000);
        vm.prank(consumer);
        usdc.approve(address(paymentSettlement), 10_000);
        vm.prank(consumer);
        paymentSettlement.deposit(10_000);
        vm.prank(consumer);
        paymentSettlement.createReservation(reservationSalt, provider, CHANNEL, requestHash, 1, 5_000, expiresAt, false);

        MycoSettlementV3.ReceiptInput memory receipt = MycoSettlementV3.ReceiptInput({
            receiptHash: keccak256(abi.encode("receipt", reservationId)),
            acceptedHash: keccak256(abi.encode("accepted", reservationId)),
            reservationId: reservationId,
            requestHash: requestHash,
            responseHash: keccak256(abi.encode("response", reservationId)),
            channel: CHANNEL,
            pricingVersion: 1,
            pricingHash: paymentSettlement.channelPricingHash(CHANNEL, 1),
            consumer: consumer,
            provider: provider,
            relay: relay,
            pool: pool,
            inputTokens: 1_000,
            outputTokens: 500,
            deadline: expiresAt
        });
        bytes32 digest = paymentSettlement.receiptDigest(receipt);
        paymentSettlement.settleSignedReceipt(
            MycoSettlementV3.SignedReceiptInput({
                receipt: receipt,
                consumerSignature: _sign(CONSUMER_KEY, digest),
                providerSignature: _sign(PROVIDER_KEY, digest)
            })
        );

        require(usdc.balanceOf(provider) == 2_550, "stablecoin payment completed");
        MycoSettlementV3.Settlement memory item =
            paymentSettlement.settlement(receipt.reservationId, receipt.receiptHash);
        require(item.providerReward == 0 && item.consumerReward == 0, "failed reward not recorded");
        require(paymentSettlement.epochMinted(paymentSettlement.currentEpoch()) == 0, "failed reward consumed cap");
    }

    function testMycoTokenV2HasImmutableCappedMintAuthorityAndSelfBurnOnly() public {
        MycoTokenV2 token = new MycoTokenV2(address(this), 100);
        address holder = address(0xA001);
        token.mint(holder, 100);

        vm.expectRevert(bytes("max supply"));
        token.mint(holder, 1);

        vm.prank(address(0xBAD));
        vm.expectRevert(bytes("not mint authority"));
        token.mint(address(0xBAD), 1);

        vm.prank(address(0xBAD));
        vm.expectRevert(bytes("balance"));
        token.burn(1);

        vm.prank(holder);
        token.burn(40);
        require(token.balanceOf(holder) == 60, "holder self burn");
        require(token.totalSupply() == 60, "supply reduced");
    }

    function testMycoTokenV2RejectsExternallyOwnedMintAuthority() public {
        vm.expectRevert(bytes("authority not contract"));
        new MycoTokenV2(address(0xBEEF), 100);
    }

    function _reserveAndReceipt(bytes32 reservationSalt, uint256 amount)
        internal
        returns (MycoSettlementV3.ReceiptInput memory)
    {
        return _reserveAndReceiptWithFallback(reservationSalt, amount, false);
    }

    function _reserveAndReceiptWithFallback(bytes32 reservationSalt, uint256 amount, bool providerFallbackAllowed)
        internal
        returns (MycoSettlementV3.ReceiptInput memory)
    {
        uint64 expiresAt = uint64(block.timestamp + 10 days);
        bytes32 reservationId = settlement.reservationIdFor(consumer, reservationSalt);
        bytes32 requestHash = keccak256(abi.encode("request", reservationId));
        vm.prank(consumer);
        settlement.createReservation(
            reservationSalt, provider, CHANNEL, requestHash, 1, amount, expiresAt, providerFallbackAllowed
        );
        return _receiptFor(reservationId, consumer, provider, 1, expiresAt);
    }

    function _receiptFor(
        bytes32 reservationId,
        address receiptConsumer,
        address receiptProvider,
        uint64 pricingVersion,
        uint64 deadline
    ) internal view returns (MycoSettlementV3.ReceiptInput memory) {
        return MycoSettlementV3.ReceiptInput({
            receiptHash: keccak256(abi.encode("receipt", reservationId)),
            acceptedHash: keccak256(abi.encode("accepted", reservationId)),
            reservationId: reservationId,
            requestHash: keccak256(abi.encode("request", reservationId)),
            responseHash: keccak256(abi.encode("response", reservationId)),
            channel: CHANNEL,
            pricingVersion: pricingVersion,
            pricingHash: settlement.channelPricingHash(CHANNEL, pricingVersion),
            consumer: receiptConsumer,
            provider: receiptProvider,
            relay: relay,
            pool: pool,
            inputTokens: 1_000,
            outputTokens: 500,
            deadline: deadline
        });
    }

    function _signReceipt(MycoSettlementV3.ReceiptInput memory receipt)
        internal
        returns (MycoSettlementV3.SignedReceiptInput memory)
    {
        bytes32 digest = settlement.receiptDigest(receipt);
        return MycoSettlementV3.SignedReceiptInput({
            receipt: receipt,
            consumerSignature: _sign(CONSUMER_KEY, digest),
            providerSignature: _sign(PROVIDER_KEY, digest)
        });
    }

    function _delegateReceipt(
        MycoSettlementV3.ReceiptInput memory receipt,
        uint256 consumerNonce,
        uint256 providerNonce
    ) internal returns (MycoSettlementV3.DelegatedReceiptInput memory) {
        uint256 maxAmount = 3_000;
        uint256 expiresAt = block.timestamp + 1 days;
        bytes32 consumerDigest = settlement.delegateDigest(
            receipt, consumer, address(this), settlement.ROLE_CONSUMER(), maxAmount, expiresAt, consumerNonce
        );
        bytes32 providerDigest = settlement.delegateDigest(
            receipt, provider, address(this), settlement.ROLE_PROVIDER(), maxAmount, expiresAt, providerNonce
        );
        return MycoSettlementV3.DelegatedReceiptInput({
            receipt: receipt,
            consumerAuthorization: MycoSettlementV3.DelegateAuthorizationInput({
                maxAmount: maxAmount,
                expiresAt: expiresAt,
                nonce: consumerNonce,
                signature: _sign(CONSUMER_KEY, consumerDigest)
            }),
            providerAuthorization: MycoSettlementV3.DelegateAuthorizationInput({
                maxAmount: maxAmount,
                expiresAt: expiresAt,
                nonce: providerNonce,
                signature: _sign(PROVIDER_KEY, providerDigest)
            })
        });
    }

    function _addVersion(MycoSettlementV3.ChannelConfig memory config) internal {
        settlement.scheduleChannelVersion(CHANNEL, config);
        vm.warp(block.timestamp + settlement.GOVERNANCE_DELAY_SECONDS());
        settlement.addChannelVersion(CHANNEL, config);
    }

    function _defaultConfig() internal pure returns (MycoSettlementV3.ChannelConfig memory) {
        return MycoSettlementV3.ChannelConfig({
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

    function _different(bytes32 entropy, bytes32 original) internal pure returns (bytes32 value) {
        value = keccak256(abi.encode(entropy));
        if (value == original) value = bytes32(uint256(value) ^ 1);
    }

    function _differentAddress(bytes32 entropy, address original) internal pure returns (address value) {
        value = address(uint160(uint256(keccak256(abi.encode(entropy)))));
        if (value == original) value = address(uint160(value) ^ 1);
    }
}
