// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IMycoRewardToken {
    function mint(address to, uint256 amount) external;
    function burnFromTreasury(address treasury, uint256 amount) external;
}

contract MycoSettlementV2 {
    uint16 public constant BPS = 10_000;
    bytes32 public constant RECEIPT_TYPEHASH = keccak256(
        "Receipt(bytes32 receiptHash,bytes32 acceptedHash,bytes32 channel,address consumer,address provider,address relay,address pool,uint256 inputTokens,uint256 outputTokens,bytes32 pricingHash,uint256 deadline)"
    );
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant DELEGATE_TYPEHASH = keccak256(
        "SettlementDelegate(address account,address delegate,bytes32 receiptHash,bytes32 acceptedHash,bytes32 channel,address counterparty,uint256 grossFee,uint256 maxAmount,uint256 expiresAt,uint256 nonce)"
    );

    struct ChannelConfig {
        uint256 inputPer1K;
        uint256 outputPer1K;
        uint256 minimumFee;
        uint16 providerBps;
        uint16 relayBps;
        uint16 poolBps;
        uint16 treasuryBps;
        uint16 providerRewardBps;
        uint16 consumerRewardBps;
        uint256 rewardPerTreasuryUnit;
        bool active;
    }

    struct EconomicsConfig {
        uint256 epochSeconds;
        uint256 epochEmission;
        uint256 halvingIntervalEpochs;
        uint16 maxConsumerRebateBps;
    }

    struct Settlement {
        address consumer;
        address provider;
        address relay;
        address pool;
        bytes32 channel;
        uint256 grossFee;
        uint256 providerAmount;
        uint256 relayAmount;
        uint256 poolAmount;
        uint256 treasuryAmount;
        uint256 providerReward;
        uint256 consumerReward;
        uint256 settledAt;
    }

    struct ReceiptInput {
        bytes32 receiptHash;
        bytes32 acceptedHash;
        bytes32 channel;
        address consumer;
        address provider;
        address relay;
        address pool;
        uint256 inputTokens;
        uint256 outputTokens;
        bytes32 pricingHash;
        uint256 deadline;
    }

    struct SignatureInput {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct SignedReceiptInput {
        ReceiptInput receipt;
        SignatureInput consumerSignature;
        SignatureInput providerSignature;
        SignatureInput operatorSignature;
        bool operatorSigned;
    }

    IMycoERC20Like public immutable stablecoin;
    IMycoRewardToken public immutable rewardToken;
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 public constant MIN_GOVERNANCE_DELAY_SECONDS = 1 hours;
    address public owner;
    address public pendingOwner;
    address public treasury;
    uint256 public governanceDelaySeconds;

    mapping(address => bool) public operators;
    mapping(bytes32 => ChannelConfig) public channels;
    mapping(address => uint256) public prepaidBalance;
    mapping(bytes32 => Settlement) public settlements;
    mapping(uint256 => uint256) public epochMinted;
    mapping(address => mapping(address => bool)) public settlementDelegates;
    mapping(address => mapping(uint256 => bool)) public usedDelegateNonces;
    mapping(bytes32 => uint256) public governanceActionReadyAt;

    EconomicsConfig public economics;
    bool public trustedSettlementEnabled;
    bool private locked;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);
    event OperatorUpdated(address indexed operator, bool allowed);
    event TreasuryUpdated(address indexed treasury);
    event ChannelUpdated(bytes32 indexed channel);
    event EconomicsUpdated(uint256 epochSeconds, uint256 epochEmission, uint256 halvingIntervalEpochs);
    event GovernanceExecutorUpdated(address indexed previousExecutor, address indexed nextExecutor);
    event GovernanceExecutorProposed(address indexed previousExecutor, address indexed nextExecutor);
    event GovernanceDelayUpdated(uint256 delaySeconds);
    event GovernanceActionScheduled(bytes32 indexed actionHash, uint256 readyAt);
    event GovernanceActionConsumed(bytes32 indexed actionHash);
    event SettlementDelegateUpdated(address indexed account, address indexed delegate, bool allowed);
    event DelegateSettlementAuthorized(address indexed account, address indexed delegate, uint256 maxAmount, uint256 expiresAt, uint256 nonce);
    event TreasuryBuybackBurn(address indexed treasury, uint256 amount);
    event TrustedSettlementUpdated(bool enabled);
    event OwnershipTransferred(address indexed previousOwner, address indexed nextOwner);
    event ReceiptSettled(
        bytes32 indexed receiptHash,
        bytes32 indexed channel,
        address indexed consumer,
        address provider,
        uint256 grossFee,
        uint256 providerReward,
        uint256 consumerReward
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == owner, "not governance");
        _;
    }

    modifier governanceAction(bytes32 actionHash) {
        _consumeGovernanceAction(actionHash);
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "not operator");
        _;
    }

    modifier onlyTrustedSettlement() {
        require(trustedSettlementEnabled, "trusted settlement disabled");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    constructor(address stablecoin_, address rewardToken_, address treasury_) {
        require(stablecoin_ != address(0), "zero stablecoin");
        require(rewardToken_ != address(0), "zero reward");
        require(treasury_ != address(0), "zero treasury");
        stablecoin = IMycoERC20Like(stablecoin_);
        rewardToken = IMycoRewardToken(rewardToken_);
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("MycoMesh Settlement")),
                keccak256(bytes("2")),
                block.chainid,
                address(this)
            )
        );
        owner = msg.sender;
        treasury = treasury_;
        operators[msg.sender] = true;
        economics = EconomicsConfig({
            epochSeconds: 7 days,
            epochEmission: 1_000_000 ether,
            halvingIntervalEpochs: 210_000,
            maxConsumerRebateBps: 2_000
        });
        emit OwnershipTransferred(address(0), msg.sender);
        emit OperatorUpdated(msg.sender, true);
        emit TreasuryUpdated(treasury_);
    }

    function transferOwnership(address nextOwner) external onlyOwner {
        require(nextOwner != address(0), "zero owner");
        pendingOwner = nextOwner;
        emit GovernanceExecutorProposed(owner, nextOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        operators[owner] = true;
        emit OwnershipTransferred(previousOwner, owner);
        emit OperatorUpdated(owner, true);
    }

    function setOperator(address operator, bool allowed) external onlyOwner governanceAction(operatorActionHash(operator, allowed)) {
        operators[operator] = allowed;
        emit OperatorUpdated(operator, allowed);
    }

    function setGovernanceExecutor(address nextExecutor) external onlyOwner governanceAction(governanceExecutorActionHash(nextExecutor)) {
        require(nextExecutor != address(0), "zero governance");
        pendingOwner = nextExecutor;
        emit GovernanceExecutorUpdated(owner, nextExecutor);
        emit GovernanceExecutorProposed(owner, nextExecutor);
    }

    function setGovernanceDelay(uint256 delaySeconds) external onlyGovernance governanceAction(governanceDelayActionHash(delaySeconds)) {
        require(delaySeconds >= MIN_GOVERNANCE_DELAY_SECONDS, "delay too short");
        governanceDelaySeconds = delaySeconds;
        emit GovernanceDelayUpdated(delaySeconds);
    }

    function scheduleGovernanceAction(bytes32 actionHash) external onlyGovernance returns (uint256 readyAt) {
        require(actionHash != bytes32(0), "zero action");
        readyAt = block.timestamp + governanceDelaySeconds;
        governanceActionReadyAt[actionHash] = readyAt;
        emit GovernanceActionScheduled(actionHash, readyAt);
    }

    function treasuryActionHash(address nextTreasury) public pure returns (bytes32) {
        return keccak256(abi.encode("setTreasury", nextTreasury));
    }

    function operatorActionHash(address operator, bool allowed) public pure returns (bytes32) {
        return keccak256(abi.encode("setOperator", operator, allowed));
    }

    function governanceExecutorActionHash(address nextExecutor) public pure returns (bytes32) {
        return keccak256(abi.encode("setGovernanceExecutor", nextExecutor));
    }

    function governanceDelayActionHash(uint256 delaySeconds) public pure returns (bytes32) {
        return keccak256(abi.encode("setGovernanceDelay", delaySeconds));
    }

    function economicsActionHash(EconomicsConfig calldata config) public pure returns (bytes32) {
        return keccak256(abi.encode("setEconomics", config.epochSeconds, config.epochEmission, config.halvingIntervalEpochs, config.maxConsumerRebateBps));
    }

    function trustedSettlementActionHash(bool enabled) public pure returns (bytes32) {
        return keccak256(abi.encode("setTrustedSettlementEnabled", enabled));
    }

    function channelActionHash(bytes32 channel, ChannelConfig calldata config) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "setChannel",
                channel,
                config.inputPer1K,
                config.outputPer1K,
                config.minimumFee,
                config.providerBps,
                config.relayBps,
                config.poolBps,
                config.treasuryBps,
                config.providerRewardBps,
                config.consumerRewardBps,
                config.rewardPerTreasuryUnit,
                config.active
            )
        );
    }

    function buybackBurnActionHash(uint256 amount) public pure returns (bytes32) {
        return keccak256(abi.encode("treasuryBuybackBurn", amount));
    }

    function setTreasury(address nextTreasury) external onlyOwner governanceAction(treasuryActionHash(nextTreasury)) {
        require(nextTreasury != address(0), "zero treasury");
        treasury = nextTreasury;
        emit TreasuryUpdated(nextTreasury);
    }

    function setEconomics(EconomicsConfig calldata config) external onlyGovernance governanceAction(economicsActionHash(config)) {
        require(config.epochSeconds > 0, "zero epoch");
        require(config.maxConsumerRebateBps <= BPS, "bad rebate");
        economics = config;
        emit EconomicsUpdated(config.epochSeconds, config.epochEmission, config.halvingIntervalEpochs);
    }

    function setTrustedSettlementEnabled(bool enabled) external onlyGovernance governanceAction(trustedSettlementActionHash(enabled)) {
        trustedSettlementEnabled = enabled;
        emit TrustedSettlementUpdated(enabled);
    }

    function setChannel(bytes32 channel, ChannelConfig calldata config) external onlyGovernance governanceAction(channelActionHash(channel, config)) {
        require(channel != bytes32(0), "zero channel");
        require(
            uint256(config.providerBps) + config.relayBps + config.poolBps + config.treasuryBps == BPS,
            "bad split"
        );
        require(uint256(config.providerRewardBps) + config.consumerRewardBps == BPS, "bad rewards");
        channels[channel] = config;
        emit ChannelUpdated(channel);
    }

    function deposit(uint256 amount) external nonReentrant {
        require(amount > 0, "zero amount");
        require(stablecoin.transferFrom(msg.sender, address(this), amount), "pull failed");
        prepaidBalance[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "zero amount");
        require(prepaidBalance[msg.sender] >= amount, "balance");
        prepaidBalance[msg.sender] -= amount;
        require(stablecoin.transfer(msg.sender, amount), "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function setSettlementDelegate(address delegate, bool allowed) external {
        require(delegate != address(0), "zero delegate");
        settlementDelegates[msg.sender][delegate] = allowed;
        emit SettlementDelegateUpdated(msg.sender, delegate, allowed);
    }

    function treasuryBuybackBurn(uint256 amount) external onlyGovernance governanceAction(buybackBurnActionHash(amount)) {
        require(amount > 0, "zero amount");
        rewardToken.burnFromTreasury(treasury, amount);
        emit TreasuryBuybackBurn(treasury, amount);
    }

    function quote(bytes32 channel, uint256 inputTokens, uint256 outputTokens) public view returns (uint256) {
        ChannelConfig memory config = channels[channel];
        require(config.active, "inactive channel");
        uint256 usageFee = ((inputTokens * config.inputPer1K) + (outputTokens * config.outputPer1K)) / 1000;
        return usageFee < config.minimumFee ? config.minimumFee : usageFee;
    }

    function settleSignedReceiptFromBalance(SignedReceiptInput calldata input) public onlyOperator nonReentrant {
        _verifySignedReceipt(input);
        _settle(input.receipt);
    }

    function settleDelegatedReceiptFromBalance(
        SignedReceiptInput calldata input,
        SignatureInput calldata consumerDelegateSignature,
        SignatureInput calldata providerDelegateSignature,
        uint256 maxAmount,
        uint256 expiresAt,
        uint256 consumerNonce,
        uint256 providerNonce
    ) public onlyOperator nonReentrant {
        _verifyDelegatedReceipt(
            input,
            consumerDelegateSignature,
            providerDelegateSignature,
            maxAmount,
            expiresAt,
            consumerNonce,
            providerNonce
        );
        _settle(input.receipt);
    }

    function settleSignedBatchFromBalance(SignedReceiptInput[] calldata inputs) external onlyOperator nonReentrant {
        for (uint256 i = 0; i < inputs.length; i++) {
            _verifySignedReceipt(inputs[i]);
            _settle(inputs[i].receipt);
        }
    }

    function settleReceiptFromBalance(ReceiptInput calldata input) external onlyOperator onlyTrustedSettlement nonReentrant {
        _settle(input);
    }

    function settleBatchFromBalance(ReceiptInput[] calldata inputs) external onlyOperator onlyTrustedSettlement nonReentrant {
        for (uint256 i = 0; i < inputs.length; i++) {
            _settle(inputs[i]);
        }
    }

    function settleTrustedReceiptFromBalance(ReceiptInput calldata input) external onlyOperator onlyTrustedSettlement nonReentrant {
        _settle(input);
    }

    function settleTrustedBatchFromBalance(ReceiptInput[] calldata inputs) external onlyOperator onlyTrustedSettlement nonReentrant {
        for (uint256 i = 0; i < inputs.length; i++) {
            _settle(inputs[i]);
        }
    }

    function currentEpoch() public view returns (uint256) {
        return block.timestamp / economics.epochSeconds;
    }

    function currentEpochEmission() public view returns (uint256) {
        if (economics.halvingIntervalEpochs == 0) {
            return economics.epochEmission;
        }
        uint256 halvings = currentEpoch() / economics.halvingIntervalEpochs;
        if (halvings >= 64) {
            return 0;
        }
        return economics.epochEmission >> halvings;
    }

    function receiptDigest(ReceiptInput calldata input) public view returns (bytes32) {
        return _receiptDigest(input);
    }

    function receiptStructHash(ReceiptInput calldata input) public pure returns (bytes32) {
        return _receiptStructHash(input);
    }

    function delegateDigest(
        address account,
        address delegate,
        ReceiptInput calldata receipt,
        uint256 maxAmount,
        uint256 expiresAt,
        uint256 nonce
    ) public view returns (bytes32) {
        address counterparty = account == receipt.consumer ? receipt.provider : receipt.consumer;
        uint256 fee = quote(receipt.channel, receipt.inputTokens, receipt.outputTokens);
        bytes32 structHash = keccak256(
            abi.encode(
                DELEGATE_TYPEHASH,
                account,
                delegate,
                receipt.receiptHash,
                receipt.acceptedHash,
                receipt.channel,
                counterparty,
                fee,
                maxAmount,
                expiresAt,
                nonce
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function channelPricingHash(bytes32 channel) public view returns (bytes32) {
        return _channelPricingHash(channel);
    }

    function remainingEpochEmission(uint256 epoch) public view returns (uint256) {
        uint256 emission = epoch == currentEpoch() ? currentEpochEmission() : _epochEmission(epoch);
        uint256 minted = epochMinted[epoch];
        return minted >= emission ? 0 : emission - minted;
    }

    function _verifySignedReceipt(SignedReceiptInput calldata input) internal view {
        require(input.receipt.deadline == 0 || block.timestamp <= input.receipt.deadline, "receipt expired");
        require(input.receipt.acceptedHash != bytes32(0), "missing acceptance");
        require(input.receipt.pricingHash == _channelPricingHash(input.receipt.channel), "pricing hash");
        bytes32 digest = _receiptDigest(input.receipt);
        require(_recover(digest, input.consumerSignature) == input.receipt.consumer, "bad consumer signature");
        require(_recover(digest, input.providerSignature) == input.receipt.provider, "bad provider signature");
        if (input.operatorSigned) {
            address signer = _recover(digest, input.operatorSignature);
            require(operators[signer], "bad operator signature");
        }
    }

    function _verifyDelegatedReceipt(
        SignedReceiptInput calldata input,
        SignatureInput calldata consumerDelegateSignature,
        SignatureInput calldata providerDelegateSignature,
        uint256 maxAmount,
        uint256 expiresAt,
        uint256 consumerNonce,
        uint256 providerNonce
    ) internal {
        require(input.receipt.deadline == 0 || block.timestamp <= input.receipt.deadline, "receipt expired");
        require(input.receipt.acceptedHash != bytes32(0), "missing acceptance");
        require(input.receipt.pricingHash == _channelPricingHash(input.receipt.channel), "pricing hash");
        require(expiresAt == 0 || block.timestamp <= expiresAt, "delegate expired");
        uint256 fee = quote(input.receipt.channel, input.receipt.inputTokens, input.receipt.outputTokens);
        require(maxAmount == 0 || fee <= maxAmount, "delegate max");
        _consumeDelegateAuthorization(
            input.receipt.consumer,
            _recover(delegateDigest(input.receipt.consumer, msg.sender, input.receipt, maxAmount, expiresAt, consumerNonce), consumerDelegateSignature),
            maxAmount,
            expiresAt,
            consumerNonce
        );
        _consumeDelegateAuthorization(
            input.receipt.provider,
            _recover(delegateDigest(input.receipt.provider, msg.sender, input.receipt, maxAmount, expiresAt, providerNonce), providerDelegateSignature),
            maxAmount,
            expiresAt,
            providerNonce
        );
        if (input.operatorSigned) {
            address signer = _recover(_receiptDigest(input.receipt), input.operatorSignature);
            require(operators[signer], "bad operator signature");
        }
    }

    function _consumeDelegateAuthorization(
        address account,
        address recovered,
        uint256 maxAmount,
        uint256 expiresAt,
        uint256 nonce
    ) internal {
        require(recovered == account, "bad delegate signature");
        require(settlementDelegates[account][msg.sender], "delegate not allowed");
        require(!usedDelegateNonces[account][nonce], "delegate nonce used");
        usedDelegateNonces[account][nonce] = true;
        emit DelegateSettlementAuthorized(account, msg.sender, maxAmount, expiresAt, nonce);
    }

    function _settle(ReceiptInput calldata input) internal {
        require(input.receiptHash != bytes32(0), "zero receipt");
        require(settlements[input.receiptHash].settledAt == 0, "settled");
        require(input.consumer != address(0), "zero consumer");
        require(input.provider != address(0), "zero provider");
        require(input.pricingHash == bytes32(0) || input.pricingHash == _channelPricingHash(input.channel), "pricing hash");

        ChannelConfig memory config = channels[input.channel];
        require(config.active, "inactive channel");

        Settlement memory item = Settlement({
            consumer: input.consumer,
            provider: input.provider,
            relay: input.relay,
            pool: input.pool,
            channel: input.channel,
            grossFee: quote(input.channel, input.inputTokens, input.outputTokens),
            providerAmount: 0,
            relayAmount: 0,
            poolAmount: 0,
            treasuryAmount: 0,
            providerReward: 0,
            consumerReward: 0,
            settledAt: block.timestamp
        });
        require(prepaidBalance[input.consumer] >= item.grossFee, "prepaid balance");
        prepaidBalance[input.consumer] -= item.grossFee;

        item.providerAmount = (item.grossFee * config.providerBps) / BPS;
        item.relayAmount = (item.grossFee * config.relayBps) / BPS;
        item.poolAmount = (item.grossFee * config.poolBps) / BPS;
        item.treasuryAmount = item.grossFee - item.providerAmount - item.relayAmount - item.poolAmount;

        require(stablecoin.transfer(input.provider, item.providerAmount), "provider transfer failed");
        if (input.relay != address(0) && item.relayAmount > 0) {
            require(stablecoin.transfer(input.relay, item.relayAmount), "relay transfer failed");
        } else {
            item.treasuryAmount += item.relayAmount;
            item.relayAmount = 0;
        }
        if (input.pool != address(0) && item.poolAmount > 0) {
            require(stablecoin.transfer(input.pool, item.poolAmount), "pool transfer failed");
        } else {
            item.treasuryAmount += item.poolAmount;
            item.poolAmount = 0;
        }
        require(stablecoin.transfer(treasury, item.treasuryAmount), "treasury transfer failed");

        uint256 totalReward = _consumeRewardEmission(item.treasuryAmount * config.rewardPerTreasuryUnit);
        item.providerReward = (totalReward * config.providerRewardBps) / BPS;
        item.consumerReward = totalReward - item.providerReward;
        if (item.providerReward > 0) {
            rewardToken.mint(input.provider, item.providerReward);
        }
        if (item.consumerReward > 0) {
            rewardToken.mint(input.consumer, item.consumerReward);
        }

        settlements[input.receiptHash] = item;

        emit ReceiptSettled(
            input.receiptHash,
            input.channel,
            input.consumer,
            input.provider,
            item.grossFee,
            item.providerReward,
            item.consumerReward
        );
    }

    function _consumeRewardEmission(uint256 requested) internal returns (uint256) {
        if (requested == 0) {
            return 0;
        }
        uint256 epoch = currentEpoch();
        uint256 cap = _epochEmission(epoch);
        if (cap == 0) {
            return 0;
        }
        uint256 minted = epochMinted[epoch];
        if (minted >= cap) {
            return 0;
        }
        uint256 available = cap - minted;
        uint256 amount = requested > available ? available : requested;
        epochMinted[epoch] = minted + amount;
        return amount;
    }

    function _epochEmission(uint256 epoch) internal view returns (uint256) {
        if (economics.halvingIntervalEpochs == 0) {
            return economics.epochEmission;
        }
        uint256 halvings = epoch / economics.halvingIntervalEpochs;
        if (halvings >= 64) {
            return 0;
        }
        return economics.epochEmission >> halvings;
    }

    function _receiptDigest(ReceiptInput calldata input) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _receiptStructHash(input)));
    }

    function _receiptStructHash(ReceiptInput calldata input) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                RECEIPT_TYPEHASH,
                input.receiptHash,
                input.acceptedHash,
                input.channel,
                input.consumer,
                input.provider,
                input.relay,
                input.pool,
                input.inputTokens,
                input.outputTokens,
                input.pricingHash,
                input.deadline
            )
        );
    }

    function _channelPricingHash(bytes32 channel) internal view returns (bytes32) {
        ChannelConfig memory config = channels[channel];
        return keccak256(
            abi.encode(
                channel,
                config.inputPer1K,
                config.outputPer1K,
                config.minimumFee,
                config.providerBps,
                config.relayBps,
                config.poolBps,
                config.treasuryBps,
                config.providerRewardBps,
                config.consumerRewardBps,
                config.rewardPerTreasuryUnit,
                config.active
            )
        );
    }

    function _consumeGovernanceAction(bytes32 actionHash) internal {
        if (governanceDelaySeconds == 0) {
            return;
        }
        uint256 readyAt = governanceActionReadyAt[actionHash];
        require(readyAt != 0, "governance action not scheduled");
        require(block.timestamp >= readyAt, "governance action pending");
        delete governanceActionReadyAt[actionHash];
        emit GovernanceActionConsumed(actionHash);
    }

    function _recover(bytes32 digest, SignatureInput calldata signature) internal pure returns (address) {
        bytes32 r = signature.r;
        bytes32 s = signature.s;
        uint8 v = signature.v;
        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "bad signature v");
        require(uint256(s) <= SECP256K1_HALF_ORDER, "bad signature s");
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "bad signature");
        return recovered;
    }
}
