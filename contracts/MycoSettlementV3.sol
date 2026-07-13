// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoERC20V3 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IMycoRewardTokenV3 {
    function mint(address to, uint256 amount) external;
}

interface IERC1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);
}

/// @notice Myco settlement with payment reservations, immutable pricing versions and permissionless receipt submission.
/// @dev Governance should be a multisig. Risk-increasing changes are delayed; reward issuance can be paused immediately.
contract MycoSettlementV3 {
    uint16 public constant BPS = 10_000;
    uint8 public constant ROLE_CONSUMER = 1;
    uint8 public constant ROLE_PROVIDER = 2;
    uint256 public constant GOVERNANCE_DELAY_SECONDS = 2 days;
    uint256 public constant MAX_RESERVATION_DURATION = 30 days;
    uint256 public constant MAX_BATCH_SIZE = 32;
    uint256 public constant EPOCH_SECONDS = 7 days;
    uint256 public constant EPOCH_EMISSION = 1_000_000 ether;
    uint256 public constant HALVING_INTERVAL_EPOCHS = 208;

    bytes4 private constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant RECEIPT_TYPEHASH = keccak256(
        "Receipt(bytes32 receiptHash,bytes32 acceptedHash,bytes32 reservationId,bytes32 requestHash,bytes32 responseHash,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,address consumer,address provider,address relay,address pool,uint256 inputTokens,uint256 outputTokens,uint256 deadline)"
    );
    bytes32 public constant DELEGATE_TYPEHASH = keccak256(
        "DelegateAuthorization(bytes32 receiptStructHash,address account,address delegate,uint8 role,uint256 maxAmount,uint256 expiresAt,uint256 nonce)"
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

    struct ChannelVersion {
        ChannelConfig config;
        address treasury;
        bytes32 pricingHash;
    }

    struct ReceiptInput {
        bytes32 receiptHash;
        bytes32 acceptedHash;
        bytes32 reservationId;
        bytes32 requestHash;
        bytes32 responseHash;
        bytes32 channel;
        uint64 pricingVersion;
        bytes32 pricingHash;
        address consumer;
        address provider;
        address relay;
        address pool;
        uint256 inputTokens;
        uint256 outputTokens;
        uint256 deadline;
    }

    struct SignedReceiptInput {
        ReceiptInput receipt;
        bytes consumerSignature;
        bytes providerSignature;
    }

    struct DelegateAuthorizationInput {
        uint256 maxAmount;
        uint256 expiresAt;
        uint256 nonce;
        bytes signature;
    }

    struct DelegatedReceiptInput {
        ReceiptInput receipt;
        DelegateAuthorizationInput consumerAuthorization;
        DelegateAuthorizationInput providerAuthorization;
    }

    struct Reservation {
        address consumer;
        address provider;
        bytes32 channel;
        bytes32 requestHash;
        uint64 pricingVersion;
        uint64 expiresAt;
        uint256 amount;
        bool closed;
        bool providerFallbackAllowed;
    }

    struct Settlement {
        bytes32 reservationId;
        address consumer;
        address provider;
        address relay;
        address pool;
        bytes32 channel;
        uint64 pricingVersion;
        uint256 grossFee;
        uint256 providerAmount;
        uint256 relayAmount;
        uint256 poolAmount;
        uint256 treasuryAmount;
        uint256 providerReward;
        uint256 consumerReward;
        uint256 settledAt;
        bool providerFallback;
    }

    IMycoERC20V3 public immutable stablecoin;
    IMycoRewardTokenV3 public immutable rewardToken;
    uint16 public immutable maxConsumerRebateBps;
    uint256 public immutable emissionStartedAt;
    uint256 private immutable _initialChainId;
    bytes32 private immutable _initialDomainSeparator;

    address public governance;
    address public pendingGovernance;
    uint256 public pendingGovernanceReadyAt;
    address public treasury;
    bool public rewardsEnabled;

    mapping(bytes32 => uint256) public governanceActionReadyAt;
    mapping(bytes32 => uint64) public latestChannelVersion;
    mapping(bytes32 => mapping(uint64 => ChannelVersion)) public channelVersions;
    mapping(address => uint256) public availableBalance;
    mapping(address => uint256) public lockedBalance;
    mapping(bytes32 => Reservation) public reservations;
    mapping(bytes32 => Settlement) private _settlements;
    mapping(bytes32 => bool) public settlementKeySettled;
    mapping(address => mapping(uint256 => bool)) public usedDelegateNonces;
    mapping(uint256 => uint256) public epochMinted;

    bool private entered;

    event Deposited(address indexed account, uint256 requestedAmount, uint256 receivedAmount);
    event Withdrawn(address indexed account, uint256 amount);
    event ReservationCreated(
        bytes32 indexed reservationId,
        address indexed consumer,
        address indexed provider,
        bytes32 channel,
        bytes32 requestHash,
        uint64 pricingVersion,
        uint256 amount,
        uint256 expiresAt,
        bool providerFallbackAllowed
    );
    event ReservationReleased(bytes32 indexed reservationId, address indexed consumer, uint256 amount);
    event ReceiptSettled(
        bytes32 indexed receiptHash,
        bytes32 indexed reservationId,
        address indexed consumer,
        address provider,
        uint256 grossFee
    );
    event ChannelVersionAdded(bytes32 indexed channel, uint64 indexed version, bytes32 pricingHash, bool active);
    event TreasuryUpdated(address indexed previousTreasury, address indexed nextTreasury);
    event GovernanceActionScheduled(bytes32 indexed actionHash, uint256 readyAt);
    event GovernanceActionCancelled(bytes32 indexed actionHash);
    event GovernanceActionConsumed(bytes32 indexed actionHash);
    event TreasuryUpdateScheduled(address indexed nextTreasury, bytes32 indexed actionHash, uint256 readyAt);
    event ChannelVersionScheduled(
        bytes32 indexed channel,
        uint64 indexed version,
        bytes32 indexed actionHash,
        ChannelConfig config,
        uint256 readyAt
    );
    event RewardEnableScheduled(bytes32 indexed actionHash, uint256 readyAt);
    event RewardsEnabled();
    event RewardsPaused();
    event GovernanceTransferStarted(
        address indexed previousGovernance, address indexed nextGovernance, uint256 readyAt
    );
    event GovernanceTransferred(address indexed previousGovernance, address indexed nextGovernance);
    event DelegateAuthorizationUsed(
        address indexed account, address indexed delegate, uint8 indexed role, uint256 nonce, bytes32 receiptStructHash
    );
    event RewardMintFailed(address indexed recipient, uint256 amount);
    event ProviderFallbackSettled(
        bytes32 indexed receiptHash,
        bytes32 indexed reservationId,
        address indexed consumer,
        address provider,
        uint256 grossFee,
        uint256 providerAmount,
        uint256 treasuryAmount
    );

    modifier onlyGovernance() {
        require(msg.sender == governance, "not governance");
        _;
    }

    modifier nonReentrant() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    modifier consumesGovernanceAction(bytes32 actionHash) {
        _consumeGovernanceAction(actionHash);
        _;
    }

    constructor(
        address stablecoin_,
        address rewardToken_,
        address treasury_,
        address governance_,
        uint16 maxConsumerRebateBps_,
        bytes32 initialChannel_,
        ChannelConfig memory initialConfig_
    ) {
        require(stablecoin_ != address(0), "zero stablecoin");
        require(stablecoin_.code.length > 0, "stablecoin not contract");
        require(rewardToken_ != address(0), "zero reward");
        require(treasury_ != address(0), "zero treasury");
        require(treasury_ != address(this), "treasury is settlement");
        require(governance_ != address(0), "zero governance");
        require(maxConsumerRebateBps_ <= BPS, "bad rebate");
        require(initialChannel_ != bytes32(0), "zero initial channel");
        require(initialConfig_.active, "inactive initial channel");

        stablecoin = IMycoERC20V3(stablecoin_);
        rewardToken = IMycoRewardTokenV3(rewardToken_);
        treasury = treasury_;
        governance = governance_;
        maxConsumerRebateBps = maxConsumerRebateBps_;
        emissionStartedAt = block.timestamp;
        _validateChannelConfig(initialConfig_);

        bytes32 initialPricingHash = _channelPricingHash(initialChannel_, 1, treasury_, initialConfig_);
        channelVersions[initialChannel_][1] =
            ChannelVersion({config: initialConfig_, treasury: treasury_, pricingHash: initialPricingHash});
        latestChannelVersion[initialChannel_] = 1;
        _initialChainId = block.chainid;
        _initialDomainSeparator = _buildDomainSeparator();

        emit TreasuryUpdated(address(0), treasury_);
        emit GovernanceTransferred(address(0), governance_);
        emit ChannelVersionAdded(initialChannel_, 1, initialPricingHash, true);
    }

    // -------------------------------------------------------------------------
    // Timelocked governance
    // -------------------------------------------------------------------------

    function scheduleTreasuryUpdate(address nextTreasury)
        external
        onlyGovernance
        returns (bytes32 actionHash, uint256 readyAt)
    {
        require(nextTreasury != address(0), "zero treasury");
        require(nextTreasury != address(this), "treasury is settlement");
        actionHash = treasuryActionHash(nextTreasury);
        readyAt = _scheduleGovernanceAction(actionHash);
        emit TreasuryUpdateScheduled(nextTreasury, actionHash, readyAt);
    }

    function scheduleChannelVersion(bytes32 channel, ChannelConfig calldata config)
        external
        onlyGovernance
        returns (bytes32 actionHash, uint256 readyAt)
    {
        require(channel != bytes32(0), "zero channel");
        _validateChannelConfig(config);
        uint64 nextVersion = latestChannelVersion[channel] + 1;
        actionHash = channelActionHash(channel, config);
        readyAt = _scheduleGovernanceAction(actionHash);
        emit ChannelVersionScheduled(channel, nextVersion, actionHash, config, readyAt);
    }

    function scheduleRewardEnable() external onlyGovernance returns (bytes32 actionHash, uint256 readyAt) {
        require(!rewardsEnabled, "rewards enabled");
        actionHash = rewardEnableActionHash();
        readyAt = _scheduleGovernanceAction(actionHash);
        emit RewardEnableScheduled(actionHash, readyAt);
    }

    function cancelGovernanceAction(bytes32 actionHash) external onlyGovernance {
        require(governanceActionReadyAt[actionHash] != 0, "action not scheduled");
        delete governanceActionReadyAt[actionHash];
        emit GovernanceActionCancelled(actionHash);
    }

    function treasuryActionHash(address nextTreasury) public pure returns (bytes32) {
        return keccak256(abi.encode("setTreasury", nextTreasury));
    }

    function rewardEnableActionHash() public pure returns (bytes32) {
        return keccak256(abi.encode("enableRewards"));
    }

    function channelActionHash(bytes32 channel, ChannelConfig calldata config) public view returns (bytes32) {
        uint64 nextVersion = latestChannelVersion[channel] + 1;
        return keccak256(abi.encode("addChannelVersion", channel, nextVersion, treasury, config));
    }

    function setTreasury(address nextTreasury)
        external
        onlyGovernance
        consumesGovernanceAction(treasuryActionHash(nextTreasury))
    {
        require(nextTreasury != address(0), "zero treasury");
        require(nextTreasury != address(this), "treasury is settlement");
        address previousTreasury = treasury;
        treasury = nextTreasury;
        emit TreasuryUpdated(previousTreasury, nextTreasury);
    }

    /// @notice Adds an immutable pricing version. Existing versions can still settle existing reservations.
    function addChannelVersion(bytes32 channel, ChannelConfig calldata config)
        external
        onlyGovernance
        consumesGovernanceAction(channelActionHash(channel, config))
        returns (uint64 version)
    {
        require(channel != bytes32(0), "zero channel");
        _validateChannelConfig(config);
        version = latestChannelVersion[channel] + 1;
        bytes32 pricingHash = _channelPricingHash(channel, version, treasury, config);
        channelVersions[channel][version] =
            ChannelVersion({config: config, treasury: treasury, pricingHash: pricingHash});
        latestChannelVersion[channel] = version;
        emit ChannelVersionAdded(channel, version, pricingHash, config.active);
    }

    function enableRewards() external onlyGovernance consumesGovernanceAction(rewardEnableActionHash()) {
        require(!rewardsEnabled, "rewards enabled");
        rewardsEnabled = true;
        emit RewardsEnabled();
    }

    /// @notice Reward issuance can always be stopped immediately; enabling it again requires a fresh delay.
    function pauseRewards() external onlyGovernance {
        rewardsEnabled = false;
        bytes32 actionHash = rewardEnableActionHash();
        if (governanceActionReadyAt[actionHash] != 0) {
            delete governanceActionReadyAt[actionHash];
            emit GovernanceActionCancelled(actionHash);
        }
        emit RewardsPaused();
    }

    function beginGovernanceTransfer(address nextGovernance) external onlyGovernance {
        require(nextGovernance != address(0), "zero governance");
        require(nextGovernance != governance, "same governance");
        pendingGovernance = nextGovernance;
        pendingGovernanceReadyAt = block.timestamp + GOVERNANCE_DELAY_SECONDS;
        emit GovernanceTransferStarted(governance, nextGovernance, pendingGovernanceReadyAt);
    }

    function cancelGovernanceTransfer() external onlyGovernance {
        pendingGovernance = address(0);
        pendingGovernanceReadyAt = 0;
    }

    function acceptGovernance() external {
        require(msg.sender == pendingGovernance, "not pending governance");
        require(block.timestamp >= pendingGovernanceReadyAt, "governance transfer pending");
        address previousGovernance = governance;
        governance = pendingGovernance;
        pendingGovernance = address(0);
        pendingGovernanceReadyAt = 0;
        emit GovernanceTransferred(previousGovernance, governance);
    }

    // -------------------------------------------------------------------------
    // Deposits and payment reservations
    // -------------------------------------------------------------------------

    /// @notice Only standard, non-rebasing ERC-20 transfers with exact balance deltas are supported.
    function deposit(uint256 amount) external nonReentrant returns (uint256 received) {
        require(amount > 0, "zero amount");
        uint256 beforeBalance = _tokenBalance(address(this));
        _safeTransferFrom(msg.sender, address(this), amount);
        uint256 afterBalance = _tokenBalance(address(this));
        require(afterBalance == beforeBalance + amount, "unsupported token behavior");
        received = afterBalance - beforeBalance;
        availableBalance[msg.sender] += received;
        emit Deposited(msg.sender, amount, received);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "zero amount");
        require(availableBalance[msg.sender] >= amount, "available balance");
        availableBalance[msg.sender] -= amount;
        _safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    function prepaidBalance(address account) external view returns (uint256) {
        return availableBalance[account] + lockedBalance[account];
    }

    function settlementKeyFor(bytes32 reservationId, bytes32 receiptHash) public pure returns (bytes32) {
        return keccak256(abi.encode(reservationId, receiptHash));
    }

    function receiptSettled(bytes32 reservationId, bytes32 receiptHash) external view returns (bool) {
        return settlementKeySettled[settlementKeyFor(reservationId, receiptHash)];
    }

    function settlement(bytes32 reservationId, bytes32 receiptHash) external view returns (Settlement memory) {
        return _settlements[settlementKeyFor(reservationId, receiptHash)];
    }

    /// @notice Returns the canonical reservation id for a consumer-owned salt.
    /// @dev Binding the id to this deployment, chain and consumer prevents copied mempool salts from blocking users.
    function reservationIdFor(address consumer, bytes32 reservationSalt) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), block.chainid, consumer, reservationSalt));
    }

    function createReservation(
        bytes32 reservationSalt,
        address provider,
        bytes32 channel,
        bytes32 requestHash,
        uint64 pricingVersion,
        uint256 amount,
        uint64 expiresAt,
        bool providerFallbackAllowed
    ) external returns (bytes32 reservationId) {
        require(reservationSalt != bytes32(0), "zero reservation salt");
        reservationId = reservationIdFor(msg.sender, reservationSalt);
        require(reservations[reservationId].consumer == address(0), "reservation exists");
        require(provider != address(0), "zero provider");
        require(provider != msg.sender, "same party");
        require(provider != address(this), "provider is settlement");
        require(requestHash != bytes32(0), "zero request hash");
        require(amount > 0, "zero amount");
        require(expiresAt > block.timestamp, "bad expiry");
        require(expiresAt <= block.timestamp + MAX_RESERVATION_DURATION, "expiry too long");
        require(pricingVersion != 0 && pricingVersion == latestChannelVersion[channel], "not latest pricing");
        ChannelConfig storage config = channelVersions[channel][pricingVersion].config;
        require(config.active, "inactive channel");
        require(amount >= config.minimumFee, "below minimum fee");
        require(availableBalance[msg.sender] >= amount, "available balance");

        availableBalance[msg.sender] -= amount;
        lockedBalance[msg.sender] += amount;
        reservations[reservationId] = Reservation({
            consumer: msg.sender,
            provider: provider,
            channel: channel,
            requestHash: requestHash,
            pricingVersion: pricingVersion,
            expiresAt: expiresAt,
            amount: amount,
            closed: false,
            providerFallbackAllowed: providerFallbackAllowed
        });
        emit ReservationCreated(
            reservationId,
            msg.sender,
            provider,
            channel,
            requestHash,
            pricingVersion,
            amount,
            expiresAt,
            providerFallbackAllowed
        );
    }

    /// @notice Anyone can release an unused reservation after expiry; funds always return to its consumer.
    function releaseExpiredReservation(bytes32 reservationId) external {
        Reservation storage reservation = reservations[reservationId];
        require(reservation.consumer != address(0), "unknown reservation");
        require(!reservation.closed, "reservation closed");
        require(block.timestamp > reservation.expiresAt, "reservation active");

        reservation.closed = true;
        lockedBalance[reservation.consumer] -= reservation.amount;
        availableBalance[reservation.consumer] += reservation.amount;
        emit ReservationReleased(reservationId, reservation.consumer, reservation.amount);
    }

    // -------------------------------------------------------------------------
    // Permissionless signed settlement
    // -------------------------------------------------------------------------

    function settleSignedReceipt(SignedReceiptInput calldata input) external nonReentrant {
        _settleSignedReceipt(input);
    }

    function settleSignedBatch(SignedReceiptInput[] calldata inputs) external nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE, "bad batch length");
        for (uint256 i = 0; i < inputs.length; ++i) {
            _settleSignedReceipt(inputs[i]);
        }
    }

    function settleDelegatedReceipt(DelegatedReceiptInput calldata input) external nonReentrant {
        _settleDelegatedReceipt(input);
    }

    function settleDelegatedBatch(DelegatedReceiptInput[] calldata inputs) external nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE, "bad batch length");
        for (uint256 i = 0; i < inputs.length; ++i) {
            _settleDelegatedReceipt(inputs[i]);
        }
    }

    /// @notice Claims the minimum fee only when the consumer explicitly opted in while creating the reservation.
    /// @dev The provider must sign a request-bound, unaccepted receipt. Relay/pool payments and rewards are disabled.
    function settleProviderFallback(ReceiptInput calldata receipt, bytes calldata providerSignature)
        external
        nonReentrant
    {
        uint256 grossFee = _validateReceipt(receipt, true);
        bytes32 digest = _toTypedDataHash(receiptStructHash(receipt));
        require(_isValidSignature(receipt.provider, digest, providerSignature), "bad provider signature");
        _settle(receipt, grossFee, true);
    }

    function receiptStructHash(ReceiptInput calldata receipt) public pure returns (bytes32) {
        return keccak256(abi.encode(RECEIPT_TYPEHASH, receipt));
    }

    function receiptDigest(ReceiptInput calldata receipt) public view returns (bytes32) {
        return _toTypedDataHash(receiptStructHash(receipt));
    }

    function delegateDigest(
        ReceiptInput calldata receipt,
        address account,
        address delegate,
        uint8 role,
        uint256 maxAmount,
        uint256 expiresAt,
        uint256 nonce
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                DELEGATE_TYPEHASH, receiptStructHash(receipt), account, delegate, role, maxAmount, expiresAt, nonce
            )
        );
        return _toTypedDataHash(structHash);
    }

    function quote(bytes32 channel, uint64 pricingVersion, uint256 inputTokens, uint256 outputTokens)
        public
        view
        returns (uint256)
    {
        ChannelVersion storage version = channelVersions[channel][pricingVersion];
        require(pricingVersion != 0 && version.pricingHash != bytes32(0), "unknown pricing");
        ChannelConfig storage config = version.config;
        uint256 usageFee = _quoteUsageFee(inputTokens, config.inputPer1K, outputTokens, config.outputPer1K);
        return usageFee < config.minimumFee ? config.minimumFee : usageFee;
    }

    function channelPricingHash(bytes32 channel, uint64 pricingVersion) external view returns (bytes32) {
        return channelVersions[channel][pricingVersion].pricingHash;
    }

    function currentEpoch() public view returns (uint256) {
        return (block.timestamp - emissionStartedAt) / EPOCH_SECONDS;
    }

    function currentEpochEmission() public view returns (uint256) {
        return _epochEmission(currentEpoch());
    }

    function remainingEpochEmission(uint256 epoch) external view returns (uint256) {
        uint256 emission = _epochEmission(epoch);
        uint256 minted = epochMinted[epoch];
        return minted >= emission ? 0 : emission - minted;
    }

    function _settleSignedReceipt(SignedReceiptInput calldata input) internal {
        uint256 grossFee = _validateReceipt(input.receipt, false);
        bytes32 digest = _toTypedDataHash(receiptStructHash(input.receipt));
        require(_isValidSignature(input.receipt.consumer, digest, input.consumerSignature), "bad consumer signature");
        require(_isValidSignature(input.receipt.provider, digest, input.providerSignature), "bad provider signature");
        _settle(input.receipt, grossFee, false);
    }

    function _settleDelegatedReceipt(DelegatedReceiptInput calldata input) internal {
        uint256 grossFee = _validateReceipt(input.receipt, false);
        _verifyDelegateAuthorization(
            input.receipt, input.receipt.consumer, ROLE_CONSUMER, grossFee, input.consumerAuthorization
        );
        _verifyDelegateAuthorization(
            input.receipt, input.receipt.provider, ROLE_PROVIDER, grossFee, input.providerAuthorization
        );
        _settle(input.receipt, grossFee, false);
    }

    function _verifyDelegateAuthorization(
        ReceiptInput calldata receipt,
        address account,
        uint8 role,
        uint256 grossFee,
        DelegateAuthorizationInput calldata authorization
    ) internal {
        require(authorization.expiresAt != 0 && block.timestamp <= authorization.expiresAt, "delegate expired");
        require(grossFee <= authorization.maxAmount, "delegate max");
        require(!usedDelegateNonces[account][authorization.nonce], "delegate nonce used");
        bytes32 digest = delegateDigest(
            receipt, account, msg.sender, role, authorization.maxAmount, authorization.expiresAt, authorization.nonce
        );
        require(_isValidSignature(account, digest, authorization.signature), "bad delegate signature");
        usedDelegateNonces[account][authorization.nonce] = true;
        emit DelegateAuthorizationUsed(account, msg.sender, role, authorization.nonce, receiptStructHash(receipt));
    }

    function _validateReceipt(ReceiptInput calldata receipt, bool providerFallback)
        internal
        view
        returns (uint256 grossFee)
    {
        require(receipt.receiptHash != bytes32(0), "zero receipt");
        bytes32 settlementKey = settlementKeyFor(receipt.reservationId, receipt.receiptHash);
        require(!settlementKeySettled[settlementKey], "receipt settled");
        if (providerFallback) require(receipt.acceptedHash == bytes32(0), "unexpected acceptance");
        else require(receipt.acceptedHash != bytes32(0), "missing acceptance");
        require(receipt.requestHash != bytes32(0), "missing request");
        require(receipt.responseHash != bytes32(0), "missing response");
        require(receipt.consumer != address(0) && receipt.provider != address(0), "zero party");
        require(receipt.consumer != receipt.provider, "same party");
        require(receipt.deadline != 0 && block.timestamp <= receipt.deadline, "receipt expired");

        Reservation storage reservation = reservations[receipt.reservationId];
        require(reservation.consumer != address(0), "unknown reservation");
        require(!reservation.closed, "reservation closed");
        require(block.timestamp <= reservation.expiresAt, "reservation expired");
        require(receipt.deadline <= reservation.expiresAt, "deadline after reservation");
        require(reservation.consumer == receipt.consumer, "reservation consumer");
        require(reservation.provider == receipt.provider, "reservation provider");
        require(reservation.channel == receipt.channel, "reservation channel");
        require(reservation.requestHash == receipt.requestHash, "reservation request");
        require(reservation.pricingVersion == receipt.pricingVersion, "reservation pricing");
        if (providerFallback) require(reservation.providerFallbackAllowed, "fallback not allowed");

        ChannelVersion storage version = channelVersions[receipt.channel][receipt.pricingVersion];
        require(version.pricingHash != bytes32(0), "unknown pricing");
        require(receipt.pricingHash == version.pricingHash, "pricing hash");
        grossFee = providerFallback
            ? version.config.minimumFee
            : quote(receipt.channel, receipt.pricingVersion, receipt.inputTokens, receipt.outputTokens);
        require(grossFee <= reservation.amount, "reservation amount");
    }

    function _settle(ReceiptInput calldata receipt, uint256 grossFee, bool providerFallback) internal {
        Reservation storage reservation = reservations[receipt.reservationId];
        ChannelVersion storage version = channelVersions[receipt.channel][receipt.pricingVersion];
        ChannelConfig storage config = version.config;

        uint256 providerAmount = _bpsAmount(grossFee, config.providerBps);
        uint256 relayAmount;
        uint256 poolAmount;
        uint256 treasuryAmount;
        if (providerFallback) {
            treasuryAmount = grossFee - providerAmount;
        } else {
            relayAmount = _bpsAmount(grossFee, config.relayBps);
            poolAmount = _bpsAmount(grossFee, config.poolBps);
            treasuryAmount = grossFee - providerAmount - relayAmount - poolAmount;
            if (receipt.relay == address(0)) {
                treasuryAmount += relayAmount;
                relayAmount = 0;
            }
            if (receipt.pool == address(0)) {
                treasuryAmount += poolAmount;
                poolAmount = 0;
            }
        }

        reservation.closed = true;
        bytes32 settlementKey = settlementKeyFor(receipt.reservationId, receipt.receiptHash);
        settlementKeySettled[settlementKey] = true;
        lockedBalance[receipt.consumer] -= reservation.amount;
        availableBalance[receipt.consumer] += reservation.amount - grossFee;

        Settlement storage item = _settlements[settlementKey];
        item.reservationId = receipt.reservationId;
        item.consumer = receipt.consumer;
        item.provider = receipt.provider;
        item.relay = providerFallback ? address(0) : receipt.relay;
        item.pool = providerFallback ? address(0) : receipt.pool;
        item.channel = receipt.channel;
        item.pricingVersion = receipt.pricingVersion;
        item.grossFee = grossFee;
        item.providerAmount = providerAmount;
        item.relayAmount = relayAmount;
        item.poolAmount = poolAmount;
        item.treasuryAmount = treasuryAmount;
        item.settledAt = block.timestamp;
        item.providerFallback = providerFallback;

        _safeTransfer(receipt.provider, providerAmount);
        if (relayAmount > 0) _safeTransfer(receipt.relay, relayAmount);
        if (poolAmount > 0) _safeTransfer(receipt.pool, poolAmount);
        _safeTransfer(version.treasury, treasuryAmount);

        if (!providerFallback) _mintRewards(receipt.provider, receipt.consumer, item, treasuryAmount, config);

        emit ReceiptSettled(receipt.receiptHash, receipt.reservationId, receipt.consumer, receipt.provider, grossFee);
        if (providerFallback) {
            emit ProviderFallbackSettled(
                receipt.receiptHash,
                receipt.reservationId,
                receipt.consumer,
                receipt.provider,
                grossFee,
                providerAmount,
                treasuryAmount
            );
        }
    }

    function _mintRewards(
        address provider,
        address consumer,
        Settlement storage item,
        uint256 treasuryAmount,
        ChannelConfig storage config
    ) internal {
        if (!rewardsEnabled) return;
        uint256 epoch = currentEpoch();
        uint256 cap = _epochEmission(epoch);
        uint256 minted = epochMinted[epoch];
        if (minted >= cap) return;
        uint256 requested = _saturatingMultiply(treasuryAmount, config.rewardPerTreasuryUnit);
        uint256 available = cap - minted;
        uint256 totalReward = requested > available ? available : requested;
        uint256 providerReward = _bpsAmount(totalReward, config.providerRewardBps);
        uint256 consumerReward = totalReward - providerReward;
        if (address(rewardToken).code.length == 0) {
            if (providerReward > 0) emit RewardMintFailed(provider, providerReward);
            if (consumerReward > 0) emit RewardMintFailed(consumer, consumerReward);
            return;
        }
        if (providerReward > 0) {
            try rewardToken.mint(provider, providerReward) {
                item.providerReward = providerReward;
                epochMinted[epoch] += providerReward;
            } catch {
                emit RewardMintFailed(provider, providerReward);
            }
        }
        if (consumerReward > 0) {
            try rewardToken.mint(consumer, consumerReward) {
                item.consumerReward = consumerReward;
                epochMinted[epoch] += consumerReward;
            } catch {
                emit RewardMintFailed(consumer, consumerReward);
            }
        }
    }

    function _validateChannelConfig(ChannelConfig memory config) internal view {
        require(uint256(config.providerBps) + config.relayBps + config.poolBps + config.treasuryBps == BPS, "bad split");
        require(uint256(config.providerRewardBps) + config.consumerRewardBps == BPS, "bad rewards");
        require(config.consumerRewardBps <= maxConsumerRebateBps, "consumer rebate too high");
    }

    function _channelPricingHash(bytes32 channel, uint64 version, address versionTreasury, ChannelConfig memory config)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(channel, version, versionTreasury, config));
    }

    function _consumeGovernanceAction(bytes32 actionHash) internal {
        uint256 readyAt = governanceActionReadyAt[actionHash];
        require(readyAt != 0, "action not scheduled");
        require(block.timestamp >= readyAt, "action pending");
        delete governanceActionReadyAt[actionHash];
        emit GovernanceActionConsumed(actionHash);
    }

    function _scheduleGovernanceAction(bytes32 actionHash) internal returns (uint256 readyAt) {
        require(actionHash != bytes32(0), "zero action");
        readyAt = block.timestamp + GOVERNANCE_DELAY_SECONDS;
        governanceActionReadyAt[actionHash] = readyAt;
        emit GovernanceActionScheduled(actionHash, readyAt);
    }

    function _epochEmission(uint256 epoch) internal pure returns (uint256) {
        uint256 halvings = epoch / HALVING_INTERVAL_EPOCHS;
        if (halvings >= 64) return 0;
        return EPOCH_EMISSION >> halvings;
    }

    function _saturatingMultiply(uint256 left, uint256 right) internal pure returns (uint256) {
        if (left == 0 || right == 0) return 0;
        if (right > type(uint256).max / left) return type(uint256).max;
        return left * right;
    }

    /// @dev Computes floor((firstTokens * firstRate + secondTokens * secondRate) / 1000)
    /// without overflowing intermediate products when the final result fits in uint256.
    function _quoteUsageFee(uint256 firstTokens, uint256 firstRate, uint256 secondTokens, uint256 secondRate)
        internal
        pure
        returns (uint256)
    {
        (uint256 firstBase, uint256 firstRemainder) = _quoteLeg(firstTokens, firstRate);
        (uint256 secondBase, uint256 secondRemainder) = _quoteLeg(secondTokens, secondRate);
        uint256 usageFee = _checkedQuoteAdd(firstBase, secondBase);
        return _checkedQuoteAdd(usageFee, (firstRemainder + secondRemainder) / 1000);
    }

    function _quoteLeg(uint256 tokens, uint256 rate) internal pure returns (uint256 base, uint256 remainder) {
        uint256 wholeTokens = tokens / 1000;
        require(wholeTokens == 0 || rate <= type(uint256).max / wholeTokens, "quote overflow");
        base = wholeTokens * rate;

        uint256 tokenRemainder = tokens % 1000;
        base = _checkedQuoteAdd(base, tokenRemainder * (rate / 1000));
        remainder = tokenRemainder * (rate % 1000);
    }

    function _checkedQuoteAdd(uint256 left, uint256 right) internal pure returns (uint256) {
        require(right <= type(uint256).max - left, "quote overflow");
        return left + right;
    }

    /// @dev Exact floor(amount * bps / BPS) without an overflowing amount * bps intermediate.
    function _bpsAmount(uint256 amount, uint16 bps) internal pure returns (uint256) {
        return ((amount / BPS) * bps) + (((amount % BPS) * bps) / BPS);
    }

    function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == _initialChainId ? _initialDomainSeparator : _buildDomainSeparator();
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("MycoMesh Settlement")),
                keccak256(bytes("3")),
                block.chainid,
                address(this)
            )
        );
    }

    function _isValidSignature(address signer, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        if (signer.code.length > 0) {
            (bool ok, bytes memory result) =
                signer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, signature)));
            return ok && result.length >= 32 && abi.decode(result, (bytes4)) == EIP1271_MAGIC_VALUE;
        }
        return _recover(digest, signature) == signer;
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
        if ((v != 27 && v != 28) || uint256(s) > SECP256K1_HALF_ORDER) return address(0);
        recovered = ecrecover(digest, v, r, s);
    }

    function _tokenBalance(address account) internal view returns (uint256 balance) {
        (bool ok, bytes memory data) = address(stablecoin).staticcall(abi.encodeCall(IMycoERC20V3.balanceOf, (account)));
        require(ok && data.length >= 32, "balanceOf failed");
        balance = abi.decode(data, (uint256));
    }

    function _safeTransfer(address to, uint256 amount) internal {
        if (amount == 0) return;
        require(to != address(this), "token self transfer");
        uint256 beforeFrom = _tokenBalance(address(this));
        uint256 beforeTo = _tokenBalance(to);
        _callOptionalReturn(abi.encodeCall(IMycoERC20V3.transfer, (to, amount)));
        uint256 afterFrom = _tokenBalance(address(this));
        uint256 afterTo = _tokenBalance(to);
        require(
            afterFrom <= beforeFrom && beforeFrom - afterFrom == amount && afterTo >= beforeTo
                && afterTo - beforeTo == amount,
            "unsupported token behavior"
        );
    }

    function _safeTransferFrom(address from, address to, uint256 amount) internal {
        require(from != to, "token self transfer");
        uint256 beforeFrom = _tokenBalance(from);
        uint256 beforeTo = _tokenBalance(to);
        _callOptionalReturn(abi.encodeCall(IMycoERC20V3.transferFrom, (from, to, amount)));
        uint256 afterFrom = _tokenBalance(from);
        uint256 afterTo = _tokenBalance(to);
        require(
            afterFrom <= beforeFrom && beforeFrom - afterFrom == amount && afterTo >= beforeTo
                && afterTo - beforeTo == amount,
            "unsupported token behavior"
        );
    }

    function _callOptionalReturn(bytes memory data) internal {
        (bool ok, bytes memory result) = address(stablecoin).call(data);
        require(ok && (result.length == 0 || abi.decode(result, (bool))), "token transfer failed");
    }
}
