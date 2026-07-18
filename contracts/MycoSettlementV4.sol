// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 surface used by the settlement contract.
interface IMycoERC20V4 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IMycoRewardTokenV4 {
    function mint(address to, uint256 amount) external;
}

/// @notice V4 session escrow for long-lived, prepaid inference sessions.
///
/// A consumer funds one session on-chain.  Inference receipts are signed by
/// the session EOA and the bound provider, and can be submitted by any
/// relayer in a batch.  A session is closed only after an explicit consumer
/// request and a grace period, or after expiry, so a close transaction cannot
/// race a consumer's close request and immediately steal its refund window.
contract MycoSettlementV4 {
    uint16 public constant BPS = 10_000;
    uint8 public constant ROLE_CONSUMER = 1;
    uint8 public constant ROLE_PROVIDER = 2;
    uint256 public constant GOVERNANCE_DELAY_SECONDS = 2 days;
    uint256 public constant MAX_SESSION_DURATION = 30 days;
    uint256 public constant CLOSE_GRACE_SECONDS = 1 days;
    uint256 public constant MAX_BATCH_SIZE = 32;
    uint256 public constant EPOCH_SECONDS = 7 days;
    uint256 public constant EPOCH_EMISSION = 1_000_000 ether;
    uint256 public constant HALVING_INTERVAL_EPOCHS = 208;

    bytes4 private constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant SESSION_RECEIPT_TYPEHASH = keccak256(
        "SessionReceipt(bytes32 receiptHash,bytes32 acceptedHash,bytes32 sessionId,bytes32 requestHash,bytes32 responseHash,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,address consumer,address provider,address relay,address pool,uint256 inputTokens,uint256 outputTokens,uint256 sequence,uint256 quotedFee,uint256 deadline)"
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

    struct Session {
        address consumer;
        address provider;
        address sessionKey;
        bytes32 channel;
        uint64 pricingVersion;
        bytes32 pricingHash;
        uint64 openedAt;
        uint64 expiresAt;
        uint64 closeRequestedAt;
        uint256 maxAmount;
        uint256 spent;
        uint256 nextSequence;
        bool closed;
    }

    struct SessionReceipt {
        bytes32 receiptHash;
        bytes32 acceptedHash;
        bytes32 sessionId;
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
        uint256 sequence;
        uint256 quotedFee;
        uint256 deadline;
    }

    struct SignedSessionReceipt {
        SessionReceipt receipt;
        bytes sessionKeySignature;
        bytes providerSignature;
    }

    struct Settlement {
        bytes32 sessionId;
        bytes32 receiptHash;
        address consumer;
        address provider;
        address relay;
        address pool;
        bytes32 channel;
        uint64 pricingVersion;
        uint256 sequence;
        uint256 grossFee;
        uint256 providerAmount;
        uint256 relayAmount;
        uint256 poolAmount;
        uint256 treasuryAmount;
        uint256 providerReward;
        uint256 consumerReward;
        uint256 settledAt;
    }

    IMycoERC20V4 public immutable stablecoin;
    IMycoRewardTokenV4 public immutable rewardToken;
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
    mapping(bytes32 => Session) public sessions;
    mapping(bytes32 => bool) public settlementKeySettled;
    mapping(bytes32 => Settlement) private _settlements;
    mapping(uint256 => uint256) public epochMinted;

    bool private entered;

    event Deposited(address indexed account, uint256 requestedAmount, uint256 receivedAmount);
    event Withdrawn(address indexed account, uint256 amount);
    event SessionOpened(
        bytes32 indexed sessionId,
        address indexed consumer,
        address indexed provider,
        address sessionKey,
        bytes32 channel,
        uint64 pricingVersion,
        bytes32 pricingHash,
        uint256 maxAmount,
        uint256 expiresAt
    );
    event SessionCloseRequested(bytes32 indexed sessionId, uint256 closeAt, uint256 closeableAt);
    event SessionCloseCancelled(bytes32 indexed sessionId);
    event SessionClosed(bytes32 indexed sessionId, address indexed consumer, uint256 spent, uint256 refunded);
    event ReceiptSettled(
        bytes32 indexed receiptHash,
        bytes32 indexed sessionId,
        address indexed consumer,
        address provider,
        uint256 sequence,
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
    event GovernanceTransferStarted(address indexed previousGovernance, address indexed nextGovernance, uint256 readyAt);
    event GovernanceTransferred(address indexed previousGovernance, address indexed nextGovernance);
    event RewardMintFailed(address indexed recipient, uint256 amount);

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
        require(stablecoin_ != address(0) && stablecoin_.code.length > 0, "bad stablecoin");
        require(rewardToken_ != address(0), "zero reward");
        require(treasury_ != address(0) && treasury_ != address(this), "bad treasury");
        require(governance_ != address(0), "zero governance");
        require(maxConsumerRebateBps_ <= BPS, "bad rebate");
        require(initialChannel_ != bytes32(0), "zero initial channel");
        require(initialConfig_.active, "inactive initial channel");
        _validateChannelConfig(initialConfig_, maxConsumerRebateBps_);

        stablecoin = IMycoERC20V4(stablecoin_);
        rewardToken = IMycoRewardTokenV4(rewardToken_);
        treasury = treasury_;
        governance = governance_;
        maxConsumerRebateBps = maxConsumerRebateBps_;
        emissionStartedAt = block.timestamp;

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

    // ---------------------------------------------------------------------
    // Governance and immutable pricing versions
    // ---------------------------------------------------------------------

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

    function scheduleTreasuryUpdate(address nextTreasury)
        external
        onlyGovernance
        returns (bytes32 actionHash, uint256 readyAt)
    {
        require(nextTreasury != address(0) && nextTreasury != address(this), "bad treasury");
        actionHash = treasuryActionHash(nextTreasury);
        readyAt = _scheduleGovernanceAction(actionHash);
        emit TreasuryUpdateScheduled(nextTreasury, actionHash, readyAt);
    }

    function setTreasury(address nextTreasury)
        external
        onlyGovernance
        consumesGovernanceAction(treasuryActionHash(nextTreasury))
    {
        require(nextTreasury != address(0) && nextTreasury != address(this), "bad treasury");
        address previous = treasury;
        treasury = nextTreasury;
        emit TreasuryUpdated(previous, nextTreasury);
    }

    function scheduleChannelVersion(bytes32 channel, ChannelConfig calldata config)
        external
        onlyGovernance
        returns (bytes32 actionHash, uint256 readyAt)
    {
        require(channel != bytes32(0), "zero channel");
        _validateChannelConfig(config, maxConsumerRebateBps);
        uint64 nextVersion = latestChannelVersion[channel] + 1;
        actionHash = channelActionHash(channel, config);
        readyAt = _scheduleGovernanceAction(actionHash);
        emit ChannelVersionScheduled(channel, nextVersion, actionHash, config, readyAt);
    }

    function addChannelVersion(bytes32 channel, ChannelConfig calldata config)
        external
        onlyGovernance
        consumesGovernanceAction(channelActionHash(channel, config))
        returns (uint64 version)
    {
        require(channel != bytes32(0), "zero channel");
        _validateChannelConfig(config, maxConsumerRebateBps);
        version = latestChannelVersion[channel] + 1;
        bytes32 pricingHash = _channelPricingHash(channel, version, treasury, config);
        channelVersions[channel][version] = ChannelVersion({config: config, treasury: treasury, pricingHash: pricingHash});
        latestChannelVersion[channel] = version;
        emit ChannelVersionAdded(channel, version, pricingHash, config.active);
    }

    function scheduleRewardEnable() external onlyGovernance returns (bytes32 actionHash, uint256 readyAt) {
        require(!rewardsEnabled, "rewards enabled");
        actionHash = rewardEnableActionHash();
        readyAt = _scheduleGovernanceAction(actionHash);
        emit RewardEnableScheduled(actionHash, readyAt);
    }

    function enableRewards() external onlyGovernance consumesGovernanceAction(rewardEnableActionHash()) {
        require(!rewardsEnabled, "rewards enabled");
        rewardsEnabled = true;
        emit RewardsEnabled();
    }

    function pauseRewards() external onlyGovernance {
        rewardsEnabled = false;
        bytes32 actionHash = rewardEnableActionHash();
        if (governanceActionReadyAt[actionHash] != 0) {
            delete governanceActionReadyAt[actionHash];
            emit GovernanceActionCancelled(actionHash);
        }
        emit RewardsPaused();
    }

    function cancelGovernanceAction(bytes32 actionHash) external onlyGovernance {
        require(governanceActionReadyAt[actionHash] != 0, "action not scheduled");
        delete governanceActionReadyAt[actionHash];
        emit GovernanceActionCancelled(actionHash);
    }

    function beginGovernanceTransfer(address nextGovernance) external onlyGovernance {
        require(nextGovernance != address(0) && nextGovernance != governance, "bad governance");
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
        address previous = governance;
        governance = pendingGovernance;
        pendingGovernance = address(0);
        pendingGovernanceReadyAt = 0;
        emit GovernanceTransferred(previous, governance);
    }

    // ---------------------------------------------------------------------
    // Prepaid balances and sessions
    // ---------------------------------------------------------------------

    function deposit(uint256 amount) external nonReentrant returns (uint256 received) {
        require(amount > 0, "zero amount");
        uint256 beforeBalance = _tokenBalance(address(this));
        _safeTransferFrom(msg.sender, address(this), amount);
        uint256 afterBalance = _tokenBalance(address(this));
        require(afterBalance == beforeBalance + amount, "unsupported token behavior");
        received = amount;
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

    function sessionIdFor(address consumer, bytes32 sessionSalt) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), block.chainid, consumer, sessionSalt));
    }

    function openSession(
        bytes32 sessionSalt,
        address provider,
        address sessionKey,
        bytes32 channel,
        uint64 pricingVersion,
        uint256 maxAmount,
        uint64 expiresAt
    ) external nonReentrant returns (bytes32 sessionId) {
        require(sessionSalt != bytes32(0), "zero session salt");
        sessionId = sessionIdFor(msg.sender, sessionSalt);
        require(sessions[sessionId].consumer == address(0), "session exists");
        require(provider != address(0) && provider != msg.sender && provider != address(this), "bad provider");
        require(provider.code.length == 0, "provider must be EOA");
        require(sessionKey != address(0) && sessionKey.code.length == 0, "session key must be EOA");
        require(sessionKey != provider, "session key provider");
        require(maxAmount > 0, "zero session amount");
        require(expiresAt > block.timestamp, "bad expiry");
        require(expiresAt <= block.timestamp + MAX_SESSION_DURATION, "expiry too long");
        require(pricingVersion != 0 && pricingVersion == latestChannelVersion[channel], "not latest pricing");
        ChannelVersion storage version = channelVersions[channel][pricingVersion];
        require(version.config.active, "inactive channel");
        require(maxAmount >= version.config.minimumFee, "below minimum fee");
        require(availableBalance[msg.sender] >= maxAmount, "available balance");

        availableBalance[msg.sender] -= maxAmount;
        lockedBalance[msg.sender] += maxAmount;
        sessions[sessionId] = Session({
            consumer: msg.sender,
            provider: provider,
            sessionKey: sessionKey,
            channel: channel,
            pricingVersion: pricingVersion,
            pricingHash: version.pricingHash,
            openedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            closeRequestedAt: 0,
            maxAmount: maxAmount,
            spent: 0,
            nextSequence: 0,
            closed: false
        });
        emit SessionOpened(
            sessionId, msg.sender, provider, sessionKey, channel, pricingVersion, version.pricingHash, maxAmount, expiresAt
        );
    }

    function requestClose(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];
        require(session.consumer != address(0), "unknown session");
        require(msg.sender == session.consumer, "not consumer");
        require(!session.closed, "session closed");
        require(session.closeRequestedAt == 0, "close already requested");
        session.closeRequestedAt = uint64(block.timestamp);
        emit SessionCloseRequested(sessionId, block.timestamp, block.timestamp + CLOSE_GRACE_SECONDS);
    }

    function cancelClose(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];
        require(session.consumer != address(0), "unknown session");
        require(msg.sender == session.consumer, "not consumer");
        require(!session.closed, "session closed");
        require(session.closeRequestedAt != 0, "close not requested");
        require(block.timestamp < session.expiresAt, "session expired");
        session.closeRequestedAt = 0;
        emit SessionCloseCancelled(sessionId);
    }

    /// @notice Permissionless refund after the consumer's grace period or session expiry.
    function closeSession(bytes32 sessionId) external nonReentrant {
        Session storage session = sessions[sessionId];
        require(session.consumer != address(0), "unknown session");
        require(!session.closed, "session closed");
        bool expired = block.timestamp > session.expiresAt;
        bool graceElapsed =
            session.closeRequestedAt != 0 && block.timestamp >= uint256(session.closeRequestedAt) + CLOSE_GRACE_SECONDS;
        require(expired || graceElapsed, "close pending");

        session.closed = true;
        uint256 refund = session.maxAmount - session.spent;
        lockedBalance[session.consumer] -= session.maxAmount;
        availableBalance[session.consumer] += refund;
        emit SessionClosed(sessionId, session.consumer, session.spent, refund);
    }

    function sessionRemaining(bytes32 sessionId) external view returns (uint256) {
        Session storage session = sessions[sessionId];
        if (session.consumer == address(0) || session.spent >= session.maxAmount) return 0;
        return session.maxAmount - session.spent;
    }

    /// @notice Struct-shaped read helper for clients that do not use the autogenerated mapping getter.
    function sessionInfo(bytes32 sessionId) external view returns (Session memory) {
        return sessions[sessionId];
    }

    // ---------------------------------------------------------------------
    // Signed receipts and settlement
    // ---------------------------------------------------------------------

    function settlementKeyFor(bytes32 sessionId, bytes32 receiptHash) public pure returns (bytes32) {
        return keccak256(abi.encode(sessionId, receiptHash));
    }

    function receiptSettled(bytes32 sessionId, bytes32 receiptHash) external view returns (bool) {
        return settlementKeySettled[settlementKeyFor(sessionId, receiptHash)];
    }

    function settlement(bytes32 sessionId, bytes32 receiptHash) external view returns (Settlement memory) {
        return _settlements[settlementKeyFor(sessionId, receiptHash)];
    }

    function receiptStructHash(SessionReceipt calldata receipt) public pure returns (bytes32) {
        return keccak256(abi.encode(SESSION_RECEIPT_TYPEHASH, receipt));
    }

    function receiptDigest(SessionReceipt calldata receipt) public view returns (bytes32) {
        return _toTypedDataHash(receiptStructHash(receipt));
    }

    function settleSignedReceipt(SignedSessionReceipt calldata input) external nonReentrant {
        _settleSignedReceipt(input);
    }

    function settleSignedBatch(SignedSessionReceipt[] calldata inputs) external nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE, "bad batch length");
        for (uint256 i = 0; i < inputs.length; ++i) {
            _settleSignedReceipt(inputs[i]);
        }
    }

    function quote(bytes32 channel, uint64 pricingVersion, uint256 inputTokens, uint256 outputTokens)
        public
        view
        returns (uint256)
    {
        ChannelVersion storage version = channelVersions[channel][pricingVersion];
        require(pricingVersion != 0 && version.pricingHash != bytes32(0), "unknown pricing");
        uint256 usageFee = _quoteUsageFee(
            inputTokens, version.config.inputPer1K, outputTokens, version.config.outputPer1K
        );
        return usageFee < version.config.minimumFee ? version.config.minimumFee : usageFee;
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

    function _settleSignedReceipt(SignedSessionReceipt calldata input) internal {
        uint256 grossFee = _validateReceipt(input.receipt);
        bytes32 digest = _toTypedDataHash(receiptStructHash(input.receipt));
        Session storage session = sessions[input.receipt.sessionId];
        require(_recover(digest, input.sessionKeySignature) == session.sessionKey, "bad session signature");
        require(_recover(digest, input.providerSignature) == session.provider, "bad provider signature");
        _settle(input.receipt, grossFee);
    }

    function _validateReceipt(SessionReceipt calldata receipt) internal view returns (uint256 grossFee) {
        require(receipt.receiptHash != bytes32(0), "zero receipt");
        require(receipt.acceptedHash != bytes32(0), "missing acceptance");
        require(receipt.requestHash != bytes32(0), "missing request");
        require(receipt.responseHash != bytes32(0), "missing response");
        require(receipt.sessionId != bytes32(0), "zero session");
        require(receipt.consumer != address(0) && receipt.provider != address(0), "zero party");
        require(receipt.consumer != receipt.provider, "same party");
        require(receipt.relay != address(this) && receipt.pool != address(this), "invalid recipient");
        require(receipt.deadline != 0 && block.timestamp <= receipt.deadline, "receipt expired");

        bytes32 settlementKey = settlementKeyFor(receipt.sessionId, receipt.receiptHash);
        require(!settlementKeySettled[settlementKey], "receipt settled");

        Session storage session = sessions[receipt.sessionId];
        require(session.consumer != address(0), "unknown session");
        require(!session.closed, "session closed");
        require(block.timestamp <= session.expiresAt, "session expired");
        require(receipt.deadline <= session.expiresAt, "deadline after session");
        require(session.consumer == receipt.consumer, "session consumer");
        require(session.provider == receipt.provider, "session provider");
        require(session.channel == receipt.channel, "session channel");
        require(session.pricingVersion == receipt.pricingVersion, "session pricing");
        require(session.pricingHash == receipt.pricingHash, "session pricing hash");
        require(session.nextSequence == receipt.sequence, "bad sequence");

        ChannelVersion storage version = channelVersions[receipt.channel][receipt.pricingVersion];
        require(version.pricingHash != bytes32(0) && receipt.pricingHash == version.pricingHash, "pricing hash");
        grossFee = quote(receipt.channel, receipt.pricingVersion, receipt.inputTokens, receipt.outputTokens);
        require(receipt.quotedFee == grossFee, "quote mismatch");
        require(grossFee <= session.maxAmount - session.spent, "session amount");
    }

    function _settle(SessionReceipt calldata receipt, uint256 grossFee) internal {
        Session storage session = sessions[receipt.sessionId];
        ChannelVersion storage version = channelVersions[receipt.channel][receipt.pricingVersion];
        ChannelConfig storage config = version.config;

        uint256 providerAmount = _bpsAmount(grossFee, config.providerBps);
        uint256 relayAmount = _bpsAmount(grossFee, config.relayBps);
        uint256 poolAmount = _bpsAmount(grossFee, config.poolBps);
        uint256 treasuryAmount = grossFee - providerAmount - relayAmount - poolAmount;
        if (receipt.relay == address(0)) {
            treasuryAmount += relayAmount;
            relayAmount = 0;
        }
        if (receipt.pool == address(0)) {
            treasuryAmount += poolAmount;
            poolAmount = 0;
        }

        session.spent += grossFee;
        session.nextSequence += 1;
        bytes32 settlementKey = settlementKeyFor(receipt.sessionId, receipt.receiptHash);
        settlementKeySettled[settlementKey] = true;
        Settlement storage item = _settlements[settlementKey];
        item.sessionId = receipt.sessionId;
        item.receiptHash = receipt.receiptHash;
        item.consumer = receipt.consumer;
        item.provider = receipt.provider;
        item.relay = receipt.relay;
        item.pool = receipt.pool;
        item.channel = receipt.channel;
        item.pricingVersion = receipt.pricingVersion;
        item.sequence = receipt.sequence;
        item.grossFee = grossFee;
        item.providerAmount = providerAmount;
        item.relayAmount = relayAmount;
        item.poolAmount = poolAmount;
        item.treasuryAmount = treasuryAmount;
        item.settledAt = block.timestamp;

        _safeTransfer(receipt.provider, providerAmount);
        if (relayAmount > 0) _safeTransfer(receipt.relay, relayAmount);
        if (poolAmount > 0) _safeTransfer(receipt.pool, poolAmount);
        _safeTransfer(version.treasury, treasuryAmount);
        _mintRewards(receipt.provider, receipt.consumer, item, treasuryAmount, config);

        emit ReceiptSettled(receipt.receiptHash, receipt.sessionId, receipt.consumer, receipt.provider, receipt.sequence, grossFee);
    }

    // ---------------------------------------------------------------------
    // Accounting, signatures, and math
    // ---------------------------------------------------------------------

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
        uint256 totalReward = requested > cap - minted ? cap - minted : requested;
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

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == _initialChainId ? _initialDomainSeparator : _buildDomainSeparator();
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("MycoMesh Settlement")),
                keccak256(bytes("4")),
                block.chainid,
                address(this)
            )
        );
    }

    function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
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

    function _validateChannelConfig(ChannelConfig memory config, uint16 rebateCap) internal pure {
        require(
            uint256(config.providerBps) + config.relayBps + config.poolBps + config.treasuryBps == BPS,
            "bad split"
        );
        require(uint256(config.providerRewardBps) + config.consumerRewardBps == BPS, "bad rewards");
        require(config.consumerRewardBps <= rebateCap, "consumer rebate too high");
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

    function _bpsAmount(uint256 amount, uint16 bps) internal pure returns (uint256) {
        return ((amount / BPS) * bps) + (((amount % BPS) * bps) / BPS);
    }

    function _tokenBalance(address account) internal view returns (uint256 balance) {
        (bool ok, bytes memory data) = address(stablecoin).staticcall(abi.encodeCall(IMycoERC20V4.balanceOf, (account)));
        require(ok && data.length >= 32, "balanceOf failed");
        balance = abi.decode(data, (uint256));
    }

    function _safeTransfer(address to, uint256 amount) internal {
        if (amount == 0) return;
        require(to != address(this), "token self transfer");
        uint256 beforeFrom = _tokenBalance(address(this));
        uint256 beforeTo = _tokenBalance(to);
        _callOptionalReturn(abi.encodeCall(IMycoERC20V4.transfer, (to, amount)));
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
        _callOptionalReturn(abi.encodeCall(IMycoERC20V4.transferFrom, (from, to, amount)));
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
