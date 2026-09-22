// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoERC20V10 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice V10 fixed-capacity prepaid channels; local candidate, not a migration of V9 funds.
/// @dev This is a new EIP-712 version and deployment, NOT an upgrade of V8 funds.
/// A pinned, independently operated adjudicator quorum must verify off-chain
/// evidence; this contract cannot prove model identity or computational truth.
/// Distinct addresses do not prove distinct operators. No production policy is
/// implied by the constructor bounds. Governance cannot change dispute policy,
/// replace judges, seize balances, mint rewards, or retroactively edit pricing.
/// Only ordinary exact-transfer, non-rebasing ERC-20s are supported.
contract MycoSettlementV10 {
    uint16 public constant BPS = 10_000;
    uint256 public constant MAX_BATCH_SIZE = 32;
    uint256 public constant MAX_AUTHORIZATION_TTL = 3 hours;
    uint256 public constant MAX_ADJUDICATORS = 16;
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant PAYMENT_AUTHORIZATION_TYPEHASH = keccak256(
        "ReservedPaymentAuthorization(bytes32 channelId,bytes32 requestId,bytes32 requestHash,address key,uint256 maxFee,uint64 issuedAt,uint64 executeBy,uint64 deadline)"
    );
    bytes32 public constant USAGE_RECEIPT_TYPEHASH = keccak256(
        "ReservedUsageReceipt(bytes32 channelId,bytes32 authorizationHash,bytes32 dispatchHash,bytes32 responseHash,uint256 inputTokens,uint256 outputTokens,uint256 actualFee)"
    );
    bytes32 public constant DISPATCH_TYPEHASH = keccak256("RelayDispatch(bytes32 authorizationHash,bytes32 channelId)");
    bytes32 public constant OPEN_CHANNEL_TYPEHASH = keccak256(
        "OpenCapacityChannel(address consumerOwner,address consumerKey,address providerOwner,address providerSigner,address relay,address relaySigner,address pool,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,uint256 capacity,uint256 maxFeePerRequest,uint64 validFrom,uint64 admitUntil,uint64 claimUntil,uint256 consumerNonce,uint256 providerNonce,uint64 permitDeadline)"
    );
    bytes32 private constant DISPUTE_VOTE_TYPEHASH = keccak256(
        "DisputeVote(bytes32 settlementKey,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)"
    );
    uint256 public constant MAX_CHANNEL_DURATION = 7 days;
    uint256 public constant PROTOCOL_VERSION = 10;

    struct OpenChannel {
        address consumerOwner; address consumerKey;
        address providerOwner; address providerSigner;
        address relay; address relaySigner; address pool;
        bytes32 channel; uint64 pricingVersion; bytes32 pricingHash;
        uint256 capacity; uint256 maxFeePerRequest;
        uint64 validFrom; uint64 admitUntil; uint64 claimUntil;
        uint256 consumerNonce; uint256 providerNonce; uint64 permitDeadline;
    }
    struct ChannelPermit { OpenChannel config; bytes consumerSignature; bytes providerSignature; }
    struct CapacityChannel {
        OpenChannel config;
        uint256 settledMaxFee; uint256 creditRemaining; uint256 stakeRemaining; bool closed;
    }
    mapping(bytes32 => CapacityChannel) private capacityChannels;
    mapping(address => uint256) public allocatedStake;
    mapping(address => uint256) public consumerAllocationNonce;
    mapping(address => uint256) public providerAllocationNonce;
    uint256 public totalAllocatedCredit;
    event CapacityChannelOpened(bytes32 indexed channelId, address indexed consumerOwner, address indexed providerOwner, uint256 capacity, uint64 validFrom, uint64 claimUntil);
    event CapacityChannelClosed(bytes32 indexed channelId, uint256 creditReturned, uint256 stakeReleased);

    struct ChannelConfig {
        uint256 inputPer1K;
        uint256 outputPer1K;
        uint256 minimumFee;
        uint16 providerBps;
        uint16 relayBps;
        uint16 poolBps;
        uint16 treasuryBps;
        bool active;
    }

    struct ChannelVersion {
        ChannelConfig config;
        address treasury;
        bytes32 pricingHash;
    }

    /// @dev All values are constructor-pinned, in native token units / seconds.
    /// tokenRewardCap is a LIFETIME cap, not an authority to mint tokenReward.
    struct DisputePolicy {
        uint64 disputeWindow;
        uint64 arbitrationTimeout;
        uint64 consumerWithdrawalDelay;
        uint256 reporterBond;
        uint16 slashBps;
        uint256 slashCap;
        uint16 reporterBountyBps;
        uint256 stableBountyCap;
        uint256 tokenReward;
        uint256 tokenRewardCap;
        uint256 tokenMinimumExposure;
        uint256 tokenMinimumPenalty;
        address bondPenaltyRecipient;
    }

    struct KeyGrant {
        address owner;
        uint256 maxPerRequest;
        uint64 validUntil;
        bool active;
    }

    struct Withdrawal {
        uint256 amount;
        uint64 availableAt;
    }

    struct PaymentAuthorization {
        bytes32 channelId; bytes32 requestId; bytes32 requestHash; address key;
        uint256 maxFee; uint64 issuedAt; uint64 executeBy; uint64 deadline;
    }
    struct UsageReceipt {
        bytes32 channelId; bytes32 authorizationHash; bytes32 dispatchHash; bytes32 responseHash;
        uint256 inputTokens; uint256 outputTokens; uint256 actualFee;
    }
    struct SignedReceipt {
        PaymentAuthorization authorization; UsageReceipt receipt;
        bytes keySignature; bytes providerSignature; bytes relaySignature;
    }

    enum Status {
        None,
        Pending,
        Disputed,
        Released,
        Confirmed,
        Dismissed,
        TimedOut
    }

    struct Settlement {
        address owner;
        address key;
        address provider;
        address providerSigner;
        address relay;
        address relaySigner;
        address pool;
        address treasury;
        bytes32 requestId;
        bytes32 requestHash;
        bytes32 authorizationHash;
        bytes32 responseHash;
        uint256 grossFee;
        uint256 providerAmount;
        uint256 relayAmount;
        uint256 poolAmount;
        uint256 treasuryAmount;
        uint64 settledAt;
        uint64 releaseAt;
        Status status;
    }

    struct Dispute {
        uint64 openedAt;
        uint64 resolveAt;
        uint16 dismissVotes;
        uint256 reportCount;
        uint256 totalBond;
        bytes32 winningReportId;
        uint256 slashAmount;
        uint256 stableBounty;
    }

    struct Report {
        address reporter;
        bytes32 evidenceHash;
        bool bondClaimed;
    }

    /// @notice A judge's EIP-712 vote authorization for relayer submission.
    /// @dev The judge signs the exact settlement, outcome, evidence report,
    /// nonce, and expiry. The relayer cannot change any of those fields.
    struct DisputeVotePermit {
        bool confirmed;
        bytes32 reportId;
        bytes32 decisionHash;
        uint256 nonce;
        uint64 deadline;
        bytes signature;
    }

    IMycoERC20V10 public immutable stablecoin;
    IMycoERC20V10 public immutable rewardToken;
    uint16 public immutable adjudicationThreshold;
    uint256 private immutable initialChainId;
    bytes32 private immutable initialDomainSeparator;
    address public governance;
    address public treasury;
    DisputePolicy public policy;
    address[] private judges;
    mapping(address => bool) public isAdjudicator;
    mapping(bytes32 => mapping(address => uint8)) public disputeVotes;
    mapping(address => uint256) private adjudicatorNonces;
    mapping(bytes32 => mapping(address => bytes32)) public voteReportId;
    mapping(bytes32 => mapping(bytes32 => uint16)) public confirmationVotes;
    mapping(bytes32 => mapping(bytes32 => Report)) public reports;
    mapping(bytes32 => mapping(address => bool)) public hasReported;

    mapping(bytes32 => uint64) public latestChannelVersion;
    mapping(bytes32 => mapping(uint64 => ChannelVersion)) public channelVersions;
    mapping(address => uint256) public availableBalance;
    mapping(address => uint256) public claimableBalance;
    mapping(address => KeyGrant) public keyGrants;
    mapping(address => mapping(address => bool)) public providerSigners;
    mapping(address => Withdrawal) public withdrawals;
    mapping(bytes32 => bool) public settled;
    mapping(bytes32 => Settlement) private settlements;
    mapping(bytes32 => Dispute) private disputes;
    mapping(address => uint256) public providerStake;
    /// @notice Capacity funded by governance on behalf of a Provider.
    /// @dev This is intentionally tracked separately from the Provider's own
    /// stake. A Provider can use sponsored capacity, but can never withdraw
    /// the sponsored principal. Governance can reclaim it only after all
    /// allocations and pending settlements for that Provider are released.
    mapping(address => uint256) private sponsoredStake;
    mapping(address => uint256) public lockedStake;

    uint256 public totalAvailable;
    uint256 public totalClaimable;
    uint256 public totalPendingFees;
    uint256 public totalStake;
    /// @notice Global cap for all network-sponsored Provider capacity.
    /// A zero value keeps sponsorship disabled until governance opts in.
    uint256 private sponsoredCapacityLimit;
    uint256 public totalReporterBonds;
    bool private entered;

    event Deposited(address indexed account, uint256 amount);
    event WithdrawalRequested(address indexed account, uint256 amount, uint256 availableAt);
    event WithdrawalCancelled(address indexed account);
    event Withdrawn(address indexed account, uint256 amount);
    event KeyRegistered(address indexed owner, address indexed key, uint256 maxPerRequest, uint256 validUntil);
    event KeyRevoked(address indexed owner, address indexed key);
    event ProviderSignerAuthorized(address indexed provider, address indexed signer);
    event ProviderSignerRevoked(address indexed provider, address indexed signer);
    event ChannelVersionAdded(bytes32 indexed channel, uint64 indexed version, bytes32 pricingHash, bool active);
    event StakeDeposited(address indexed provider, uint256 amount);
    event StakeWithdrawn(address indexed provider, uint256 amount);
    event ReceiptEscrowed(
        bytes32 indexed settlementKey,
        bytes32 indexed requestId,
        address indexed owner,
        address provider,
        uint256 grossFee,
        uint256 releaseAt
    );
    event SettlementReleased(bytes32 indexed settlementKey, Status status);
    event DisputeOpened(bytes32 indexed settlementKey, uint256 resolveAt);
    event EvidenceSubmitted(
        bytes32 indexed settlementKey,
        bytes32 indexed reportId,
        address indexed reporter,
        bytes32 evidenceHash,
        uint256 bond
    );
    event DisputeBondReturned(bytes32 indexed settlementKey, bytes32 indexed reportId, address indexed reporter);
    event DisputeVote(
        bytes32 indexed settlementKey,
        address indexed adjudicator,
        bool confirmed,
        bytes32 reportId,
        bytes32 decisionHash
    );
    event DisputeResolved(
        bytes32 indexed settlementKey, Status status, uint256 slashAmount, uint256 stableBounty
    );
    event PayoutClaimed(address indexed account, uint256 amount);

    modifier nonReentrant() {
        require(!entered); // reentrant
        entered = true;
        _;
        entered = false;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance); // not governance
        _;
    }

    constructor(
        address stablecoin_,
        address rewardToken_,
        address treasury_,
        address governance_,
        bytes32 initialChannel_,
        ChannelConfig memory initialConfig_,
        DisputePolicy memory policy_,
        address[] memory adjudicators_,
        uint16 threshold_
    ) {
        require(stablecoin_ != address(0) && stablecoin_.code.length > 0); // bad stablecoin
        require(treasury_ != address(0) && treasury_ != address(this) && governance_ != address(0)); // bad authority
        require(initialChannel_ != bytes32(0)); // zero channel
        _validateConfig(initialConfig_);
        require(initialConfig_.active); // inactive channel
        require(policy_.disputeWindow > 0 && policy_.disputeWindow <= 30 days); // bad dispute window
        require(policy_.arbitrationTimeout > 0 && policy_.arbitrationTimeout <= 30 days); // bad arbitration timeout
        require(
            policy_.consumerWithdrawalDelay > 0 && policy_.consumerWithdrawalDelay <= 30 days); // bad withdrawal delay
        require(policy_.reporterBond > 0); // zero reporter bond
        require(policy_.slashBps > 0 && policy_.slashBps <= BPS && policy_.slashCap > 0); // bad slash policy
        require(
            policy_.reporterBountyBps > 0 && policy_.reporterBountyBps < BPS && policy_.stableBountyCap > 0
                && policy_.stableBountyCap <= policy_.slashCap); // bad bounty policy
        require(
            policy_.bondPenaltyRecipient != address(0) && policy_.bondPenaltyRecipient != address(this)); // bad penalty recipient
        require(rewardToken_ == address(0)); // V10 controlled test has no token rewards
        require(
            policy_.tokenReward == 0 && policy_.tokenRewardCap == 0 && policy_.tokenMinimumExposure == 0
                && policy_.tokenMinimumPenalty == 0); // reward disabled
        require(
            adjudicators_.length <= MAX_ADJUDICATORS && threshold_ >= 2 && threshold_ <= adjudicators_.length
                && threshold_ > adjudicators_.length / 2); // bad judge quorum
        for (uint256 i; i < adjudicators_.length; ++i) {
            address judge = adjudicators_[i];
            require(
                judge != address(0) && judge != address(this) && judge != governance_ && judge != treasury_
                    && judge != policy_.bondPenaltyRecipient); // bad adjudicator
            require(!isAdjudicator[judge]); // duplicate adjudicator
            isAdjudicator[judge] = true;
            judges.push(judge);
        }
        stablecoin = IMycoERC20V10(stablecoin_);
        rewardToken = IMycoERC20V10(rewardToken_);
        treasury = treasury_;
        governance = governance_;
        policy = policy_;
        adjudicationThreshold = threshold_;
        initialChainId = block.chainid;
        initialDomainSeparator = _buildDomainSeparator();
        _addChannelVersion(initialChannel_, initialConfig_);
    }

    function adjudicators() external view returns (address[] memory) {
        return judges;
    }

    function adjudicatorNonce(address judge) external view returns (uint256) {
        return adjudicatorNonces[judge];
    }

    function settlementInfo(bytes32 key) external view returns (Settlement memory) {
        return settlements[key];
    }

    function disputeInfo(bytes32 key) external view returns (Dispute memory) {
        return disputes[key];
    }

    /// @notice With supported ERC-20s, contract stable balance must cover this sum.
    function stableLiabilities() public view returns (uint256) {
        return totalAvailable + totalAllocatedCredit + totalClaimable + totalPendingFees + totalStake + totalReporterBonds;
    }

    function addChannelVersion(bytes32 channel, ChannelConfig calldata config)
        external
        onlyGovernance
        nonReentrant
        returns (uint64 version)
    {
        require(channel != bytes32(0)); // zero channel
        _validateConfig(config);
        return _addChannelVersion(channel, config);
    }

    function setTreasury(address nextTreasury) external onlyGovernance nonReentrant {
        require(nextTreasury != address(0) && nextTreasury != address(this)); // bad treasury
        treasury = nextTreasury;
    }

    function transferGovernance(address nextGovernance) external onlyGovernance nonReentrant {
        require(
            nextGovernance != address(0) && nextGovernance != address(this) && !isAdjudicator[nextGovernance]); // bad governance
        governance = nextGovernance;
    }

    function deposit(uint256 amount) external nonReentrant {
        require(amount > 0); // zero amount
        _takeExact(stablecoin, msg.sender, amount);
        availableBalance[msg.sender] += amount;
        totalAvailable += amount;
        emit Deposited(msg.sender, amount);
    }

    function registerKey(address key, uint256 maxPerRequest, uint64 validUntil) external nonReentrant {
        require(key != address(0) && key.code.length == 0 && key != msg.sender && key != address(this)); // bad key
        require(maxPerRequest > 0); // zero key limit
        require(validUntil == 0 || validUntil > block.timestamp); // key expired
        require(keyGrants[key].owner == address(0) || keyGrants[key].owner == msg.sender); // key owned
        keyGrants[key] = KeyGrant(msg.sender, maxPerRequest, validUntil, true);
        emit KeyRegistered(msg.sender, key, maxPerRequest, validUntil);
    }

    function revokeKey(address key) external nonReentrant {
        KeyGrant storage grant = keyGrants[key];
        require(grant.owner == msg.sender); // not key owner
        require(grant.active); // key inactive
        grant.active = false;
        emit KeyRevoked(msg.sender, key);
    }

    function authorizeProviderSigner(address signer) external nonReentrant {
        require(
            signer != address(0) && signer.code.length == 0 && signer != msg.sender && signer != address(this)); // bad provider signer
        require(!providerSigners[msg.sender][signer]); // signer authorized
        providerSigners[msg.sender][signer] = true;
        emit ProviderSignerAuthorized(msg.sender, signer);
    }

    function revokeProviderSigner(address signer) external nonReentrant {
        require(providerSigners[msg.sender][signer]); // signer inactive
        providerSigners[msg.sender][signer] = false;
        emit ProviderSignerRevoked(msg.sender, signer);
    }

    function requestWithdrawal(uint256 amount) external nonReentrant {
        require(amount > 0 && amount <= availableBalance[msg.sender]); // bad withdrawal
        uint64 availableAt = _future(policy.consumerWithdrawalDelay);
        withdrawals[msg.sender] = Withdrawal(amount, availableAt);
        emit WithdrawalRequested(msg.sender, amount, availableAt);
    }

    function cancelWithdrawal() external nonReentrant {
        require(withdrawals[msg.sender].amount > 0); // no withdrawal
        delete withdrawals[msg.sender];
        emit WithdrawalCancelled(msg.sender);
    }

    function withdraw() external nonReentrant {
        Withdrawal memory request = withdrawals[msg.sender];
        require(request.amount > 0 && block.timestamp >= request.availableAt); // withdrawal pending
        require(availableBalance[msg.sender] >= request.amount); // balance changed
        delete withdrawals[msg.sender];
        availableBalance[msg.sender] -= request.amount;
        totalAvailable -= request.amount;
        _sendExact(stablecoin, msg.sender, request.amount);
        emit Withdrawn(msg.sender, request.amount);
    }

    function depositStake(uint256 amount) external nonReentrant {
        require(amount > 0); // zero amount
        _takeExact(stablecoin, msg.sender, amount);
        providerStake[msg.sender] += amount;
        totalStake += amount;
        emit StakeDeposited(msg.sender, amount);
    }

    function withdrawStake(uint256 amount) external nonReentrant {
        uint256 free = providerStake[msg.sender] - lockedStake[msg.sender] - allocatedStake[msg.sender]
            - sponsoredStake[msg.sender];
        require(amount > 0 && amount <= free); // stake encumbered or network-sponsored principal
        providerStake[msg.sender] -= amount;
        totalStake -= amount;
        _sendExact(stablecoin, msg.sender, amount);
        emit StakeWithdrawn(msg.sender, amount);
    }

    /// @notice Set the remaining bounded network-sponsored capacity budget.
    /// Governance must explicitly opt in; already-funded capacity remains
    /// locked to its Provider until it is slashed or the deployment is retired.
    function setSponsoredCapacityLimit(uint256 limit) external onlyGovernance {
        sponsoredCapacityLimit = limit;
    }

    function sponsorProviderCapacity(address provider, uint256 amount) external onlyGovernance nonReentrant {
        require(provider != address(0) && provider != address(this) && amount > 0); // bad sponsorship
        require(amount <= sponsoredCapacityLimit); // admission cap
        _takeExact(stablecoin, msg.sender, amount);
        sponsoredStake[provider] += amount;
        providerStake[provider] += amount;
        totalStake += amount;
        sponsoredCapacityLimit -= amount;
    }

    function claim() external nonReentrant returns (uint256 amount) {
        amount = claimableBalance[msg.sender];
        require(amount > 0); // no claimable balance
        claimableBalance[msg.sender] = 0;
        totalClaimable -= amount;
        _sendExact(stablecoin, msg.sender, amount);
        emit PayoutClaimed(msg.sender, amount);
    }

    function openChannelStructHash(OpenChannel calldata c) public pure returns (bytes32) {
        return keccak256(abi.encode(OPEN_CHANNEL_TYPEHASH, c));
    }
    function channelIdFor(OpenChannel calldata c) public view returns (bytes32) {
        return _typedDataHash(openChannelStructHash(c));
    }
    function channelInfo(bytes32 id) external view returns (CapacityChannel memory) { return capacityChannels[id]; }
    function dispatchStructHash(bytes32 authorizationHash, bytes32 channelId) public pure returns (bytes32) {
        return keccak256(abi.encode(DISPATCH_TYPEHASH, authorizationHash, channelId));
    }
    function dispatchDigest(bytes32 authorizationHash, bytes32 channelId) external view returns (bytes32) {
        return _typedDataHash(dispatchStructHash(authorizationHash, channelId));
    }
    function openCapacityChannels(ChannelPermit[] calldata inputs) external nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE); // bad open batch
        for (uint256 i; i < inputs.length; ++i) _openChannel(inputs[i]);
    }
    function _openChannel(ChannelPermit calldata permit) internal {
        OpenChannel calldata c = permit.config;
        require(c.consumerOwner != address(0) && c.providerOwner != address(0)
            && c.relay != address(0) && c.relaySigner != address(0)); // zero channel role
        require(c.providerOwner != address(this) && c.relay != address(this) && c.pool != address(this)
            && c.providerOwner != policy.bondPenaltyRecipient && c.providerSigner != policy.bondPenaltyRecipient); // bad channel payee
        require(c.capacity > 0 && c.maxFeePerRequest > 0 && c.maxFeePerRequest <= c.capacity); // bad channel limits
        require(c.validFrom > block.timestamp && c.admitUntil > c.validFrom && c.claimUntil > c.admitUntil
            && c.claimUntil - block.timestamp <= MAX_CHANNEL_DURATION && c.permitDeadline >= block.timestamp); // bad channel times
        require(c.consumerNonce == consumerAllocationNonce[c.consumerOwner]++
            && c.providerNonce == providerAllocationNonce[c.providerOwner]++); // permit nonce
        bytes32 id = channelIdFor(c);
        require(_recover(id, permit.consumerSignature) == c.consumerOwner
            && _recover(id, permit.providerSignature) == c.providerOwner); // owner permits
        KeyGrant storage grant = keyGrants[c.consumerKey];
        require(grant.owner == c.consumerOwner && grant.active && grant.maxPerRequest >= c.maxFeePerRequest
            && (grant.validUntil == 0 || grant.validUntil >= c.claimUntil)); // channel key grant
        require(providerSigners[c.providerOwner][c.providerSigner]); // channel provider grant
        ChannelVersion storage version = channelVersions[c.channel][c.pricingVersion];
        require(version.config.active && version.pricingHash == c.pricingHash); // channel pricing
        uint256 eligible;
        for (uint256 i; i < judges.length; ++i) {
            address j = judges[i];
            if (j != c.consumerOwner && j != c.consumerKey && j != c.providerOwner && j != c.providerSigner
                && j != c.relay && j != c.relaySigner && j != c.pool && j != version.treasury && j != policy.bondPenaltyRecipient) ++eligible;
        }
        require(eligible >= adjudicationThreshold); // insufficient judges
        require(availableBalance[c.consumerOwner] >= c.capacity); // insufficient balance
        require(providerStake[c.providerOwner] - lockedStake[c.providerOwner] - allocatedStake[c.providerOwner] >= c.capacity); // insufficient stake
        capacityChannels[id] = CapacityChannel(c, 0, c.capacity, c.capacity, false);
        availableBalance[c.consumerOwner] -= c.capacity; totalAvailable -= c.capacity;
        totalAllocatedCredit += c.capacity; allocatedStake[c.providerOwner] += c.capacity;
        emit CapacityChannelOpened(id, c.consumerOwner, c.providerOwner, c.capacity, c.validFrom, c.claimUntil);
    }
    function closeExpiredChannel(bytes32 id) external nonReentrant {
        CapacityChannel storage slot = capacityChannels[id];
        require(slot.config.capacity > 0 && !slot.closed && block.timestamp > slot.config.claimUntil); // channel not expired
        slot.closed = true;
        uint256 credit = slot.creditRemaining; uint256 stake = slot.stakeRemaining;
        slot.creditRemaining = 0; slot.stakeRemaining = 0;
        totalAllocatedCredit -= credit; totalAvailable += credit; availableBalance[slot.config.consumerOwner] += credit;
        allocatedStake[slot.config.providerOwner] -= stake;
        emit CapacityChannelClosed(id, credit, stake);
    }

    function settlementKeyFor(bytes32 channelId, bytes32 requestId) public pure returns (bytes32) {
        return keccak256(abi.encode(channelId, requestId));
    }

    function authorizationStructHash(PaymentAuthorization calldata authorization) public pure returns (bytes32) {
        return keccak256(abi.encode(PAYMENT_AUTHORIZATION_TYPEHASH, authorization));
    }

    function authorizationDigest(PaymentAuthorization calldata authorization) public view returns (bytes32) {
        return _typedDataHash(authorizationStructHash(authorization));
    }

    function receiptStructHash(UsageReceipt calldata receipt) public pure returns (bytes32) {
        return keccak256(abi.encode(USAGE_RECEIPT_TYPEHASH, receipt));
    }

    function receiptDigest(UsageReceipt calldata receipt) public view returns (bytes32) {
        return _typedDataHash(receiptStructHash(receipt));
    }

    function settleReservedReceipt(SignedReceipt calldata input) external nonReentrant {
        _settle(input);
    }

    function settleReservedBatch(SignedReceipt[] calldata inputs) external nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE); // bad batch length
        for (uint256 i; i < inputs.length; ++i) {
            _settle(inputs[i]);
        }
    }

    function quote(bytes32 channel, uint64 pricingVersion, uint256 inputTokens, uint256 outputTokens)
        public
        view
        returns (uint256)
    {
        ChannelVersion storage version = channelVersions[channel][pricingVersion];
        require(pricingVersion != 0 && version.pricingHash != bytes32(0)); // unknown pricing
        uint256 fee =
            _quoteLeg(inputTokens, version.config.inputPer1K) + _quoteLeg(outputTokens, version.config.outputPer1K);
        return fee < version.config.minimumFee ? version.config.minimumFee : fee;
    }

    function channelPricingHash(bytes32 channel, uint64 version) external view returns (bytes32) {
        return channelVersions[channel][version].pricingHash;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == initialChainId ? initialDomainSeparator : _buildDomainSeparator();
    }

    function release(bytes32 key) external nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending); // not pending
        require(block.timestamp >= record.releaseAt); // release pending
        _release(key, record, Status.Released);
    }

    function openDispute(bytes32 key, bytes32 evidenceHash) external nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending); // not pending
        require(block.timestamp < record.releaseAt); // dispute window closed
        Dispute storage dispute = disputes[key];
        record.status = Status.Disputed;
        dispute.openedAt = uint64(block.timestamp);
        require(record.releaseAt <= type(uint64).max - policy.arbitrationTimeout); // timestamp overflow
        dispute.resolveAt = record.releaseAt + policy.arbitrationTimeout;
        _addReport(key, record, dispute, evidenceHash);
        emit DisputeOpened(key, dispute.resolveAt);
    }

    /// @notice Other reporters retain the entire original evidence window.
    /// @dev A first junk report cannot occupy all evidence slots. There is no
    /// report-array scan or capacity cap. Each reporter can submit once; evidence
    /// commitments from different reporters may coincide so front-running a hash
    /// cannot censor its genuine author. Judges must verify attribution off-chain.
    function submitEvidence(bytes32 key, bytes32 evidenceHash) external nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Disputed); // not disputed
        require(block.timestamp < record.releaseAt); // dispute window closed
        _addReport(key, record, disputes[key], evidenceHash);
    }

    function reportIdFor(bytes32 key, address reporter, bytes32 evidenceHash) public pure returns (bytes32) {
        return keccak256(abi.encode(key, reporter, evidenceHash));
    }

    /// @notice Only after evidence collection ends, each judge votes once.
    /// @dev A decisionHash commits to independently retained adjudication reasons;
    /// merely supplying a hash is not an on-chain proof of fraud. Confirmation
    /// requires a quorum for the SAME report, not merely different allegations.
    /// Judges must coordinate on that report before their irreversible votes;
    /// split votes can intentionally resolve through the nonpunitive timeout.
    function voteDispute(bytes32 key, bool confirmed, bytes32 reportId, bytes32 decisionHash) external nonReentrant {
        _voteDispute(key, confirmed, reportId, decisionHash, msg.sender);
    }

    /// @notice Submit a quorum of independently signed judge votes in one transaction.
    /// @dev This is the only automatic monetary execution path. Each permit is
    /// checked against the pinned adjudicator set, its monotonic nonce, and an
    /// expiry. The transaction must contain exactly the permits needed to reach
    /// quorum; extra permits after resolution revert atomically.
    function voteDisputeBySig(bytes32 key, DisputeVotePermit[] calldata permits) external nonReentrant {
        require(permits.length > 0 && permits.length <= MAX_ADJUDICATORS); // bad vote batch
        bool confirmed = permits[0].confirmed;
        bytes32 reportId = permits[0].reportId;
        bytes32 decisionHash = permits[0].decisionHash;
        require(decisionHash != bytes32(0)); // empty batch decision
        // Never combine the automatic monetary path with earlier manual votes:
        // their independently retained decision reasons are deliberately not
        // stored, so such a hybrid quorum could not prove decision consistency.
        require(permits.length == adjudicationThreshold);
        for (uint256 i; i < judges.length; ++i) {
            require(disputeVotes[key][judges[i]] == 0); // existing manual vote
        }
        for (uint256 i; i < permits.length; ++i) {
            DisputeVotePermit calldata permit = permits[i];
            require(permit.confirmed == confirmed && permit.reportId == reportId
                && permit.decisionHash == decisionHash); // inconsistent automatic verdict
            require(permit.deadline >= block.timestamp); // vote authorization expired
            bytes32 digest = _typedDataHash(keccak256(abi.encode(DISPUTE_VOTE_TYPEHASH, key, permit.confirmed,
                permit.reportId, permit.decisionHash, permit.nonce, permit.deadline)));
            address judge = _recover(digest, permit.signature);
            require(permit.nonce == adjudicatorNonces[judge]++); // vote authorization replayed
            _voteDispute(key, permit.confirmed, permit.reportId, permit.decisionHash, judge);
        }
    }

    function _voteDispute(bytes32 key, bool confirmed, bytes32 reportId, bytes32 decisionHash, address judge) internal {
        Settlement storage record = settlements[key];
        Dispute storage dispute = disputes[key];
        require(record.status == Status.Disputed); // not disputed
        require(block.timestamp >= record.releaseAt); // evidence window open
        require(block.timestamp < dispute.resolveAt); // adjudication expired
        require(
            isAdjudicator[judge] && !hasReported[key][judge] && _independent(record, address(0), judge)); // not independent judge
        require(disputeVotes[key][judge] == 0); // already voted
        require(decisionHash != bytes32(0)); // empty decision
        disputeVotes[key][judge] = confirmed ? 1 : 2;
        if (confirmed) {
            require(reports[key][reportId].reporter != address(0)); // unknown report
            ++confirmationVotes[key][reportId];
            voteReportId[key][judge] = reportId;
        } else {
            require(reportId == bytes32(0)); // unexpected report
            ++dispute.dismissVotes;
        }
        emit DisputeVote(key, judge, confirmed, reportId, decisionHash);
        if (confirmed && confirmationVotes[key][reportId] >= adjudicationThreshold) {
            dispute.winningReportId = reportId;
            _confirm(key, record, dispute);
        } else if (dispute.dismissVotes >= adjudicationThreshold) {
            _dismiss(key, record, dispute);
        }
    }

    /// @notice Permissionlessly return one refundable report bond to its owner.
    /// @dev No report-count loop can block a refund. Dismissed cases forfeit bonds;
    /// successful or inconclusive timed-out cases return them, not extra rewards.
    function claimDisputeBond(bytes32 key, bytes32 reportId) external nonReentrant {
        Status status = settlements[key].status;
        require(status == Status.Confirmed || status == Status.TimedOut); // bond not refundable
        Report storage report = reports[key][reportId];
        require(report.reporter != address(0)); // unknown report
        require(!report.bondClaimed); // bond already returned
        report.bondClaimed = true;
        totalReporterBonds -= policy.reporterBond;
        _credit(report.reporter, policy.reporterBond);
        emit DisputeBondReturned(key, reportId, report.reporter);
    }

    /// @notice Liveness escape hatch; silence is NOT a cheating verdict.
    /// @dev Timeout releases ordinary earnings and returns the reporter's bond,
    /// with no slash or bounty. Repeated bonded griefing is an explicit residual
    /// risk: production admission/reputation policy must address it separately.
    function resolveTimedOutDispute(bytes32 key) external nonReentrant {
        Settlement storage record = settlements[key];
        Dispute storage dispute = disputes[key];
        require(record.status == Status.Disputed); // not disputed
        require(block.timestamp >= dispute.resolveAt); // adjudication pending
        _release(key, record, Status.TimedOut);
        emit DisputeResolved(key, Status.TimedOut, 0, 0);
    }

    function _settle(SignedReceipt calldata input) internal {
        PaymentAuthorization calldata authorization = input.authorization;
        UsageReceipt calldata receipt = input.receipt;
        CapacityChannel storage slot = capacityChannels[authorization.channelId];
        OpenChannel storage c = slot.config;
        require(c.capacity > 0 && !slot.closed); // channel inactive
        require(authorization.requestId != bytes32(0) && authorization.requestHash != bytes32(0)); // bad request
        require(authorization.key == c.consumerKey); // wrong channel key
        require(authorization.issuedAt >= c.validFrom && authorization.issuedAt <= block.timestamp); // issued window
        require(authorization.executeBy >= authorization.issuedAt && authorization.executeBy <= c.admitUntil); // execution window
        require(authorization.deadline > authorization.executeBy && authorization.deadline >= block.timestamp
            && authorization.deadline <= c.claimUntil && authorization.deadline - authorization.issuedAt <= MAX_AUTHORIZATION_TTL); // claim window
        require(authorization.maxFee > 0 && authorization.maxFee <= c.maxFeePerRequest
            && slot.settledMaxFee + authorization.maxFee <= c.capacity); // channel capacity
        bytes32 authHash = authorizationStructHash(authorization);
        require(receipt.channelId == authorization.channelId && receipt.authorizationHash == authHash
            && receipt.responseHash != bytes32(0)); // receipt binding
        bytes32 dispatchHash = dispatchStructHash(authHash, authorization.channelId);
        require(receipt.dispatchHash == dispatchHash); // dispatch binding
        require(_recover(authorizationDigest(authorization), input.keySignature) == c.consumerKey); // bad key signature
        require(_recover(_typedDataHash(dispatchHash), input.relaySignature) == c.relaySigner); // bad dispatch signature
        require(_recover(receiptDigest(receipt), input.providerSignature) == c.providerSigner); // bad provider signature
        uint256 fee = quote(c.channel, c.pricingVersion, receipt.inputTokens, receipt.outputTokens);
        require(fee > 0 && receipt.actualFee == fee && fee <= authorization.maxFee); // fee mismatch
        bytes32 key = settlementKeyFor(authorization.channelId, authorization.requestId);
        require(!settled[key]); // request settled
        ChannelVersion storage version = channelVersions[c.channel][c.pricingVersion];
        Settlement storage record = settlements[key];
        record.owner = c.consumerOwner; record.key = c.consumerKey;
        record.provider = c.providerOwner; record.providerSigner = c.providerSigner;
        record.relay = c.relay; record.relaySigner = c.relaySigner;
        record.pool = c.pool; record.treasury = version.treasury;
        record.requestId = authorization.requestId; record.requestHash = authorization.requestHash;
        record.authorizationHash = authHash; record.responseHash = receipt.responseHash;
        record.grossFee = fee;
        record.providerAmount = _portion(fee, version.config.providerBps);
        record.relayAmount = _portion(fee, version.config.relayBps);
        record.poolAmount = c.pool == address(0) ? 0 : _portion(fee, version.config.poolBps);
        record.treasuryAmount = fee - record.providerAmount - record.relayAmount - record.poolAmount;
        record.settledAt = uint64(block.timestamp); record.releaseAt = _future(policy.disputeWindow);
        record.status = Status.Pending;
        settled[key] = true;
        slot.settledMaxFee += authorization.maxFee;
        slot.creditRemaining -= fee; totalAllocatedCredit -= fee; totalPendingFees += fee;
        slot.stakeRemaining -= fee; allocatedStake[c.providerOwner] -= fee; lockedStake[c.providerOwner] += fee;
        emit ReceiptEscrowed(key, authorization.requestId, c.consumerOwner, c.providerOwner, fee, record.releaseAt);
    }

    function _release(bytes32 key, Settlement storage record, Status status) internal {
        record.status = status;
        totalPendingFees -= record.grossFee;
        lockedStake[record.provider] -= record.grossFee;
        _credit(record.provider, record.providerAmount);
        _credit(record.relay, record.relayAmount);
        _credit(record.pool, record.poolAmount);
        _credit(record.treasury, record.treasuryAmount);
        emit SettlementReleased(key, status);
    }

    function _confirm(bytes32 key, Settlement storage record, Dispute storage dispute) internal {
        record.status = Status.Confirmed;
        totalPendingFees -= record.grossFee;
        // Refund the FULL fee first; the reporter never takes consumer escrow.
        availableBalance[record.owner] += record.grossFee;
        totalAvailable += record.grossFee;
        lockedStake[record.provider] -= record.grossFee;
        uint256 slash = _portion(record.grossFee, policy.slashBps);
        if (slash > policy.slashCap) slash = policy.slashCap;
        providerStake[record.provider] -= slash;
        // Attribute a slash to network-sponsored principal first. This keeps
        // the Provider's own funds separate in accounting and makes the
        // network capacity pool the explicit risk bearer for sponsored work.
        uint256 sponsoredSlash = slash > sponsoredStake[record.provider] ? sponsoredStake[record.provider] : slash;
        sponsoredStake[record.provider] -= sponsoredSlash;
        totalStake -= slash;
        sponsoredCapacityLimit += sponsoredSlash;
        uint256 bounty = _portion(slash, policy.reporterBountyBps);
        if (bounty > policy.stableBountyCap) bounty = policy.stableBountyCap;
        dispute.slashAmount = slash;
        dispute.stableBounty = bounty;
        address reporter = reports[key][dispute.winningReportId].reporter;
        _credit(reporter, bounty);
        _credit(policy.bondPenaltyRecipient, slash - bounty);
        emit DisputeResolved(key, Status.Confirmed, slash, bounty);
    }

    function _dismiss(bytes32 key, Settlement storage record, Dispute storage dispute) internal {
        _release(key, record, Status.Dismissed);
        totalReporterBonds -= dispute.totalBond;
        _credit(policy.bondPenaltyRecipient, dispute.totalBond);
        emit DisputeResolved(key, Status.Dismissed, 0, 0);
    }

    function _addReport(bytes32 key, Settlement storage record, Dispute storage dispute, bytes32 evidenceHash)
        internal
    {
        require(evidenceHash != bytes32(0)); // empty evidence
        require(msg.sender != record.provider && msg.sender != record.providerSigner); // provider self report
        require(!isAdjudicator[msg.sender]); // judge cannot report
        require(msg.sender != policy.bondPenaltyRecipient); // penalty recipient cannot report
        require(!hasReported[key][msg.sender]); // reporter already submitted
        bytes32 reportId = reportIdFor(key, msg.sender, evidenceHash);
        hasReported[key][msg.sender] = true;
        reports[key][reportId] = Report(msg.sender, evidenceHash, false);
        ++dispute.reportCount;
        dispute.totalBond += policy.reporterBond;
        totalReporterBonds += policy.reporterBond;
        _takeExact(stablecoin, msg.sender, policy.reporterBond);
        emit EvidenceSubmitted(key, reportId, msg.sender, evidenceHash, policy.reporterBond);
    }

    function _independent(Settlement storage record, address reporter, address judge) internal view returns (bool) {
        return judge != reporter && judge != record.owner && judge != record.key && judge != record.provider
            && judge != record.providerSigner && judge != record.relay && judge != record.relaySigner
            && judge != record.pool && judge != record.treasury && judge != policy.bondPenaltyRecipient;
    }

    function _eligibleCount(Settlement storage record, address reporter) internal view returns (uint256 count) {
        for (uint256 i; i < judges.length; ++i) {
            if (_independent(record, reporter, judges[i])) ++count;
        }
    }

    function _addChannelVersion(bytes32 channel, ChannelConfig memory config) internal returns (uint64 version) {
        version = latestChannelVersion[channel] + 1;
        bytes32 pricingHash = keccak256(abi.encode(channel, version, treasury, config));
        channelVersions[channel][version] = ChannelVersion(config, treasury, pricingHash);
        latestChannelVersion[channel] = version;
        emit ChannelVersionAdded(channel, version, pricingHash, config.active);
    }

    function _validateConfig(ChannelConfig memory config) internal pure {
        require(uint256(config.providerBps) + config.relayBps + config.poolBps + config.treasuryBps == BPS); // bad bps
    }

    function _quoteLeg(uint256 tokens, uint256 rate) internal pure returns (uint256) {
        if (tokens == 0 || rate == 0) return 0;
        uint256 product = tokens * rate;
        return product / 1000 + (product % 1000 == 0 ? 0 : 1);
    }

    function _portion(uint256 amount, uint16 bps) internal pure returns (uint256) {
        return amount / BPS * bps + amount % BPS * bps / BPS;
    }

    function _credit(address account, uint256 amount) internal {
        if (amount == 0) return;
        require(account != address(0) && account != address(this)); // bad credit
        claimableBalance[account] += amount;
        totalClaimable += amount;
    }

    function _future(uint64 delay) internal view returns (uint64) {
        require(block.timestamp <= type(uint64).max - delay); // timestamp overflow
        return uint64(block.timestamp + delay);
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("MycoMesh Settlement")),
                keccak256(bytes("10")),
                block.chainid,
                address(this)
            )
        );
    }

    function _typedDataHash(bytes32 structHash) internal view returns (bytes32) {
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
        if (uint256(s) > SECP256K1_HALF_ORDER) return address(0);
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }

    function _takeExact(IMycoERC20V10 token, address from, uint256 amount) internal {
        uint256 beforeHere = token.balanceOf(address(this));
        uint256 beforeThere = token.balanceOf(from);
        require(from != address(this) && beforeThere >= amount); // bad token payer
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IMycoERC20V10.transferFrom.selector, from, address(this), amount));
        require(ok && (data.length == 0 || (data.length == 32 && abi.decode(data, (bool))))); // transferFrom failed
        require(
            token.balanceOf(address(this)) == beforeHere + amount && token.balanceOf(from) == beforeThere - amount); // unsupported token
    }

    function _sendExact(IMycoERC20V10 token, address to, uint256 amount) internal {
        uint256 beforeHere = token.balanceOf(address(this));
        uint256 beforeThere = token.balanceOf(to);
        require(to != address(0) && to != address(this) && beforeHere >= amount); // bad token recipient
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IMycoERC20V10.transfer.selector, to, amount));
        require(ok && (data.length == 0 || (data.length == 32 && abi.decode(data, (bool))))); // transfer failed
        require(
            token.balanceOf(address(this)) == beforeHere - amount && token.balanceOf(to) == beforeThere + amount); // unsupported token
    }
}
