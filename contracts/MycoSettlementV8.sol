// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoERC20V8 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Stateless prepaid settlement with separate Provider payout and signer identities.
/// @dev Payout wallets authorize revocable server signers once. Provider servers
/// never need the payout wallet private key during inference.
contract MycoSettlementV8 {
    uint16 public constant BPS = 10_000;
    uint256 public constant MAX_BATCH_SIZE = 32;
    uint256 public constant MAX_AUTHORIZATION_TTL = 1 hours;
    uint256 public constant WITHDRAWAL_DELAY = 15 minutes;
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant PAYMENT_AUTHORIZATION_TYPEHASH = keccak256(
        "PaymentAuthorization(bytes32 requestId,bytes32 requestHash,address key,address relay,address relaySigner,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,uint256 maxFee,uint64 issuedAt,uint64 deadline)"
    );
    bytes32 public constant USAGE_RECEIPT_TYPEHASH = keccak256(
        "UsageReceipt(bytes32 authorizationHash,bytes32 responseHash,address provider,address providerSigner,address relay,address pool,uint256 inputTokens,uint256 outputTokens,uint256 actualFee)"
    );

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
        bytes32 requestId;
        bytes32 requestHash;
        address key;
        address relay;
        address relaySigner;
        bytes32 channel;
        uint64 pricingVersion;
        bytes32 pricingHash;
        uint256 maxFee;
        uint64 issuedAt;
        uint64 deadline;
    }

    struct UsageReceipt {
        bytes32 authorizationHash;
        bytes32 responseHash;
        address provider;
        address providerSigner;
        address relay;
        address pool;
        uint256 inputTokens;
        uint256 outputTokens;
        uint256 actualFee;
    }

    struct SignedReceipt {
        PaymentAuthorization authorization;
        UsageReceipt receipt;
        bytes keySignature;
        bytes providerSignature;
        bytes relaySignature;
    }

    IMycoERC20V8 public immutable stablecoin;
    uint256 private immutable initialChainId;
    bytes32 private immutable initialDomainSeparator;
    address public governance;
    address public treasury;

    mapping(bytes32 => uint64) public latestChannelVersion;
    mapping(bytes32 => mapping(uint64 => ChannelVersion)) public channelVersions;
    mapping(address => uint256) public availableBalance;
    mapping(address => uint256) public claimableBalance;
    mapping(address => KeyGrant) public keyGrants;
    mapping(address => mapping(address => bool)) public providerSigners;
    mapping(address => Withdrawal) public withdrawals;
    mapping(bytes32 => bool) public settled;
    uint256 public totalClaimable;
    bool private entered;

    event Deposited(address indexed account, uint256 amount);
    event WithdrawalRequested(address indexed account, uint256 amount, uint256 availableAt);
    event WithdrawalCancelled(address indexed account);
    event Withdrawn(address indexed account, uint256 amount);
    event KeyRegistered(address indexed owner, address indexed key, uint256 maxPerRequest, uint256 validUntil);
    event KeyRevoked(address indexed owner, address indexed key);
    event ProviderSignerAuthorized(address indexed provider, address indexed signer);
    event ProviderSignerRevoked(address indexed provider, address indexed signer);
    event ReceiptSettled(
        bytes32 indexed settlementKey,
        bytes32 indexed requestId,
        address indexed owner,
        address provider,
        address providerSigner,
        address relay,
        uint256 actualFee
    );
    event PayoutClaimed(address indexed account, uint256 amount);
    event ChannelVersionAdded(bytes32 indexed channel, uint64 indexed version, bytes32 pricingHash, bool active);

    modifier nonReentrant() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "not governance");
        _;
    }

    constructor(
        address stablecoin_,
        address treasury_,
        address governance_,
        bytes32 initialChannel_,
        ChannelConfig memory initialConfig_
    ) {
        require(stablecoin_ != address(0) && stablecoin_.code.length > 0, "bad stablecoin");
        require(treasury_ != address(0) && governance_ != address(0), "zero authority");
        require(initialChannel_ != bytes32(0), "zero channel");
        _validateConfig(initialConfig_);
        require(initialConfig_.active, "inactive channel");

        stablecoin = IMycoERC20V8(stablecoin_);
        treasury = treasury_;
        governance = governance_;
        initialChainId = block.chainid;
        initialDomainSeparator = _buildDomainSeparator();
        _addChannelVersion(initialChannel_, initialConfig_);
    }

    function addChannelVersion(bytes32 channel, ChannelConfig calldata config)
        external
        onlyGovernance
        returns (uint64 version)
    {
        require(channel != bytes32(0), "zero channel");
        _validateConfig(config);
        version = _addChannelVersion(channel, config);
    }

    function setTreasury(address nextTreasury) external onlyGovernance {
        require(nextTreasury != address(0) && nextTreasury != address(this), "bad treasury");
        treasury = nextTreasury;
    }

    function transferGovernance(address nextGovernance) external onlyGovernance {
        require(nextGovernance != address(0), "zero governance");
        governance = nextGovernance;
    }

    function deposit(uint256 amount) external nonReentrant {
        require(amount > 0, "zero amount");
        uint256 beforeBalance = stablecoin.balanceOf(address(this));
        _safeTransferFrom(msg.sender, address(this), amount);
        require(stablecoin.balanceOf(address(this)) == beforeBalance + amount, "unsupported token");
        availableBalance[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
    }

    function registerKey(address key, uint256 maxPerRequest, uint64 validUntil) external {
        require(key != address(0) && key.code.length == 0, "bad key");
        require(key != msg.sender && key != address(this), "bad key owner");
        require(maxPerRequest > 0, "zero key limit");
        require(validUntil == 0 || validUntil > block.timestamp, "key expired");
        KeyGrant storage previous = keyGrants[key];
        require(previous.owner == address(0) || previous.owner == msg.sender, "key owned");
        keyGrants[key] = KeyGrant({
            owner: msg.sender,
            maxPerRequest: maxPerRequest,
            validUntil: validUntil,
            active: true
        });
        emit KeyRegistered(msg.sender, key, maxPerRequest, validUntil);
    }

    function revokeKey(address key) external {
        KeyGrant storage grant = keyGrants[key];
        require(grant.owner == msg.sender, "not key owner");
        require(grant.active, "key inactive");
        grant.active = false;
        emit KeyRevoked(msg.sender, key);
    }

    function authorizeProviderSigner(address signer) external {
        require(signer != address(0) && signer.code.length == 0, "bad provider signer");
        require(signer != msg.sender && signer != address(this), "bad provider signer");
        require(!providerSigners[msg.sender][signer], "signer authorized");
        providerSigners[msg.sender][signer] = true;
        emit ProviderSignerAuthorized(msg.sender, signer);
    }

    function revokeProviderSigner(address signer) external {
        require(providerSigners[msg.sender][signer], "signer inactive");
        providerSigners[msg.sender][signer] = false;
        emit ProviderSignerRevoked(msg.sender, signer);
    }

    function requestWithdrawal(uint256 amount) external {
        require(amount > 0 && amount <= availableBalance[msg.sender], "bad withdrawal");
        uint64 availableAt = uint64(block.timestamp + WITHDRAWAL_DELAY);
        withdrawals[msg.sender] = Withdrawal({amount: amount, availableAt: availableAt});
        emit WithdrawalRequested(msg.sender, amount, availableAt);
    }

    function cancelWithdrawal() external {
        require(withdrawals[msg.sender].amount > 0, "no withdrawal");
        delete withdrawals[msg.sender];
        emit WithdrawalCancelled(msg.sender);
    }

    function withdraw() external nonReentrant {
        Withdrawal memory request = withdrawals[msg.sender];
        require(request.amount > 0 && block.timestamp >= request.availableAt, "withdrawal pending");
        require(availableBalance[msg.sender] >= request.amount, "balance changed");
        delete withdrawals[msg.sender];
        availableBalance[msg.sender] -= request.amount;
        _safeTransfer(msg.sender, request.amount);
        emit Withdrawn(msg.sender, request.amount);
    }

    function claim() external nonReentrant returns (uint256 amount) {
        amount = claimableBalance[msg.sender];
        require(amount > 0, "no claimable balance");
        claimableBalance[msg.sender] = 0;
        totalClaimable -= amount;
        _safeTransfer(msg.sender, amount);
        emit PayoutClaimed(msg.sender, amount);
    }

    function settlementKeyFor(address owner, address key, bytes32 requestId) public pure returns (bytes32) {
        return keccak256(abi.encode(owner, key, requestId));
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

    function settleSignedReceipt(SignedReceipt calldata input) external nonReentrant {
        _settle(input);
    }

    function settleSignedBatch(SignedReceipt[] calldata inputs) external nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE, "bad batch length");
        for (uint256 i = 0; i < inputs.length; ++i) _settle(inputs[i]);
    }

    function quote(bytes32 channel, uint64 pricingVersion, uint256 inputTokens, uint256 outputTokens)
        public
        view
        returns (uint256)
    {
        ChannelVersion storage version = channelVersions[channel][pricingVersion];
        require(pricingVersion != 0 && version.pricingHash != bytes32(0), "unknown pricing");
        uint256 fee = _quoteLeg(inputTokens, version.config.inputPer1K)
            + _quoteLeg(outputTokens, version.config.outputPer1K);
        return fee < version.config.minimumFee ? version.config.minimumFee : fee;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == initialChainId ? initialDomainSeparator : _buildDomainSeparator();
    }

    function _settle(SignedReceipt calldata input) internal {
        PaymentAuthorization calldata authorization = input.authorization;
        UsageReceipt calldata receipt = input.receipt;
        require(authorization.requestId != bytes32(0) && authorization.requestHash != bytes32(0), "bad request");
        require(
            authorization.relay != address(0) && authorization.relaySigner != address(0)
                && receipt.provider != address(0) && receipt.providerSigner != address(0),
            "zero payee"
        );
        require(authorization.issuedAt <= block.timestamp, "future authorization");
        require(authorization.deadline >= block.timestamp, "authorization expired");
        require(
            authorization.deadline > authorization.issuedAt
                && authorization.deadline - authorization.issuedAt <= MAX_AUTHORIZATION_TTL,
            "authorization ttl"
        );
        require(receipt.authorizationHash == authorizationStructHash(authorization), "authorization hash");
        require(receipt.relay == authorization.relay, "relay mismatch");
        require(receipt.responseHash != bytes32(0), "zero response");

        KeyGrant storage grant = keyGrants[authorization.key];
        require(grant.owner != address(0) && grant.active, "key inactive");
        require(grant.validUntil == 0 || block.timestamp <= grant.validUntil, "key expired");
        require(authorization.maxFee > 0 && authorization.maxFee <= grant.maxPerRequest, "key limit");
        require(_recover(authorizationDigest(authorization), input.keySignature) == authorization.key, "bad key signature");
        bytes32 usageDigest = receiptDigest(receipt);
        require(_recover(usageDigest, input.providerSignature) == receipt.providerSigner, "bad provider signature");
        require(providerSigners[receipt.provider][receipt.providerSigner], "provider signer unauthorized");
        require(_recover(usageDigest, input.relaySignature) == authorization.relaySigner, "bad relay signature");

        ChannelVersion storage version = channelVersions[authorization.channel][authorization.pricingVersion];
        require(version.config.active, "inactive pricing");
        require(version.pricingHash == authorization.pricingHash, "pricing hash");
        uint256 actualFee = quote(
            authorization.channel,
            authorization.pricingVersion,
            receipt.inputTokens,
            receipt.outputTokens
        );
        require(receipt.actualFee == actualFee && actualFee <= authorization.maxFee, "fee mismatch");

        bytes32 settlementKey = settlementKeyFor(grant.owner, authorization.key, authorization.requestId);
        require(!settled[settlementKey], "request settled");
        require(availableBalance[grant.owner] >= actualFee, "insufficient balance");
        settled[settlementKey] = true;
        availableBalance[grant.owner] -= actualFee;
        totalClaimable += actualFee;

        ChannelConfig storage config = version.config;
        uint256 providerAmount = actualFee * config.providerBps / BPS;
        uint256 relayAmount = actualFee * config.relayBps / BPS;
        uint256 poolAmount = actualFee * config.poolBps / BPS;
        uint256 treasuryAmount = actualFee - providerAmount - relayAmount - poolAmount;
        if (receipt.pool == address(0)) {
            treasuryAmount += poolAmount;
            poolAmount = 0;
        }
        _credit(receipt.provider, providerAmount);
        _credit(receipt.relay, relayAmount);
        _credit(receipt.pool, poolAmount);
        _credit(version.treasury, treasuryAmount);
        emit ReceiptSettled(
            settlementKey,
            authorization.requestId,
            grant.owner,
            receipt.provider,
            receipt.providerSigner,
            receipt.relay,
            actualFee
        );
    }

    function _addChannelVersion(bytes32 channel, ChannelConfig memory config) internal returns (uint64 version) {
        version = latestChannelVersion[channel] + 1;
        bytes32 pricingHash = keccak256(abi.encode(channel, version, treasury, config));
        channelVersions[channel][version] = ChannelVersion({
            config: config,
            treasury: treasury,
            pricingHash: pricingHash
        });
        latestChannelVersion[channel] = version;
        emit ChannelVersionAdded(channel, version, pricingHash, config.active);
    }

    function _validateConfig(ChannelConfig memory config) internal pure {
        require(
            uint256(config.providerBps) + config.relayBps + config.poolBps + config.treasuryBps == BPS,
            "bad bps"
        );
    }

    function _quoteLeg(uint256 tokens, uint256 rate) internal pure returns (uint256) {
        if (tokens == 0 || rate == 0) return 0;
        uint256 product = tokens * rate;
        return product / 1000 + (product % 1000 == 0 ? 0 : 1);
    }

    function _credit(address account, uint256 amount) internal {
        if (account != address(0) && amount > 0) claimableBalance[account] += amount;
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("MycoMesh Settlement")),
                keccak256(bytes("8")),
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

    function _safeTransfer(address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(stablecoin).call(
            abi.encodeWithSelector(IMycoERC20V8.transfer.selector, to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function _safeTransferFrom(address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(stablecoin).call(
            abi.encodeWithSelector(IMycoERC20V8.transferFrom.selector, from, to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transferFrom failed");
    }
}
