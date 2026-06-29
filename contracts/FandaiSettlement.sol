// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Legacy v1 compatibility contract. MycoMesh v2 uses MycoSettlementV2.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IFandaiToken {
    function mint(address to, uint256 amount) external;
}

contract FandaiSettlement {
    uint16 public constant BPS = 10_000;

    struct ChannelConfig {
        uint256 inputPer1K;
        uint256 outputPer1K;
        uint256 minimumFee;
        uint16 providerBps;
        uint16 relayBps;
        uint16 poolBps;
        uint16 treasuryBps;
        uint256 rewardPerTreasuryUnit;
        bool active;
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
        uint256 rewardAmount;
        uint256 settledAt;
    }

    IERC20Like public immutable stablecoin;
    IFandaiToken public immutable rewardToken;
    address public owner;
    address public treasury;

    mapping(address => bool) public operators;
    mapping(bytes32 => ChannelConfig) public channels;
    mapping(bytes32 => Settlement) public settlements;

    event OperatorUpdated(address indexed operator, bool allowed);
    event TreasuryUpdated(address indexed treasury);
    event ChannelUpdated(bytes32 indexed channel);
    event OwnershipTransferred(address indexed previousOwner, address indexed nextOwner);
    event ReceiptSettled(
        bytes32 indexed receiptHash,
        bytes32 indexed channel,
        address indexed consumer,
        address provider,
        address relay,
        uint256 grossFee,
        uint256 rewardAmount
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "not operator");
        _;
    }

    constructor(address stablecoin_, address rewardToken_, address treasury_) {
        require(stablecoin_ != address(0), "zero stablecoin");
        require(rewardToken_ != address(0), "zero reward");
        require(treasury_ != address(0), "zero treasury");
        owner = msg.sender;
        stablecoin = IERC20Like(stablecoin_);
        rewardToken = IFandaiToken(rewardToken_);
        treasury = treasury_;
        operators[msg.sender] = true;
        emit OwnershipTransferred(address(0), msg.sender);
        emit OperatorUpdated(msg.sender, true);
        emit TreasuryUpdated(treasury_);
    }

    function transferOwnership(address nextOwner) external onlyOwner {
        require(nextOwner != address(0), "zero owner");
        address previousOwner = owner;
        owner = nextOwner;
        operators[nextOwner] = true;
        emit OwnershipTransferred(previousOwner, nextOwner);
        emit OperatorUpdated(nextOwner, true);
    }

    function setOperator(address operator, bool allowed) external onlyOwner {
        operators[operator] = allowed;
        emit OperatorUpdated(operator, allowed);
    }

    function setTreasury(address nextTreasury) external onlyOwner {
        require(nextTreasury != address(0), "zero treasury");
        treasury = nextTreasury;
        emit TreasuryUpdated(nextTreasury);
    }

    function setChannel(bytes32 channel, ChannelConfig calldata config) external onlyOwner {
        require(channel != bytes32(0), "zero channel");
        require(
            uint256(config.providerBps) + config.relayBps + config.poolBps + config.treasuryBps == BPS,
            "bad split"
        );
        channels[channel] = config;
        emit ChannelUpdated(channel);
    }

    function quote(bytes32 channel, uint256 inputTokens, uint256 outputTokens) public view returns (uint256) {
        ChannelConfig memory config = channels[channel];
        require(config.active, "inactive channel");
        uint256 usageFee = ((inputTokens * config.inputPer1K) + (outputTokens * config.outputPer1K)) / 1000;
        return usageFee < config.minimumFee ? config.minimumFee : usageFee;
    }

    function settleReceipt(
        bytes32 receiptHash,
        bytes32 channel,
        address consumer,
        address provider,
        address relay,
        address pool,
        uint256 inputTokens,
        uint256 outputTokens
    ) external onlyOperator {
        require(receiptHash != bytes32(0), "zero receipt");
        require(settlements[receiptHash].settledAt == 0, "settled");
        require(consumer != address(0), "zero consumer");
        require(provider != address(0), "zero provider");

        ChannelConfig memory config = channels[channel];
        require(config.active, "inactive channel");

        Settlement memory settlement = Settlement({
            consumer: consumer,
            provider: provider,
            relay: relay,
            pool: pool,
            channel: channel,
            grossFee: quote(channel, inputTokens, outputTokens),
            providerAmount: 0,
            relayAmount: 0,
            poolAmount: 0,
            treasuryAmount: 0,
            rewardAmount: 0,
            settledAt: block.timestamp
        });
        settlement.providerAmount = (settlement.grossFee * config.providerBps) / BPS;
        settlement.relayAmount = (settlement.grossFee * config.relayBps) / BPS;
        settlement.poolAmount = (settlement.grossFee * config.poolBps) / BPS;
        settlement.treasuryAmount =
            settlement.grossFee -
            settlement.providerAmount -
            settlement.relayAmount -
            settlement.poolAmount;

        require(stablecoin.transferFrom(consumer, address(this), settlement.grossFee), "pull failed");
        require(stablecoin.transfer(provider, settlement.providerAmount), "provider transfer failed");
        if (relay != address(0) && settlement.relayAmount > 0) {
            require(stablecoin.transfer(relay, settlement.relayAmount), "relay transfer failed");
        } else {
            settlement.treasuryAmount += settlement.relayAmount;
            settlement.relayAmount = 0;
        }
        if (pool != address(0) && settlement.poolAmount > 0) {
            require(stablecoin.transfer(pool, settlement.poolAmount), "pool transfer failed");
        } else {
            settlement.treasuryAmount += settlement.poolAmount;
            settlement.poolAmount = 0;
        }
        settlement.rewardAmount = settlement.treasuryAmount * config.rewardPerTreasuryUnit;
        require(stablecoin.transfer(treasury, settlement.treasuryAmount), "treasury transfer failed");
        if (settlement.rewardAmount > 0) {
            rewardToken.mint(provider, settlement.rewardAmount);
        }

        settlements[receiptHash] = settlement;

        emit ReceiptSettled(
            receiptHash,
            channel,
            consumer,
            provider,
            relay,
            settlement.grossFee,
            settlement.rewardAmount
        );
    }
}
