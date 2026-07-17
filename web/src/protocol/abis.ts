import { parseAbi } from "viem";

export const testUsdcAbi = parseAbi([
  "function mint(address to, uint256 amount)",
]);

export const erc20Abi = parseAbi([
  "function balanceOf(address account) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
]);

export const settlementV3Abi = parseAbi([
  "function stablecoin() view returns (address)",
  "function rewardToken() view returns (address)",
  "function treasury() view returns (address)",
  "function governance() view returns (address)",
  "function rewardsEnabled() view returns (bool)",
  "function availableBalance(address consumer) view returns (uint256)",
  "function lockedBalance(address consumer) view returns (uint256)",
  "function prepaidBalance(address consumer) view returns (uint256)",
  "function reservationIdFor(address consumer, bytes32 reservationSalt) view returns (bytes32)",
  "function latestChannelVersion(bytes32 channel) view returns (uint64)",
  "function channelPricingHash(bytes32 channel, uint64 pricingVersion) view returns (bytes32)",
  "function quote(bytes32 channel, uint64 pricingVersion, uint256 inputTokens, uint256 outputTokens) view returns (uint256)",
  "function deposit(uint256 amount)",
  "function withdraw(uint256 amount)",
  "function createReservation(bytes32 reservationSalt, address provider, bytes32 channel, bytes32 requestHash, uint64 pricingVersion, uint256 amount, uint64 expiresAt, bool providerFallbackAllowed) returns (bytes32 reservationId)",
  "function settleSignedReceipt(((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,address,address,uint256,uint256,uint256),bytes,bytes) input)",
  "function releaseExpiredReservation(bytes32 reservationId)",
  "event Deposited(address indexed account, uint256 requestedAmount, uint256 receivedAmount)",
  "event Withdrawn(address indexed consumer, uint256 amount)",
  "event ReservationCreated(bytes32 indexed reservationId, address indexed consumer, address indexed provider, bytes32 channel, bytes32 requestHash, uint64 pricingVersion, uint256 amount, uint64 expiresAt, bool providerFallbackAllowed)",
  "event ReservationReleased(bytes32 indexed reservationId, address indexed consumer, uint256 amount)",
  "event ReceiptSettled(bytes32 indexed receiptHash, bytes32 indexed reservationId, address indexed consumer, address provider, uint256 grossFee)",
]);

export const rewardTokenV2Abi = parseAbi([
  "function mintAuthority() view returns (address)",
]);
