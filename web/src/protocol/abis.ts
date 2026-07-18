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

// V4 keeps the V3 ABI above untouched. A session locks one bounded escrow on
// activation; individual receipts are relayed later and never require a
// browser wallet signature or a confirmation-depth wait.
export const settlementV4Abi = parseAbi([
  "function stablecoin() view returns (address)",
  "function rewardToken() view returns (address)",
  "function treasury() view returns (address)",
  "function governance() view returns (address)",
  "function rewardsEnabled() view returns (bool)",
  "function availableBalance(address consumer) view returns (uint256)",
  "function lockedBalance(address consumer) view returns (uint256)",
  "function prepaidBalance(address consumer) view returns (uint256)",
  "function sessionIdFor(address consumer, bytes32 sessionSalt) view returns (bytes32)",
  "function latestChannelVersion(bytes32 channel) view returns (uint64)",
  "function channelPricingHash(bytes32 channel, uint64 pricingVersion) view returns (bytes32)",
  "function quote(bytes32 channel, uint64 pricingVersion, uint256 inputTokens, uint256 outputTokens) view returns (uint256)",
  "function deposit(uint256 amount)",
  "function withdraw(uint256 amount)",
  "function openSession(bytes32 sessionSalt, address provider, address sessionKey, bytes32 channel, uint64 pricingVersion, uint256 maxAmount, uint64 expiresAt) returns (bytes32 sessionId)",
  "function requestClose(bytes32 sessionId)",
  "function cancelClose(bytes32 sessionId)",
  "function closeSession(bytes32 sessionId)",
  "function sessionRemaining(bytes32 sessionId) view returns (uint256)",
  "function sessionInfo(bytes32 sessionId) view returns ((address consumer,address provider,address sessionKey,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,uint64 openedAt,uint64 expiresAt,uint64 closeRequestedAt,uint256 maxAmount,uint256 spent,uint256 nextSequence,bool closed))",
  "function settleSignedReceipt(((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,address,address,uint256,uint256,uint256,uint256,uint256),bytes,bytes) input)",
  "function settleSignedBatch(((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,address,address,uint256,uint256,uint256,uint256,uint256),bytes,bytes)[] inputs)",
  "event Deposited(address indexed account, uint256 requestedAmount, uint256 receivedAmount)",
  "event Withdrawn(address indexed account, uint256 amount)",
  "event SessionOpened(bytes32 indexed sessionId, address indexed consumer, address indexed provider, address sessionKey, bytes32 channel, uint64 pricingVersion, bytes32 pricingHash, uint256 maxAmount, uint256 expiresAt)",
  "event SessionCloseRequested(bytes32 indexed sessionId, uint256 closeAt, uint256 closeableAt)",
  "event SessionClosed(bytes32 indexed sessionId, address indexed consumer, uint256 spent, uint256 refunded)",
  "event ReceiptSettled(bytes32 indexed receiptHash, bytes32 indexed sessionId, address indexed consumer, address provider, uint256 sequence, uint256 grossFee)",
]);

export const rewardTokenV2Abi = parseAbi([
  "function mintAuthority() view returns (address)",
]);
