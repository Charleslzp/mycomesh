import { parseAbi } from "viem";

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
  "function deposit(uint256 amount)",
  "function withdraw(uint256 amount)",
  "function releaseExpiredReservation(bytes32 reservationId)",
  "event Deposited(address indexed consumer, uint256 amount)",
  "event Withdrawn(address indexed consumer, uint256 amount)",
  "event ReservationCreated(bytes32 indexed reservationId, address indexed consumer, address indexed provider, bytes32 requestHash, uint256 amount, uint64 expiresAt, bool providerFallbackAllowed)",
  "event ReservationReleased(bytes32 indexed reservationId, address indexed consumer, uint256 amount)",
  "event ReceiptSettled(bytes32 indexed receiptHash, bytes32 indexed reservationId, address indexed consumer, address provider, uint256 grossFee)",
]);

export const rewardTokenV2Abi = parseAbi([
  "function mintAuthority() view returns (address)",
]);
