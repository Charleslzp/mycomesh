import { getAddress, isAddress } from "viem";

export const RESERVATION_RECOVERY_STORAGE_KEY = "mycomesh.reservation-recovery.v1";

const RECOVERY_SCHEMA = "mycomesh.reservation.recovery.v1" as const;
const MAX_RECOVERY_RECORDS = 24;
const MAX_STORAGE_BYTES = 64 * 1024;
const MAX_DATE_MILLISECONDS = 8_640_000_000_000_000;
const BYTES32_PATTERN = /^0x[0-9a-fA-F]{64}$/;

export interface ReservationRecoveryRecord {
  schema: typeof RECOVERY_SCHEMA;
  chainId: number;
  settlement: `0x${string}`;
  consumer: `0x${string}`;
  reservationId: `0x${string}`;
  expiresAt: number;
  transactionHash: `0x${string}` | null;
  createdAt: number;
}

export interface ReservationRecoveryScope {
  chainId: number;
  settlement: string;
  consumer: string;
  reservationId?: string;
}

export function reservationIdFromQuery(searchParams: URLSearchParams): string {
  return (searchParams.get("reservation_id") ?? searchParams.get("reservation") ?? "").trim();
}

function browserStorage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function resolveStorage(storage: Storage | null | undefined): Storage | null {
  return storage === undefined ? browserStorage() : storage;
}

function bytes32(value: unknown): `0x${string}` | null {
  if (typeof value !== "string" || !BYTES32_PATTERN.test(value)) return null;
  return value.toLowerCase() as `0x${string}`;
}

function address(value: unknown): `0x${string}` | null {
  if (typeof value !== "string" || !isAddress(value, { strict: false })) return null;
  return getAddress(value);
}

function normalizeRecord(value: unknown): ReservationRecoveryRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Partial<ReservationRecoveryRecord>;
  const settlement = address(record.settlement);
  const consumer = address(record.consumer);
  const reservationId = bytes32(record.reservationId);
  const transactionHash = record.transactionHash === null ? null : bytes32(record.transactionHash);
  if (
    record.schema !== RECOVERY_SCHEMA ||
    !Number.isSafeInteger(record.chainId) ||
    Number(record.chainId) <= 0 ||
    !settlement ||
    !consumer ||
    !reservationId ||
    (record.transactionHash !== null && !transactionHash) ||
    !Number.isSafeInteger(record.expiresAt) ||
    Number(record.expiresAt) <= 0 ||
    Number(record.expiresAt) > MAX_DATE_MILLISECONDS / 1000 ||
    !Number.isSafeInteger(record.createdAt) ||
    Number(record.createdAt) <= 0 ||
    Number(record.createdAt) > MAX_DATE_MILLISECONDS
  ) {
    return null;
  }
  return {
    schema: RECOVERY_SCHEMA,
    chainId: Number(record.chainId),
    settlement,
    consumer,
    reservationId,
    expiresAt: Number(record.expiresAt),
    transactionHash,
    createdAt: Number(record.createdAt),
  };
}

function recordKey(record: Pick<ReservationRecoveryRecord, "chainId" | "settlement" | "consumer" | "reservationId">): string {
  return [
    record.chainId,
    record.settlement.toLowerCase(),
    record.consumer.toLowerCase(),
    record.reservationId.toLowerCase(),
  ].join(":");
}

function writeRecords(records: readonly ReservationRecoveryRecord[], storage: Storage | null): void {
  if (!storage) return;
  try {
    storage.setItem(RESERVATION_RECOVERY_STORAGE_KEY, JSON.stringify(records));
  } catch {
    // Recovery remains available in component state when browser storage is blocked or full.
  }
}

export function readReservationRecoveries(
  storage: Storage | null | undefined = undefined,
): ReservationRecoveryRecord[] {
  const target = resolveStorage(storage);
  if (!target) return [];
  try {
    const raw = target.getItem(RESERVATION_RECOVERY_STORAGE_KEY);
    if (!raw || raw.length > MAX_STORAGE_BYTES) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const records = parsed
      .map(normalizeRecord)
      .filter((record): record is ReservationRecoveryRecord => record !== null)
      .sort((left, right) => right.createdAt - left.createdAt);
    const unique = new Map<string, ReservationRecoveryRecord>();
    for (const record of records) {
      const key = recordKey(record);
      if (!unique.has(key)) unique.set(key, record);
      if (unique.size >= MAX_RECOVERY_RECORDS) break;
    }
    return [...unique.values()];
  } catch {
    return [];
  }
}

export function saveReservationRecovery(
  value: ReservationRecoveryRecord,
  storage: Storage | null | undefined = undefined,
): ReservationRecoveryRecord {
  const normalized = normalizeRecord(value);
  if (!normalized) throw new Error("Reservation recovery metadata is invalid.");
  const target = resolveStorage(storage);
  const key = recordKey(normalized);
  const records = readReservationRecoveries(target).filter((record) => recordKey(record) !== key);
  writeRecords([normalized, ...records].slice(0, MAX_RECOVERY_RECORDS), target);
  return normalized;
}

export function findReservationRecovery(
  scope: ReservationRecoveryScope,
  options: { requireTransaction?: boolean } = {},
  storage: Storage | null | undefined = undefined,
): ReservationRecoveryRecord | null {
  const settlement = address(scope.settlement);
  const consumer = address(scope.consumer);
  const reservationId = scope.reservationId === undefined ? null : bytes32(scope.reservationId);
  if (!Number.isSafeInteger(scope.chainId) || scope.chainId <= 0 || !settlement || !consumer) return null;
  if (scope.reservationId !== undefined && !reservationId) return null;
  return readReservationRecoveries(storage).find((record) =>
    record.chainId === scope.chainId &&
    record.settlement.toLowerCase() === settlement.toLowerCase() &&
    record.consumer.toLowerCase() === consumer.toLowerCase() &&
    (!reservationId || record.reservationId === reservationId) &&
    (!options.requireTransaction || Boolean(record.transactionHash))
  ) ?? null;
}

export function removeReservationRecovery(
  scope: Required<ReservationRecoveryScope>,
  storage: Storage | null | undefined = undefined,
): void {
  const target = resolveStorage(storage);
  const settlement = address(scope.settlement);
  const consumer = address(scope.consumer);
  const reservationId = bytes32(scope.reservationId);
  if (!target || !settlement || !consumer || !reservationId) return;
  const records = readReservationRecoveries(target).filter((record) => !(
    record.chainId === scope.chainId &&
    record.settlement.toLowerCase() === settlement.toLowerCase() &&
    record.consumer.toLowerCase() === consumer.toLowerCase() &&
    record.reservationId === reservationId
  ));
  writeRecords(records, target);
}
