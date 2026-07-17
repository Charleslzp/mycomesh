import { describe, expect, it } from "vitest";
import {
  findReservationRecovery,
  readReservationRecoveries,
  removeReservationRecovery,
  RESERVATION_RECOVERY_STORAGE_KEY,
  reservationIdFromQuery,
  saveReservationRecovery,
  type ReservationRecoveryRecord,
} from "./reservationRecovery";

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();
  get length() { return this.values.size; }
  clear() { this.values.clear(); }
  getItem(key: string) { return this.values.get(key) ?? null; }
  key(index: number) { return [...this.values.keys()][index] ?? null; }
  removeItem(key: string) { this.values.delete(key); }
  setItem(key: string, value: string) { this.values.set(key, value); }
}

const settlement = "0x1111111111111111111111111111111111111111";
const consumer = "0x2222222222222222222222222222222222222222";
const reservationId = ("0x" + "33".repeat(32)) as `0x${string}`;
const transactionHash = ("0x" + "44".repeat(32)) as `0x${string}`;

function record(overrides: Partial<ReservationRecoveryRecord> = {}): ReservationRecoveryRecord {
  return {
    schema: "mycomesh.reservation.recovery.v1",
    chainId: 11155111,
    settlement,
    consumer,
    reservationId,
    expiresAt: 1_900_000_000,
    transactionHash: null,
    createdAt: 1_800_000_000_000,
    ...overrides,
  };
}

describe("reservation recovery metadata", () => {
  it("persists a prepared reservation and atomically adds its transaction hash", () => {
    const storage = new MemoryStorage();
    saveReservationRecovery({ ...record(), apiKey: "must-not-persist" } as ReservationRecoveryRecord, storage);
    expect(findReservationRecovery({ chainId: 11155111, settlement, consumer }, {}, storage)?.transactionHash).toBeNull();
    expect(findReservationRecovery({ chainId: 11155111, settlement, consumer }, { requireTransaction: true }, storage)).toBeNull();
    saveReservationRecovery(record({ transactionHash }), storage);

    expect(readReservationRecoveries(storage)).toEqual([
      expect.objectContaining({ reservationId, transactionHash }),
    ]);
    expect(storage.getItem(RESERVATION_RECOVERY_STORAGE_KEY)).not.toContain("apiKey");
  });

  it("selects only records for the active deployment and Consumer", () => {
    const storage = new MemoryStorage();
    saveReservationRecovery(record({ transactionHash }), storage);
    saveReservationRecovery(record({
      reservationId: ("0x" + "99".repeat(32)) as `0x${string}`,
      createdAt: 1_800_000_000_002,
    }), storage);
    saveReservationRecovery(record({
      consumer: "0x5555555555555555555555555555555555555555",
      reservationId: ("0x" + "66".repeat(32)) as `0x${string}`,
      transactionHash: ("0x" + "77".repeat(32)) as `0x${string}`,
      createdAt: 1_800_000_000_001,
    }), storage);

    expect(findReservationRecovery({ chainId: 11155111, settlement, consumer }, { requireTransaction: true }, storage)?.reservationId).toBe(reservationId);
    expect(findReservationRecovery({ chainId: 1, settlement, consumer }, {}, storage)).toBeNull();
  });

  it("prefers the canonical reservation_id query parameter", () => {
    expect(reservationIdFromQuery(new URLSearchParams(`reservation=${transactionHash}&reservation_id=${reservationId}`))).toBe(reservationId);
    expect(reservationIdFromQuery(new URLSearchParams(`reservation=${transactionHash}`))).toBe(transactionHash);
  });

  it("retains prepared metadata on failure and removes only the released reservation", () => {
    const storage = new MemoryStorage();
    const otherId = ("0x" + "88".repeat(32)) as `0x${string}`;
    saveReservationRecovery(record(), storage);
    saveReservationRecovery(record({ reservationId: otherId, createdAt: 1_800_000_000_001 }), storage);

    removeReservationRecovery({ chainId: 11155111, settlement, consumer, reservationId }, storage);

    expect(readReservationRecoveries(storage).map((item) => item.reservationId)).toEqual([otherId]);
  });

  it("ignores malformed or oversized browser data", () => {
    const storage = new MemoryStorage();
    storage.setItem(RESERVATION_RECOVERY_STORAGE_KEY, "not-json");
    expect(readReservationRecoveries(storage)).toEqual([]);
    storage.setItem(RESERVATION_RECOVERY_STORAGE_KEY, JSON.stringify([
      record({ expiresAt: Number.MAX_SAFE_INTEGER }),
    ]));
    expect(readReservationRecoveries(storage)).toEqual([]);
    storage.setItem(RESERVATION_RECOVERY_STORAGE_KEY, "x".repeat(70_000));
    expect(readReservationRecoveries(storage)).toEqual([]);
  });
});
