import { randomBytes } from "node:crypto";

/**
 * MSP command ids are UUIDv7 by contract — the host rejects any other version,
 * because the embedded timestamp is what orders commands in its durable log.
 * Node ships no v7 generator, so this builds one: 48 bits of Unix milliseconds,
 * then version and variant bits over random payload.
 */
export function uuidV7(nowMs: number = Date.now()): string {
  const bytes = randomBytes(16);
  const timestamp = BigInt(Math.max(0, Math.trunc(nowMs)));

  bytes[0] = Number((timestamp >> 40n) & 0xffn);
  bytes[1] = Number((timestamp >> 32n) & 0xffn);
  bytes[2] = Number((timestamp >> 24n) & 0xffn);
  bytes[3] = Number((timestamp >> 16n) & 0xffn);
  bytes[4] = Number((timestamp >> 8n) & 0xffn);
  bytes[5] = Number(timestamp & 0xffn);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}
