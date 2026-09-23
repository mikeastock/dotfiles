import { appendFileSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  computePiThreadRates,
  computeThreadRates,
  createPiSessionReader,
} from "../server";
import { computePiTurnRates, parsePiSessionSamples, piTurnWindowsFromEvents } from "./pi-session";
import type { EventRow } from "./rate";

function event(type: string, createdAt: number, seq: number, data: EventRow["data"]): EventRow {
  return {
    type,
    createdAt,
    seq,
    scope: { kind: "turn", turnId: "turn-1" },
    data,
  };
}

function assistantLine(startedAt: number, durationMs: number, output: number): string {
  return JSON.stringify({
    type: "message",
    timestamp: new Date(startedAt + durationMs).toISOString(),
    message: { role: "assistant", timestamp: startedAt, usage: { output }, stopReason: "stop" },
  });
}

const recordedSessionPath = new URL("./fixtures/pi-session-recorded.jsonl", import.meta.url);
const recordedTurnEvents = JSON.parse(
  readFileSync(new URL("./fixtures/pi-turn-events-recorded.json", import.meta.url), "utf8"),
) as EventRow[];

describe("computeThreadRates", () => {
  it("returns thread-qualified rate objects rather than Map entries", () => {
    const result = computeThreadRates("thread-1", [
      event("item/started", 0, 1, { item: { type: "agentMessage", id: "item-1" } }),
      event("item/completed", 1_000, 2, { item: { type: "agentMessage", id: "item-1" } }),
      event("thread/tokenUsage/updated", 1_001, 3, {
        tokenUsage: { last: { outputTokens: 100 } },
      }),
    ]);

    expect(result).toEqual([
      {
        threadId: "thread-1",
        turnId: "turn-1",
        rate: 100,
        totalOutputTokens: 100,
        responseCount: 1,
        measurement: "visible-stream",
      },
    ]);
  });
});

describe("Pi session files", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "tok-speed-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  describe("createPiSessionReader", () => {
    it("returns no samples for a missing file", async () => {
      const read = createPiSessionReader();
      await expect(read(join(dir, "missing.jsonl"))).resolves.toEqual([]);
    });

    it("reuses parsed samples until the file changes, then re-reads it", async () => {
      const path = join(dir, "session.jsonl");
      writeFileSync(path, assistantLine(0, 1_000, 10) + "\n");
      const read = createPiSessionReader();

      const first = await read(path);
      expect(first).toEqual([{ startedAt: 0, completedAt: 1_000, outputTokens: 10 }]);
      expect(await read(path)).toBe(first);

      appendFileSync(path, assistantLine(5_000, 2_000, 20) + "\n");
      expect(await read(path)).toEqual([
        { startedAt: 0, completedAt: 1_000, outputTokens: 10 },
        { startedAt: 5_000, completedAt: 7_000, outputTokens: 20 },
      ]);
    });

    it("forgets a file that disappears", async () => {
      const path = join(dir, "session.jsonl");
      writeFileSync(path, assistantLine(0, 1_000, 10) + "\n");
      const read = createPiSessionReader();
      await read(path);

      rmSync(path);
      await expect(read(path)).resolves.toEqual([]);
    });
  });

  describe("computePiThreadRates", () => {
    it("reads the recorded session from BB_PI_BRIDGE_SESSION_DIR and rates every turn", async () => {
      copyFileSync(
        recordedSessionPath,
        join(dir, "pi_8cf417e9-c1b3-42b1-acad-277754edafab.jsonl"),
      );

      const result = await computePiThreadRates({
        threadId: "thr_recorded",
        turnEvents: recordedTurnEvents,
        readSamples: createPiSessionReader(),
        env: { BB_PI_BRIDGE_SESSION_DIR: dir },
      });

      const expected = computePiTurnRates({
        turns: piTurnWindowsFromEvents(recordedTurnEvents).get(
          "pi_8cf417e9-c1b3-42b1-acad-277754edafab",
        )!,
        samples: parsePiSessionSamples(readFileSync(recordedSessionPath, "utf8")),
      }).map((rate) => ({ threadId: "thr_recorded", ...rate, measurement: "pi-session" }));
      expect(result).toEqual(expected);
      expect(result).toHaveLength(7);
    });

    it("finds the session under ~/.bb/pi-bridge-sessions by default", async () => {
      const sessionDir = join(dir, ".bb", "pi-bridge-sessions");
      mkdirSync(sessionDir, { recursive: true });
      writeFileSync(join(sessionDir, "pi_1.jsonl"), assistantLine(100, 1_000, 50) + "\n");

      const result = await computePiThreadRates({
        threadId: "thr_1",
        turnEvents: [
          { seq: 1, createdAt: 100, type: "turn/started", scope: { kind: "turn", turnId: "t1" }, data: { providerThreadId: "pi_1" } },
          { seq: 2, createdAt: 2_000, type: "turn/completed", scope: { kind: "turn", turnId: "t1" }, data: { providerThreadId: "pi_1" } },
        ],
        readSamples: createPiSessionReader(),
        env: {},
        homeDir: dir,
      });

      expect(result).toEqual([
        {
          threadId: "thr_1",
          turnId: "t1",
          rate: 50,
          totalOutputTokens: 50,
          responseCount: 1,
          measurement: "pi-session",
        },
      ]);
    });

    it("returns nothing when the session file does not exist", async () => {
      const result = await computePiThreadRates({
        threadId: "thr_1",
        turnEvents: [
          { seq: 1, createdAt: 100, type: "turn/started", scope: { kind: "turn", turnId: "t1" }, data: { providerThreadId: "pi_gone" } },
        ],
        readSamples: createPiSessionReader(),
        env: { BB_PI_BRIDGE_SESSION_DIR: dir },
      });

      expect(result).toEqual([]);
    });
  });
});
