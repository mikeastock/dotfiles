import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { computeThreadRates } from "../server";
import { computeTurnRates, type EventRow } from "./rate";

function loadFixture(name: string): EventRow[] {
  const url = new URL(`./fixtures/${name}`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as EventRow[];
}

// Recorded provider data, captured with `bb thread log --format json` and
// trimmed to the event types the rate walk consumes (agentMessage lifecycle,
// agentMessage deltas, tokenUsage snapshots). Identifiers and message prose are sanitized;
// timestamps, token counts, and scopes are untouched.
//
// What makes these fixtures different from the synthetic tests in
// rate.test.ts: the persisted log keeps exactly ONE delta per message even
// for multi-KB responses, so every turn below exercises the lifecycle
// fallback (started → completed) — the path all real traffic takes. And the
// turn_fixture_9 snapshot has a provider whose running total contradicts its
// own `last` (total 196 → 808 = +612, but `last` claims 808), pinning the
// documented preference for the total delta.
describe("computeTurnRates against recorded provider data", () => {
  it("matches hand-computed lifecycle speeds on three recorded turns", () => {
    const events = loadFixture("recorded-rich.json");
    const result = computeTurnRates({
      turnIds: ["turn_fixture_4", "turn_fixture_7", "turn_fixture_9"],
      events,
    });

    // 796 visible tokens over 5_025 ms of agent-message time.
    expect(result.get("turn_fixture_4")).toMatchObject({
      totalOutputTokens: 796,
      responseCount: 1,
    });
    expect(result.get("turn_fixture_4")?.rate).toBeCloseTo(
      796 / 5.025,
      10,
    );

    // 196 visible tokens over 1_285 ms.
    expect(result.get("turn_fixture_7")).toMatchObject({
      totalOutputTokens: 196,
      responseCount: 1,
    });
    expect(result.get("turn_fixture_7")?.rate).toBeCloseTo(
      196 / 1.285,
      10,
    );

    // Running-total delta wins over the mislabelled `last`: 808 − 196 = 612
    // visible tokens over 3_323 ms, not the 808 `last` reports.
    expect(result.get("turn_fixture_9")).toMatchObject({
      totalOutputTokens: 612,
      responseCount: 1,
    });
    expect(result.get("turn_fixture_9")?.rate).toBeCloseTo(
      612 / 3.323,
      10,
    );
  });

  it("discovers usage turns from recorded data like the live RPC does", () => {
    const events = loadFixture("recorded-rich.json");
    const rows = computeThreadRates("thr_fixture5", events);

    expect(rows).toHaveLength(3);
    expect(new Set(rows.map((row) => row.turnId))).toEqual(
      new Set(["turn_fixture_4", "turn_fixture_7", "turn_fixture_9"]),
    );
    for (const row of rows) expect(row.threadId).toBe("thr_fixture5");
    expect(rows.find((row) => row.turnId === "turn_fixture_4")?.rate).toBeCloseTo(
      796 / 5.025,
      10,
    );
  });

  it("matches the hand-computed speed of a turn with host tool work", () => {
    const events = loadFixture("recorded-current.json");
    const result = computeTurnRates({
      turnIds: ["turn_fixture_1"],
      events,
    });

    // 417 visible tokens over 1_119 ms. The turn also contains tool calls,
    // command executions, and file reads; none of them may leak into the
    // denominator.
    expect(result.get("turn_fixture_1")).toMatchObject({
      totalOutputTokens: 417,
      responseCount: 1,
    });
    expect(result.get("turn_fixture_1")?.rate).toBeCloseTo(
      417 / 1.119,
      10,
    );
  });
});
