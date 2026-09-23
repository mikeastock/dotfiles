import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  computePiTurnRates,
  parsePiSessionSamples,
  piSessionFilePath,
  piTurnWindowsFromEvents,
  type PiResponseSample,
  type PiTurnWindow,
} from "./pi-session";
import type { EventRow } from "./rate";

// Recorded from a real BB Pi thread (claude-opus-5-5): the Pi session file BB's
// bridge wrote, reduced to the fields tok-speed reads, plus the thread's
// turn/started + turn/completed events. The last turn was still running.
const recordedSession = readFileSync(
  new URL("./fixtures/pi-session-recorded.jsonl", import.meta.url),
  "utf8",
);
const recordedTurnEvents = JSON.parse(
  readFileSync(
    new URL("./fixtures/pi-turn-events-recorded.json", import.meta.url),
    "utf8",
  ),
) as EventRow[];
const RECORDED_PROVIDER_THREAD_ID = "pi_8cf417e9-c1b3-42b1-acad-277754edafab";

function assistantLine(args: {
  startedAt: number;
  durationMs: number;
  output: number;
  stopReason?: string;
}): string {
  return JSON.stringify({
    type: "message",
    id: "x",
    timestamp: new Date(args.startedAt + args.durationMs).toISOString(),
    message: {
      role: "assistant",
      timestamp: args.startedAt,
      usage: { output: args.output, reasoning: 0 },
      stopReason: args.stopReason ?? "stop",
    },
  });
}

function sample(startedAt: number, durationMs: number, outputTokens: number): PiResponseSample {
  return { startedAt, completedAt: startedAt + durationMs, outputTokens };
}

describe("piSessionFilePath", () => {
  it("uses ~/.bb/pi-bridge-sessions like BB's Pi bridge", () => {
    expect(
      piSessionFilePath({ providerThreadId: "pi_abc-1", env: {}, homeDir: "/home/u" }),
    ).toBe("/home/u/.bb/pi-bridge-sessions/pi_abc-1.jsonl");
  });

  it("honors BB_PI_BRIDGE_SESSION_DIR and sanitizes the key the same way", () => {
    expect(
      piSessionFilePath({
        providerThreadId: "pi/../evil id",
        env: { BB_PI_BRIDGE_SESSION_DIR: " /srv/sessions " },
        homeDir: "/home/u",
      }),
    ).toBe("/srv/sessions/pi_.._evil_id.jsonl");
  });
});

describe("parsePiSessionSamples", () => {
  it("reads start, end, and output tokens of assistant responses only", () => {
    const text = [
      JSON.stringify({ type: "session", id: "s", timestamp: "2026-01-01T00:00:00.000Z" }),
      JSON.stringify({
        type: "message",
        id: "u",
        timestamp: "2026-01-01T00:00:00.000Z",
        message: { role: "user", timestamp: 0 },
      }),
      assistantLine({ startedAt: 1_000, durationMs: 2_000, output: 200 }),
      JSON.stringify({
        type: "message",
        id: "t",
        timestamp: "2026-01-01T00:00:03.000Z",
        message: { role: "toolResult", timestamp: 3_000 },
      }),
    ].join("\n");

    expect(parsePiSessionSamples(text)).toEqual([sample(1_000, 2_000, 200)]);
  });

  it("skips aborted and errored responses", () => {
    const text = [
      assistantLine({ startedAt: 0, durationMs: 1_000, output: 10, stopReason: "aborted" }),
      assistantLine({ startedAt: 0, durationMs: 1_000, output: 10, stopReason: "error" }),
      assistantLine({ startedAt: 0, durationMs: 1_000, output: 10, stopReason: "toolUse" }),
    ].join("\n");

    expect(parsePiSessionSamples(text)).toEqual([sample(0, 1_000, 10)]);
  });

  it("skips a partially written last line and entries missing usage or times", () => {
    const complete = assistantLine({ startedAt: 0, durationMs: 1_000, output: 10 });
    const text = [
      complete,
      JSON.stringify({
        type: "message",
        timestamp: "2026-01-01T00:00:01.000Z",
        message: { role: "assistant", timestamp: 0 },
      }),
      JSON.stringify({
        type: "message",
        timestamp: "not a date",
        message: { role: "assistant", timestamp: 0, usage: { output: 5 } },
      }),
      JSON.stringify({
        type: "message",
        timestamp: "2026-01-01T00:00:01.000Z",
        message: { role: "assistant", timestamp: 0, usage: { output: -1 } },
      }),
      complete.slice(0, 40),
    ].join("\n");

    expect(parsePiSessionSamples(text)).toEqual([sample(0, 1_000, 10)]);
  });
});

describe("piTurnWindowsFromEvents", () => {
  it("groups turn windows by Pi session and leaves running turns open", () => {
    const events: EventRow[] = [
      { seq: 1, createdAt: 100, type: "turn/started", scope: { kind: "turn", turnId: "a-t1" }, data: { providerThreadId: "pi_1" } },
      { seq: 2, createdAt: 200, type: "turn/completed", scope: { kind: "turn", turnId: "a-t1" }, data: { providerThreadId: "pi_1" } },
      { seq: 3, createdAt: 300, type: "turn/started", scope: { kind: "turn", turnId: "b-t1" }, data: { providerThreadId: "pi_2" } },
      { seq: 4, createdAt: 400, type: "turn/started", scope: { kind: "turn", turnId: "a-t2" }, data: { providerThreadId: "pi_1" } },
    ];

    expect(piTurnWindowsFromEvents(events)).toEqual(
      new Map([
        [
          "pi_1",
          [
            { turnId: "a-t1", startedAt: 100, completedAt: 200 },
            { turnId: "a-t2", startedAt: 400, completedAt: null },
          ],
        ],
        ["pi_2", [{ turnId: "b-t1", startedAt: 300, completedAt: null }]],
      ]),
    );
  });

  it("ignores turn events without a turn scope or provider thread id", () => {
    const events: EventRow[] = [
      { seq: 1, createdAt: 100, type: "turn/started", scope: { kind: "thread" }, data: { providerThreadId: "pi_1" } },
      { seq: 2, createdAt: 100, type: "turn/started", scope: { kind: "turn", turnId: "t" }, data: {} },
      { seq: 3, createdAt: 200, type: "turn/completed", scope: { kind: "turn", turnId: "t" }, data: {} },
    ];

    expect(piTurnWindowsFromEvents(events)).toEqual(new Map());
  });
});

describe("computePiTurnRates", () => {
  const turns: PiTurnWindow[] = [
    { turnId: "t1", startedAt: 10_000, completedAt: 20_000 },
    { turnId: "t2", startedAt: 30_000, completedAt: 40_000 },
    { turnId: "t3", startedAt: 50_000, completedAt: null },
  ];

  it("pools output tokens over response time per turn", () => {
    const rates = computePiTurnRates({
      turns,
      samples: [
        sample(10_100, 1_000, 100),
        sample(12_000, 3_000, 200),
        sample(30_100, 2_000, 50),
      ],
    });

    expect(rates).toEqual([
      { turnId: "t1", rate: 75, totalOutputTokens: 300, responseCount: 2 },
      { turnId: "t2", rate: 25, totalOutputTokens: 50, responseCount: 1 },
    ]);
  });

  it("assigns a response that starts just before BB records turn/started", () => {
    const rates = computePiTurnRates({
      turns,
      samples: [sample(29_997, 1_000, 40)],
    });

    expect(rates).toEqual([
      { turnId: "t2", rate: 40, totalOutputTokens: 40, responseCount: 1 },
    ]);
  });

  it("never lets the start slack reach back into the previous turn", () => {
    const rates = computePiTurnRates({
      turns: [
        { turnId: "t1", startedAt: 0, completedAt: 1_000 },
        { turnId: "t2", startedAt: 1_500, completedAt: 3_000 },
      ],
      samples: [sample(900, 1_000, 10)],
    });

    expect(rates).toEqual([
      { turnId: "t1", rate: 10, totalOutputTokens: 10, responseCount: 1 },
    ]);
  });

  it("drops responses outside every turn window", () => {
    const rates = computePiTurnRates({
      turns,
      samples: [
        sample(1_000, 1_000, 10), // before the first turn (e.g. forked history)
        sample(25_000, 1_000, 10), // between two completed turns
      ],
    });

    expect(rates).toEqual([]);
  });

  it("collects responses of a running turn", () => {
    const rates = computePiTurnRates({
      turns,
      samples: [sample(90_000, 2_000, 100)],
    });

    expect(rates).toEqual([
      { turnId: "t3", rate: 50, totalOutputTokens: 100, responseCount: 1 },
    ]);
  });

  it("ignores implausibly short or long responses and zero-token turns", () => {
    const rates = computePiTurnRates({
      turns,
      samples: [
        sample(10_100, 10, 500),
        sample(10_200, 31 * 60 * 1000, 500),
        sample(30_100, 1_000, 0),
      ],
    });

    expect(rates).toEqual([]);
  });
});

describe("recorded Pi thread", () => {
  const samples = parsePiSessionSamples(recordedSession);
  const windows = piTurnWindowsFromEvents(recordedTurnEvents);
  const turns = windows.get(RECORDED_PROVIDER_THREAD_ID)!;
  const rates = computePiTurnRates({ turns, samples });

  /**
   * Independent oracle: Pi starts a new prompt with a user message, so group
   * assistant responses by the user message that precedes them. BB turns map
   * one-to-one onto those prompts in order.
   */
  function groupByPrecedingUserMessage(): PiResponseSample[][] {
    const groups: PiResponseSample[][] = [];
    for (const line of recordedSession.trim().split("\n")) {
      const entry = JSON.parse(line);
      if (entry.message?.role === "user") groups.push([]);
      if (entry.message?.role === "assistant") {
        groups.at(-1)!.push(...parsePiSessionSamples(line));
      }
    }
    return groups;
  }

  it("parses every assistant response", () => {
    const assistantCount = recordedSession
      .trim()
      .split("\n")
      .filter((line) => JSON.parse(line).message?.role === "assistant").length;
    expect(samples).toHaveLength(assistantCount);
    expect(assistantCount).toBe(73);
  });

  it("maps to a single Pi session covering all seven BB turns", () => {
    expect([...windows.keys()]).toEqual([RECORDED_PROVIDER_THREAD_ID]);
    expect(turns.map((turn) => turn.turnId)).toEqual([
      "da9d14c31e-t1",
      "da9d14c31e-t2",
      "dab3901617-t1",
      "dab3901617-t2",
      "da3c3af285-t1",
      "da3c3af285-t2",
      "da3c3af285-t3",
    ]);
    expect(turns.at(-1)!.completedAt).toBeNull();
  });

  it("assigns responses to the same turns as Pi's own prompt boundaries", () => {
    const groups = groupByPrecedingUserMessage();
    expect(groups).toHaveLength(turns.length);

    const expected = groups.map((group, index) => {
      const totalOutputTokens = group.reduce((sum, s) => sum + s.outputTokens, 0);
      const totalMs = group.reduce((sum, s) => sum + (s.completedAt - s.startedAt), 0);
      return {
        turnId: turns[index]!.turnId,
        rate: totalOutputTokens / (totalMs / 1000),
        totalOutputTokens,
        responseCount: group.length,
      };
    });
    expect(rates).toEqual(expected);
  });

  it("produces plausible provider speeds for claude-opus-5-5", () => {
    expect(rates.map((rate) => Math.round(rate.rate!))).toEqual([
      87, 57, 104, 38, 106, 98, 105,
    ]);
    for (const rate of rates) {
      expect(rate.rate).toBeGreaterThan(10);
      expect(rate.rate).toBeLessThan(300);
    }
  });
});
