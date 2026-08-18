import { describe, expect, it } from "vitest";
import {
  isSweepCandidate,
  planSweep,
  NONE_RECHECK_MS,
  type AutoSettleSettings,
  type PrLookup,
  type PrWatchRow,
  type SweepThreadRow,
} from "./auto-settle";

const settings = (
  overrides: Partial<AutoSettleSettings> = {},
): AutoSettleSettings => ({
  autoSettle: true,
  settleClosed: false,
  ...overrides,
});

const NOW = 1_800_000_000_000;

const candidate = (threadId = "thr_1", environmentId = "env_1") => ({
  threadId,
  environmentId,
});

const watchRow = (overrides: Partial<PrWatchRow> = {}): PrWatchRow => ({
  threadId: "thr_1",
  environmentId: "env_1",
  prUrl: null,
  prState: "open",
  autoSettledAt: null,
  lastCheckedAt: NOW - 1_000,
  ...overrides,
});

const available = (
  state: "open" | "draft" | "merged" | "closed",
): PrLookup => ({
  outcome: "available",
  state,
  url: "https://github.com/acme/app/pull/42",
});

const lookupsFor = (
  lookup: PrLookup,
  environmentId = "env_1",
): Map<string, PrLookup> => new Map([[environmentId, lookup]]);

const quietThread = (
  overrides: Partial<SweepThreadRow> = {},
): SweepThreadRow => ({
  id: "thr_1",
  status: "idle",
  pinnedAt: null,
  visibility: "visible",
  environmentId: "env_1",
  hasPendingInteraction: false,
  activity: {
    activeWorkflowCount: 0,
    activeBackgroundAgentCount: 0,
    activeBackgroundCommandCount: 0,
    activePlanModeCount: 0,
    activeGoalCount: 0,
  },
  ...overrides,
});

describe("planSweep", () => {
  it("settles a thread whose PR merged", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: lookupsFor(available("merged")),
      watchRows: new Map(),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual(["thr_1"]);
    expect(plan.record).toEqual([
      {
        threadId: "thr_1",
        environmentId: "env_1",
        prUrl: "https://github.com/acme/app/pull/42",
        prState: "merged",
        autoSettledAt: NOW,
        lastCheckedAt: NOW,
      },
    ]);
  });

  it.each(["open", "draft"] as const)(
    "records but does not settle a %s PR",
    (state) => {
      const plan = planSweep({
        candidates: [candidate()],
        lookups: lookupsFor(available(state)),
        watchRows: new Map(),
        settings: settings(),
        now: NOW,
      });
      expect(plan.settle).toEqual([]);
      expect(plan.record[0]).toMatchObject({
        prState: state,
        autoSettledAt: null,
      });
    },
  );

  it("does not settle a closed-unmerged PR by default", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: lookupsFor(available("closed")),
      watchRows: new Map(),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual([]);
    expect(plan.record[0]).toMatchObject({ prState: "closed" });
  });

  it("settles a closed-unmerged PR when settleClosed is on", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: lookupsFor(available("closed")),
      watchRows: new Map(),
      settings: settings({ settleClosed: true }),
      now: NOW,
    });
    expect(plan.settle).toEqual(["thr_1"]);
  });

  it("records 'none' for a branch with no PR", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: lookupsFor({ outcome: "absent" }),
      watchRows: new Map(),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual([]);
    expect(plan.record).toEqual([
      {
        threadId: "thr_1",
        environmentId: "env_1",
        prUrl: null,
        prState: "none",
        autoSettledAt: null,
        lastCheckedAt: NOW,
      },
    ]);
  });

  it("treats an unavailable lookup as no information: nothing is recorded", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: lookupsFor({ outcome: "unavailable" }),
      watchRows: new Map(),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual([]);
    expect(plan.record).toEqual([]);
  });

  it("never auto-settles a thread twice (the user-overrule rule)", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: lookupsFor(available("merged")),
      watchRows: new Map([
        ["thr_1", watchRow({ prState: "merged", autoSettledAt: NOW - 60_000 })],
      ]),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual([]);
    expect(plan.record).toEqual([]);
  });

  it("does not re-probe a fresh 'none' row", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: new Map(), // no probe should have happened at all
      watchRows: new Map([
        ["thr_1", watchRow({ prState: "none", lastCheckedAt: NOW - 1_000 })],
      ]),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual([]);
    expect(plan.record).toEqual([]);
  });

  it("re-probes a 'none' row older than a day", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: lookupsFor(available("merged")),
      watchRows: new Map([
        [
          "thr_1",
          watchRow({
            prState: "none",
            lastCheckedAt: NOW - NONE_RECHECK_MS - 1_000,
          }),
        ],
      ]),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual(["thr_1"]);
  });

  it("shares one environment lookup across several threads on that environment", () => {
    const plan = planSweep({
      candidates: [candidate("thr_1"), candidate("thr_2")],
      lookups: lookupsFor(available("merged")),
      watchRows: new Map(),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual(["thr_1", "thr_2"]);
    expect(plan.record).toHaveLength(2);
  });

  it("lets an un-settled sibling settle even when its twin was auto-settled", () => {
    const plan = planSweep({
      candidates: [candidate("thr_1"), candidate("thr_2")],
      lookups: lookupsFor(available("merged")),
      watchRows: new Map([
        ["thr_1", watchRow({ prState: "merged", autoSettledAt: NOW - 60_000 })],
      ]),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual(["thr_2"]);
  });

  it("skips candidates whose environment was not probed (tick cap)", () => {
    const plan = planSweep({
      candidates: [candidate()],
      lookups: new Map(),
      watchRows: new Map(),
      settings: settings(),
      now: NOW,
    });
    expect(plan.settle).toEqual([]);
    expect(plan.record).toEqual([]);
  });
});

describe("isSweepCandidate", () => {
  it("accepts a quiet, unpinned, visible thread with an environment", () => {
    expect(isSweepCandidate(quietThread())).toBe(true);
  });

  it.each(["active", "starting", "stopping", "error"])(
    "refuses a thread with status %s — never park live or live-ish work",
    (status) => {
      expect(isSweepCandidate(quietThread({ status }))).toBe(false);
    },
  );

  it("refuses a thread blocked on the user", () => {
    expect(isSweepCandidate(quietThread({ hasPendingInteraction: true }))).toBe(
      false,
    );
  });

  it.each([
    "activeWorkflowCount",
    "activeBackgroundAgentCount",
    "activeBackgroundCommandCount",
    "activePlanModeCount",
    "activeGoalCount",
  ] as const)("refuses while %s is above zero", (counter) => {
    expect(
      isSweepCandidate(
        quietThread({
          activity: { ...quietThread().activity, [counter]: 1 },
        }),
      ),
    ).toBe(false);
  });

  it("refuses a pinned thread — a pin is the user asking for visibility", () => {
    expect(isSweepCandidate(quietThread({ pinnedAt: NOW }))).toBe(false);
  });

  it("refuses a hidden thread", () => {
    expect(isSweepCandidate(quietThread({ visibility: "hidden" }))).toBe(false);
  });

  it("refuses a thread with no environment", () => {
    expect(isSweepCandidate(quietThread({ environmentId: null }))).toBe(false);
  });
});
