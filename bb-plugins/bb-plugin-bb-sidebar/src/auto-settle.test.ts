import { describe, expect, it } from "vitest";
import {
  decideAutoSettle,
  parseAutoSettleAfterDays,
  type AutoSettleLifecycleState,
} from "./auto-settle";

const DAY = 24 * 60 * 60 * 1_000;
const NOW = 10 * DAY;

function lifecycle(
  overrides: Partial<AutoSettleLifecycleState> = {},
): AutoSettleLifecycleState {
  return {
    settledAt: null,
    settledOverride: null,
    snoozedUntil: null,
    ...overrides,
  };
}

const quietThread = {
  createdAt: DAY,
  latestAttentionAt: 6 * DAY,
  pinnedAt: null,
  status: "idle" as const,
  updatedAt: 6 * DAY,
};

const settings = { afterDays: 3, onMerge: true };

describe("automatic settle policy", () => {
  it("accepts only configured inactivity thresholds from 1 through 90", () => {
    expect(parseAutoSettleAfterDays(true, "3")).toBe(3);
    expect(parseAutoSettleAfterDays(false, "3")).toBeNull();
    expect(parseAutoSettleAfterDays(true, "0")).toBeNull();
    expect(parseAutoSettleAfterDays(true, "3.5")).toBeNull();
    expect(parseAutoSettleAfterDays(true, "91")).toBeNull();
  });

  it("settles an inactive thread and reverses it after fresh activity", () => {
    expect(
      decideAutoSettle({
        lifecycle: null,
        now: NOW,
        pullRequest: { outcome: "absent" },
        settings,
        thread: quietThread,
      }),
    ).toBe("settle");
    expect(
      decideAutoSettle({
        lifecycle: lifecycle({ settledAt: NOW - DAY }),
        now: NOW,
        pullRequest: { outcome: "absent" },
        settings,
        thread: { ...quietThread, updatedAt: NOW },
      }),
    ).toBe("unsettle");
  });

  it("keeps open and draft pull requests active", () => {
    for (const state of ["open", "draft"] as const) {
      expect(
        decideAutoSettle({
          lifecycle: null,
          now: NOW,
          pullRequest: {
            outcome: "available",
            state,
            updatedAt: new Date(NOW).toISOString(),
          },
          settings,
          thread: quietThread,
        }),
      ).toBe("keep");
    }
  });

  it("settles closed PRs and optionally merged PRs", () => {
    const updatedAt = new Date(NOW).toISOString();
    expect(
      decideAutoSettle({
        lifecycle: null,
        now: NOW,
        pullRequest: { outcome: "available", state: "closed", updatedAt },
        settings: { afterDays: null, onMerge: false },
        thread: quietThread,
      }),
    ).toBe("settle");
    expect(
      decideAutoSettle({
        lifecycle: null,
        now: NOW,
        pullRequest: { outcome: "available", state: "merged", updatedAt },
        settings: { afterDays: null, onMerge: false },
        thread: quietThread,
      }),
    ).toBe("keep");
  });

  it("does not re-settle when activity postdates the terminal PR", () => {
    expect(
      decideAutoSettle({
        lifecycle: null,
        now: NOW,
        pullRequest: {
          outcome: "available",
          state: "merged",
          updatedAt: new Date(7 * DAY).toISOString(),
        },
        settings: { afterDays: null, onMerge: true },
        thread: { ...quietThread, updatedAt: 8 * DAY },
      }),
    ).toBe("keep");
  });

  it("keeps the current state when a terminal PR timestamp is malformed", () => {
    expect(
      decideAutoSettle({
        lifecycle: null,
        now: NOW,
        pullRequest: {
          outcome: "available",
          state: "closed",
          updatedAt: "not-a-timestamp",
        },
        settings: { afterDays: 1, onMerge: true },
        thread: quietThread,
      }),
    ).toBe("keep");
    expect(
      decideAutoSettle({
        lifecycle: lifecycle({ settledAt: NOW - DAY }),
        now: NOW,
        pullRequest: {
          outcome: "available",
          state: "closed",
          updatedAt: "not-a-timestamp",
        },
        settings: { afterDays: 1, onMerge: true },
        thread: quietThread,
      }),
    ).toBe("keep");
  });

  it("never changes explicit overrides, pinned rows, or unknown PR state", () => {
    expect(
      decideAutoSettle({
        lifecycle: lifecycle({ settledOverride: "active" }),
        now: NOW,
        pullRequest: { outcome: "absent" },
        settings,
        thread: quietThread,
      }),
    ).toBe("keep");
    expect(
      decideAutoSettle({
        lifecycle: null,
        now: NOW,
        pullRequest: { outcome: "absent" },
        settings,
        thread: { ...quietThread, pinnedAt: NOW },
      }),
    ).toBe("keep");
    expect(
      decideAutoSettle({
        lifecycle: null,
        now: NOW,
        pullRequest: { outcome: "unknown" },
        settings,
        thread: quietThread,
      }),
    ).toBe("keep");
  });
});
