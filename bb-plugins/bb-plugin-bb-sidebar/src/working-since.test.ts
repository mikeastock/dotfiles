import { describe, expect, it } from "vitest";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk/app";
import { reconcileWorkingSince, statusWithDuration } from "./working-since";

const NOW = 1_000_000_000;
const MINUTE = 60_000;

function thread(
  overrides: Partial<PluginSidebarThread> = {},
): PluginSidebarThread {
  return {
    id: "thr_1",
    projectId: "proj_1",
    title: "A thread",
    titleFallback: null,
    parentThreadId: null,
    sectionId: null,
    originKind: null,
    originPluginId: null,
    providerId: "codex",
    hasPendingInteraction: false,
    activity: {
      workflows: 0,
      backgroundAgents: 0,
      backgroundCommands: 0,
      planMode: 0,
      goals: 0,
    },
    indicator: "none",
    indicatorLabel: null,
    isUnread: false,
    isPinned: false,
    isArchived: false,
    environment: null,
    host: null,
    createdAt: NOW - 10 * MINUTE,
    updatedAt: NOW - MINUTE,
    lastReadAt: null,
    latestAttentionAt: NOW - MINUTE,
    ...overrides,
  };
}

describe("reconcileWorkingSince", () => {
  it("stamps a thread the first time it is seen working", () => {
    const next = reconcileWorkingSince(
      new Map(),
      [thread({ id: "a", indicator: "runtime" })],
      NOW,
    );
    expect(next.get("a")).toBe(NOW);
  });

  it("keeps the original stamp while the thread stays busy", () => {
    const first = new Map([["a", NOW - 5 * MINUTE]]);
    const next = reconcileWorkingSince(
      first,
      [thread({ id: "a", indicator: "runtime" })],
      NOW,
    );
    expect(next.get("a")).toBe(NOW - 5 * MINUTE);
  });

  it("returns the same map when nothing changed, so no render is spent", () => {
    const first = new Map([["a", NOW - 5 * MINUTE]]);
    const next = reconcileWorkingSince(
      first,
      [thread({ id: "a", indicator: "runtime" }), thread({ id: "b" })],
      NOW,
    );
    expect(next).toBe(first);
  });

  // A pause for a question ends the stretch: the next answer starts a fresh
  // count, which is the wait the user actually feels.
  it("clears a thread that stopped working or left the list", () => {
    const first = new Map([
      ["a", NOW - 5 * MINUTE],
      ["gone", NOW - 5 * MINUTE],
    ]);
    const next = reconcileWorkingSince(
      first,
      [thread({ id: "a", indicator: "waiting-for-input" })],
      NOW,
    );
    expect(next.size).toBe(0);
  });

  it("counts background activity as work, not only the runtime indicator", () => {
    const next = reconcileWorkingSince(
      new Map(),
      [
        thread({
          id: "a",
          activity: {
            workflows: 0,
            backgroundAgents: 1,
            backgroundCommands: 0,
            planMode: 0,
            goals: 0,
          },
        }),
      ],
      NOW,
    );
    expect(next.get("a")).toBe(NOW);
  });
});

describe("statusWithDuration", () => {
  it("appends the elapsed bucket after a minute", () => {
    expect(statusWithDuration("Working", NOW - 5 * MINUTE, NOW)).toBe(
      "Working · 5m",
    );
    expect(statusWithDuration("Planning", NOW - 3 * 60 * MINUTE, NOW)).toBe(
      "Planning · 3h",
    );
  });

  it("stays bare under a minute, and without a stamp", () => {
    expect(statusWithDuration("Working", NOW - 30_000, NOW)).toBe("Working");
    expect(statusWithDuration("Working", undefined, NOW)).toBe("Working");
  });

  // The stamp is exact while the card's clock is floored to the minute, so a
  // fresh stamp can sit ahead of `now`. That must not print a negative age.
  it("treats a stamp ahead of the quantized clock as fresh", () => {
    expect(statusWithDuration("Working", NOW + 30_000, NOW)).toBe("Working");
  });
});
