import { describe, expect, it } from "vitest";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk/app";
import {
  childStatusKind,
  childStatusPhrase,
  childStatusSummary,
  childSubtree,
} from "./child-status";

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
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  } as PluginSidebarThread;
}

describe("childStatusKind", () => {
  it("ranks failure over a raised hand over done over working", () => {
    expect(
      childStatusKind(
        thread({ indicator: "unread-error", hasPendingInteraction: true }),
      ),
    ).toBe("failed");
    expect(childStatusKind(thread({ hasPendingInteraction: true }))).toBe(
      "needs-you",
    );
    expect(childStatusKind(thread({ indicator: "waiting-for-input" }))).toBe(
      "needs-you",
    );
    expect(childStatusKind(thread({ indicator: "unread-success" }))).toBe(
      "done",
    );
    expect(childStatusKind(thread({ indicator: "plan-mode" }))).toBe("working");
    expect(childStatusKind(thread({ indicator: "draft" }))).toBeNull();
    expect(childStatusKind(thread())).toBeNull();
  });
});

describe("childStatusSummary", () => {
  it("counts each kind, skips archived rows, and picks the most urgent", () => {
    const summary = childStatusSummary([
      thread({ id: "a", indicator: "runtime" }),
      thread({ id: "b", indicator: "runtime", isArchived: true }),
      thread({ id: "c", indicator: "unread-success" }),
      thread({ id: "d", hasPendingInteraction: true }),
      thread({ id: "e" }),
    ]);
    expect(summary).toEqual({
      failed: 0,
      needsYou: 1,
      done: 1,
      working: 1,
      dominant: "needs-you",
    });
    expect(childStatusPhrase(summary)).toBe(", 1 need you, 1 done, 1 working");
  });

  it("has no dominant kind and an empty phrase for idle children", () => {
    const summary = childStatusSummary([thread({ id: "a" })]);
    expect(summary.dominant).toBeNull();
    expect(childStatusPhrase(summary)).toBe("");
  });
});

describe("childSubtree", () => {
  it("adds visible grandchildren after each child", () => {
    const a = thread({ id: "a" });
    const b = thread({ id: "b" });
    const aa = thread({ id: "aa", parentThreadId: "a" });
    const ab = thread({ id: "ab", parentThreadId: "a", isArchived: true });
    const byParent = new Map([["a", [aa, ab]]]);
    expect(childSubtree([a, b], byParent).map((row) => row.id)).toEqual([
      "a",
      "aa",
      "b",
    ]);
  });
});
