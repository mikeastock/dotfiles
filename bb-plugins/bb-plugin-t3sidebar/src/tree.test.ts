import { describe, expect, it } from "vitest";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import { buildThreadTree, summarizeDescendants, visibleRows } from "./tree";

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
    createdAt: 100,
    updatedAt: 100,
    lastReadAt: 100,
    latestAttentionAt: 100,
    ...overrides,
  };
}

const ids = (nodes: ReturnType<typeof buildThreadTree>) =>
  nodes.map((node) => node.thread.id);

describe("buildThreadTree", () => {
  it("nests a child under its parent", () => {
    const tree = buildThreadTree([
      thread({ id: "parent" }),
      thread({ id: "child", parentThreadId: "parent" }),
    ]);
    expect(ids(tree)).toEqual(["parent"]);
    expect(ids(tree[0]!.children)).toEqual(["child"]);
    expect(tree[0]!.children[0]!.depth).toBe(1);
  });

  it("nests grandchildren, counting depth from the root", () => {
    const tree = buildThreadTree([
      thread({ id: "a" }),
      thread({ id: "b", parentThreadId: "a" }),
      thread({ id: "c", parentThreadId: "b" }),
    ]);
    expect(tree[0]!.children[0]!.children[0]!.depth).toBe(2);
  });

  // The promotion rule, and the reason nesting is safe: a parent that is not
  // in this list cannot be expanded, so hiding a row inside it would lose it.
  it("promotes a child whose parent is not in the list", () => {
    const tree = buildThreadTree([
      thread({ id: "child", parentThreadId: "archived-parent" }),
    ]);
    expect(ids(tree)).toEqual(["child"]);
    expect(tree[0]!.depth).toBe(0);
  });

  it("keeps siblings newest first, at every level", () => {
    const tree = buildThreadTree([
      thread({ id: "root-old", createdAt: 1 }),
      thread({ id: "root-new", createdAt: 9 }),
      thread({ id: "kid-old", parentThreadId: "root-new", createdAt: 2 }),
      thread({ id: "kid-new", parentThreadId: "root-new", createdAt: 5 }),
    ]);
    expect(ids(tree)).toEqual(["root-new", "root-old"]);
    expect(ids(tree[0]!.children)).toEqual(["kid-new", "kid-old"]);
  });

  // Parentage comes from the server; nothing guarantees it is acyclic.
  it("survives a parentage cycle and still gives every thread a row", () => {
    const tree = buildThreadTree([
      thread({ id: "a", parentThreadId: "b" }),
      thread({ id: "b", parentThreadId: "a" }),
    ]);
    const seen = new Set<string>();
    const walk = (nodes: ReturnType<typeof buildThreadTree>) => {
      for (const node of nodes) {
        expect(seen.has(node.thread.id)).toBe(false);
        seen.add(node.thread.id);
        walk(node.children);
      }
    };
    walk(tree);
    expect([...seen].sort()).toEqual(["a", "b"]);
  });

  it("gives a thread exactly one row", () => {
    const tree = buildThreadTree([
      thread({ id: "parent" }),
      thread({ id: "child", parentThreadId: "parent" }),
    ]);
    expect(visibleRows(tree, new Set())).toHaveLength(2);
  });
});

describe("summarizeDescendants", () => {
  it("counts the whole subtree, not just direct children", () => {
    const tree = buildThreadTree([
      thread({ id: "a" }),
      thread({ id: "b", parentThreadId: "a" }),
      thread({ id: "c", parentThreadId: "b", hasPendingInteraction: true }),
      thread({ id: "d", parentThreadId: "a", isUnread: true }),
    ]);
    expect(summarizeDescendants(tree[0]!)).toEqual({
      total: 3,
      waiting: 1,
      unread: 1,
    });
  });

  // Waiting outranks unread: a blocked thread is also unread, and counting it
  // twice would overstate the quiet half of the summary.
  it("counts a blocked thread as waiting, not as unread", () => {
    const tree = buildThreadTree([
      thread({ id: "a" }),
      thread({
        id: "b",
        parentThreadId: "a",
        hasPendingInteraction: true,
        isUnread: true,
      }),
    ]);
    expect(summarizeDescendants(tree[0]!)).toEqual({
      total: 1,
      waiting: 1,
      unread: 0,
    });
  });
});

describe("visibleRows", () => {
  const tree = buildThreadTree([
    thread({ id: "a" }),
    thread({ id: "b", parentThreadId: "a" }),
    thread({ id: "c", parentThreadId: "b" }),
    thread({ id: "z" }),
  ]);

  it("returns every row when nothing is collapsed", () => {
    expect(visibleRows(tree, new Set()).map((n) => n.thread.id)).toEqual([
      "a",
      "b",
      "c",
      "z",
    ]);
  });

  it("drops a collapsed subtree whole, not one level of it", () => {
    expect(visibleRows(tree, new Set(["a"])).map((n) => n.thread.id)).toEqual([
      "a",
      "z",
    ]);
  });

  it("keeps a collapsed row itself, and its siblings", () => {
    expect(visibleRows(tree, new Set(["b"])).map((n) => n.thread.id)).toEqual([
      "a",
      "b",
      "z",
    ]);
  });
});
