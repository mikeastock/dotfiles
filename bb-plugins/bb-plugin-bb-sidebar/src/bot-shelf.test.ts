import { describe, expect, it } from "vitest";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import { buildBotShelf, summarizeBotActivity } from "./bot-shelf";
import { resolveBotOwners, type BotsSnapshot, type SidebarBot } from "./bots";

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

function bot(overrides: Partial<SidebarBot> = {}): SidebarBot {
  return {
    id: "bot_1",
    name: "Reviewer",
    role: "Code review",
    avatar: {
      color: "#6d5efc",
      shape: "round",
      expression: "curious",
      motion: "calm",
    },
    hostId: "host_1",
    mainThreadId: "thr_main",
    hiddenUntilActivity: false,
    hiddenAt: null,
    sectionId: null,
    order: 0,
    linkedProjectIds: [],
    ...overrides,
  };
}

function snapshot(
  bots: SidebarBot[],
  bindings: { threadId: string; botId: string }[],
): Extract<BotsSnapshot, { available: true }> {
  return {
    available: true,
    bots,
    sections: [],
    bindings,
    hosts: [],
    personalProjectId: null,
  };
}

function shelf(
  threads: PluginSidebarThread[],
  bots: SidebarBot[],
  bindings: { threadId: string; botId: string }[],
  options: {
    scopeProjectId?: string | null;
    activeThreads?: PluginSidebarThread[];
  } = {},
) {
  return buildBotShelf({
    snapshot: snapshot(bots, bindings),
    ownerByThreadId: resolveBotOwners(threads, bindings),
    threads,
    activeThreads: options.activeThreads ?? threads,
    scopeProjectId: options.scopeProjectId ?? null,
  });
}

describe("summarizeBotActivity", () => {
  it("ranks waiting over working over error over unread over idle", () => {
    expect(summarizeBotActivity([]).kind).toBe("idle");
    expect(summarizeBotActivity([thread({ isUnread: true })]).kind).toBe(
      "unread",
    );
    expect(
      summarizeBotActivity([
        thread({ isUnread: true, indicator: "unread-error" }),
        thread({ id: "b", isUnread: true }),
      ]).kind,
    ).toBe("error");
    expect(
      summarizeBotActivity([
        thread({ indicator: "runtime" }),
        thread({ id: "b", isUnread: true, indicator: "unread-error" }),
      ]).kind,
    ).toBe("working");
    const summary = summarizeBotActivity([
      thread({ hasPendingInteraction: true }),
      thread({ id: "b", hasPendingInteraction: true, indicator: "runtime" }),
      thread({ id: "c", indicator: "runtime" }),
    ]);
    expect(summary).toEqual({
      kind: "waiting",
      waiting: 2,
      working: 2,
      total: 3,
    });
  });
});

describe("buildBotShelf", () => {
  it("groups a bot's conversations under it and leaves the rest for the list", () => {
    const threads = [
      thread({ id: "thr_main", title: "Main" }),
      thread({ id: "thr_child", title: "Child", parentThreadId: "thr_main" }),
      thread({ id: "thr_free", title: "Free" }),
    ];
    // The Active shelf folds children into their parent before the shelf
    // sees it, so only roots arrive as active rows.
    const result = shelf(threads, [bot()], [
      { threadId: "thr_main", botId: "bot_1" },
    ], { activeThreads: threads.filter((row) => row.parentThreadId === null) });
    expect(result.groups).toHaveLength(1);
    const entry = result.groups[0]!.bots[0]!;
    expect(entry.threads.map((row) => row.id)).toEqual(["thr_main"]);
    expect(entry.openTarget).toBe("thr_main");
    // The child counts toward the bot's activity even though it has no row.
    expect(entry.activity.total).toBe(2);
    expect(result.unassigned.map((row) => row.id)).toEqual(["thr_free"]);
  });

  it("keeps the Active shelf's own order for a bot's rows", () => {
    const threads = [
      thread({ id: "thr_b" }),
      thread({ id: "thr_a" }),
      thread({ id: "thr_c" }),
    ];
    const bindings = ["thr_a", "thr_b", "thr_c"].map((threadId) => ({
      threadId,
      botId: "bot_1",
    }));
    const result = shelf(threads, [bot({ mainThreadId: null })], bindings);
    expect(result.groups[0]!.bots[0]!.threads.map((row) => row.id)).toEqual([
      "thr_b",
      "thr_a",
      "thr_c",
    ]);
  });

  // A hidden bot has no row to hold its threads, and a thread must always
  // have a row somewhere — so they go back to the list as plain cards.
  it("returns a hidden bot's conversations to the list", () => {
    const threads = [thread({ id: "thr_main", updatedAt: 100 })];
    const result = shelf(
      threads,
      [bot({ hiddenUntilActivity: true, hiddenAt: 1_000 })],
      [{ threadId: "thr_main", botId: "bot_1" }],
    );
    expect(result.groups).toHaveLength(0);
    expect(result.unassigned.map((row) => row.id)).toEqual(["thr_main"]);
  });

  it("brings a hidden bot back once a conversation has new activity", () => {
    const threads = [thread({ id: "thr_main", updatedAt: 2_000 })];
    const result = shelf(
      threads,
      [bot({ hiddenUntilActivity: true, hiddenAt: 1_000 })],
      [{ threadId: "thr_main", botId: "bot_1" }],
    );
    expect(result.groups).toHaveLength(1);
    expect(result.unassigned).toHaveLength(0);
  });

  it("treats a binding to a bot the plugin no longer lists as unassigned", () => {
    const threads = [thread({ id: "thr_main" })];
    const result = shelf(threads, [], [
      { threadId: "thr_main", botId: "bot_gone" },
    ]);
    expect(result.groups).toHaveLength(0);
    expect(result.unassigned.map((row) => row.id)).toEqual(["thr_main"]);
  });

  it("opens the newest conversation when the main one is gone", () => {
    const threads = [
      thread({ id: "thr_old", createdAt: 1 }),
      thread({ id: "thr_new", createdAt: 2 }),
    ];
    const result = shelf(threads, [bot({ mainThreadId: "thr_deleted" })], [
      { threadId: "thr_old", botId: "bot_1" },
      { threadId: "thr_new", botId: "bot_1" },
    ]);
    expect(result.groups[0]!.bots[0]!.openTarget).toBe("thr_new");
  });

  it("still lists a bot with nothing to open", () => {
    const result = shelf([], [bot({ mainThreadId: null })], []);
    expect(result.groups[0]!.bots[0]!.openTarget).toBeNull();
    expect(result.groups[0]!.bots[0]!.threads).toEqual([]);
  });

  it("scopes bots to a project by link or by work", () => {
    const threads = [thread({ id: "thr_in", projectId: "proj_2" })];
    const bots = [
      bot({ id: "bot_linked", linkedProjectIds: ["proj_2"] }),
      bot({ id: "bot_working" }),
      bot({ id: "bot_elsewhere" }),
    ];
    const result = shelf(
      threads,
      bots,
      [{ threadId: "thr_in", botId: "bot_working" }],
      { scopeProjectId: "proj_2" },
    );
    expect(result.groups[0]!.bots.map((entry) => entry.bot.id)).toEqual([
      "bot_linked",
      "bot_working",
    ]);
  });

  it("only takes rows the Active shelf offered", () => {
    // An inactive or parked bot conversation is not an active row; it stays
    // on its own shelf and never appears under the bot.
    const threads = [thread({ id: "thr_quiet" }), thread({ id: "thr_live" })];
    const result = shelf(
      threads,
      [bot({ mainThreadId: null })],
      [
        { threadId: "thr_quiet", botId: "bot_1" },
        { threadId: "thr_live", botId: "bot_1" },
      ],
      { activeThreads: [threads[1]!] },
    );
    expect(result.groups[0]!.bots[0]!.threads.map((row) => row.id)).toEqual([
      "thr_live",
    ]);
    expect(result.groups[0]!.bots[0]!.activity.total).toBe(2);
    expect(result.unassigned).toEqual([]);
  });
});
