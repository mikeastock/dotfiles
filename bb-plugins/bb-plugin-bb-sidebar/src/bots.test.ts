import { describe, expect, it } from "vitest";
import {
  botMatchesQuery,
  botsListSchema,
  groupBotsBySection,
  isBotHidden,
  latestActivityAt,
  resolveBotOwners,
  type SidebarBot,
} from "./bots";

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
    mainThreadId: null,
    hiddenUntilActivity: false,
    hiddenAt: null,
    sectionId: null,
    order: 0,
    linkedProjectIds: [],
    ...overrides,
  };
}

describe("botsListSchema", () => {
  // The bots plugin's answer carries the bot's private state — instructions,
  // memory, settings. None of it may survive the parse.
  it("keeps only the sidebar fields and drops the private ones", () => {
    const parsed = botsListSchema.parse({
      bots: [
        {
          ...bot(),
          avatar: { ...bot().avatar, motion: "playful" },
          soul: "You are a careful reviewer.",
          memory: "The user prefers terse feedback.",
          settings: { tone: "dry" },
          stateHashes: {},
          hostId: "host_1",
        },
      ],
      sections: [{ id: "sec_1", name: "Ops", order: 0 }],
      threadBindings: [{ threadId: "thr_1", botId: "bot_1" }],
      hosts: [],
      projects: [],
      warnings: [],
      personalProjectId: "proj_personal",
    });
    expect(parsed.bots[0]).toEqual({
      ...bot(),
      avatar: { ...bot().avatar, motion: "playful" },
    });
    expect(parsed).not.toHaveProperty("projects");
    expect(parsed.hosts).toEqual([]);
    expect(parsed.personalProjectId).toBe("proj_personal");
    expect(JSON.stringify(parsed)).not.toContain("careful reviewer");
  });

  // Somebody else's plugin adds shapes and expressions over time; a new one
  // must draw a default face, not take the shelf down.
  it("falls back on an unknown shape, expression or colour", () => {
    const parsed = botsListSchema.parse({
      bots: [
        {
          ...bot(),
          avatar: {
            color: "purple",
            shape: "octagon",
            expression: "smug",
            motion: "wild",
          },
        },
      ],
      sections: [],
      threadBindings: [],
    });
    expect(parsed.bots[0]!.avatar).toEqual({
      color: "#6d5efc",
      shape: "round",
      expression: "curious",
      motion: "calm",
    });
  });
});

describe("resolveBotOwners", () => {
  const threads = [
    { id: "root", parentThreadId: null },
    { id: "child", parentThreadId: "root" },
    { id: "grandchild", parentThreadId: "child" },
    { id: "loose", parentThreadId: null },
  ];

  it("binds a thread directly and its descendants by inheritance", () => {
    const owners = resolveBotOwners(threads, [
      { threadId: "root", botId: "bot_a" },
    ]);
    expect(owners.get("root")).toBe("bot_a");
    expect(owners.get("child")).toBe("bot_a");
    expect(owners.get("grandchild")).toBe("bot_a");
    expect(owners.has("loose")).toBe(false);
  });

  it("lets the nearest binding win", () => {
    const owners = resolveBotOwners(threads, [
      { threadId: "root", botId: "bot_a" },
      { threadId: "child", botId: "bot_b" },
    ]);
    expect(owners.get("child")).toBe("bot_b");
    expect(owners.get("grandchild")).toBe("bot_b");
  });

  it("survives a parent cycle", () => {
    const owners = resolveBotOwners(
      [
        { id: "a", parentThreadId: "b" },
        { id: "b", parentThreadId: "a" },
      ],
      [],
    );
    expect(owners.size).toBe(0);
  });
});

describe("isBotHidden", () => {
  it("shows a bot that was never hidden", () => {
    expect(isBotHidden(bot(), null)).toBe(false);
  });

  it("hides a hidden bot until one of its threads does something new", () => {
    const hidden = bot({ hiddenUntilActivity: true, hiddenAt: 1_000 });
    expect(isBotHidden(hidden, null)).toBe(true);
    expect(isBotHidden(hidden, 900)).toBe(true);
    expect(isBotHidden(hidden, 1_000)).toBe(true);
    expect(isBotHidden(hidden, 1_001)).toBe(false);
  });

  it("keeps a hidden bot without a hide time hidden", () => {
    expect(
      isBotHidden(bot({ hiddenUntilActivity: true, hiddenAt: null }), 5),
    ).toBe(true);
  });
});

describe("latestActivityAt", () => {
  it("is null with no threads and the newest of either clock otherwise", () => {
    expect(latestActivityAt([])).toBeNull();
    expect(
      latestActivityAt([
        { updatedAt: 5, latestAttentionAt: 9 },
        { updatedAt: 7, latestAttentionAt: 1 },
      ]),
    ).toBe(9);
  });
});

describe("botMatchesQuery", () => {
  it("matches the name or the role, case-insensitively", () => {
    expect(botMatchesQuery(bot(), "review")).toBe(true);
    expect(botMatchesQuery(bot(), "CODE")).toBe(true);
    expect(botMatchesQuery(bot(), "deploy")).toBe(false);
    expect(botMatchesQuery(bot(), "   ")).toBe(true);
  });
});

describe("groupBotsBySection", () => {
  const sections = [
    { id: "sec_b", name: "Later", order: 1 },
    { id: "sec_a", name: "Ops", order: 0 },
  ];

  it("puts main first, then sections by order, bots by order within", () => {
    const groups = groupBotsBySection(
      [
        bot({ id: "b3", sectionId: "sec_b", order: 0 }),
        bot({ id: "b2", sectionId: "sec_a", order: 1 }),
        bot({ id: "b1", sectionId: "sec_a", order: 0 }),
        bot({ id: "b0", sectionId: null, order: 5 }),
      ],
      sections,
    );
    expect(
      groups.map((group) => [
        group.section?.name ?? null,
        group.bots.map((entry) => entry.id),
      ]),
    ).toEqual([
      [null, ["b0"]],
      ["Ops", ["b1", "b2"]],
      ["Later", ["b3"]],
    ]);
  });

  it("drops empty sections and returns a bot from a deleted section to main", () => {
    const groups = groupBotsBySection(
      [bot({ id: "b1", sectionId: "sec_gone" })],
      sections,
    );
    expect(groups).toHaveLength(1);
    expect(groups[0]!.section).toBeNull();
    expect(groups[0]!.bots[0]!.id).toBe("b1");
  });
});
