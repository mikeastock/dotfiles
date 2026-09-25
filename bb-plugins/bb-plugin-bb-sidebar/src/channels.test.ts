import { describe, expect, it } from "vitest";
import {
  channelHref,
  channelIdFromPath,
  snapshotFromList,
  type BotTeamsList,
} from "./channels";

function room(overrides: Partial<BotTeamsList["rooms"][number]> = {}) {
  return {
    id: "room_1",
    name: "general",
    updatedAt: 100,
    lastReadAt: 100,
    ...overrides,
  };
}

function list(overrides: Partial<BotTeamsList> = {}): BotTeamsList {
  return {
    rooms: [],
    activeRoomIds: [],
    attentionCounts: {},
    approvalCounts: {},
    ...overrides,
  };
}

describe("snapshotFromList", () => {
  it("keeps open channels, pinned first, then most recently updated", () => {
    const snapshot = snapshotFromList(
      list({
        rooms: [
          room({ id: "old", name: "old", updatedAt: 10 }),
          room({ id: "archived", name: "archived", archived: true, updatedAt: 999 }),
          room({ id: "new", name: "new", updatedAt: 50 }),
          room({ id: "pinned", name: "pinned", pinned: true, updatedAt: 1 }),
        ],
      }),
    );

    expect(snapshot.available).toBe(true);
    if (!snapshot.available) return;
    expect(snapshot.channels.map((channel) => channel.id)).toEqual([
      "pinned",
      "new",
      "old",
    ]);
  });

  it("derives unread, working, and needs-you from Bot Teams' activity", () => {
    const snapshot = snapshotFromList(
      list({
        rooms: [
          room({ id: "quiet", updatedAt: 100, lastReadAt: 100 }),
          room({ id: "unread", updatedAt: 200, lastReadAt: 100 }),
          room({ id: "never-read", updatedAt: 5, lastReadAt: undefined }),
          room({ id: "busy" }),
        ],
        activeRoomIds: ["busy"],
        attentionCounts: { busy: 2 },
        approvalCounts: { busy: 1, quiet: 0 },
      }),
    );

    if (!snapshot.available) throw new Error("expected channels");
    const byId = new Map(snapshot.channels.map((c) => [c.id, c]));
    expect(byId.get("quiet")).toMatchObject({
      unread: false,
      working: false,
      needsYouCount: 0,
      pinned: false,
    });
    expect(byId.get("unread")?.unread).toBe(true);
    expect(byId.get("never-read")?.unread).toBe(true);
    expect(byId.get("busy")).toMatchObject({ working: true, needsYouCount: 3 });
  });

  it("carries only the fields a row needs", () => {
    const snapshot = snapshotFromList(
      list({
        rooms: [
          {
            ...room(),
            memberIds: ["bot_1"],
            permissionMode: "auto",
            responseBehavior: "smart",
          } as BotTeamsList["rooms"][number],
        ],
      }),
    );

    if (!snapshot.available) throw new Error("expected channels");
    expect(Object.keys(snapshot.channels[0]!).sort()).toEqual([
      "id",
      "name",
      "needsYouCount",
      "pinned",
      "unread",
      "updatedAt",
      "working",
    ]);
  });
});

describe("channel routes", () => {
  it("links to Bot Teams' channel page and reads the id back", () => {
    const href = channelHref("d07bf507-1e34-4435-87ec-b40ffe368b66");
    expect(href).toBe(
      "/plugins/bot-teams/channels/d07bf507-1e34-4435-87ec-b40ffe368b66",
    );
    expect(channelIdFromPath(href)).toBe(
      "d07bf507-1e34-4435-87ec-b40ffe368b66",
    );
  });

  it("reads the channel id from deeper channel routes", () => {
    expect(channelIdFromPath("/plugins/bot-teams/channels/room_1/msg/abc")).toBe(
      "room_1",
    );
  });

  it("answers null off a channel route", () => {
    expect(channelIdFromPath("/threads/thr_1")).toBeNull();
    expect(channelIdFromPath("/plugins/bot-teams/channels/")).toBeNull();
    expect(channelIdFromPath("/plugins/bot-teams/bots")).toBeNull();
  });
});
