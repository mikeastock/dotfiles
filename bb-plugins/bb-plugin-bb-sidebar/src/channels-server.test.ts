import { afterEach, describe, expect, it } from "vitest";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import plugin from "./server";

type CallRpcArgs = {
  pluginId: string;
  method: string;
  input?: unknown;
  outputSchema: { parse(value: unknown): unknown };
};

const disposers: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (disposers.length > 0) await disposers.pop()!();
});

/** A Bot Teams `list` answer, including state this sidebar must not pass on. */
const botTeamsList = {
  bots: [{ id: "bot_1", name: "Designer", home: "/secret/home" }],
  rooms: [
    {
      id: "room_1",
      name: "bedrock",
      memberIds: ["bot_1"],
      pinned: true,
      lastReadAt: 100,
      paused: false,
      createdAt: 1,
      updatedAt: 200,
    },
    {
      id: "room_2",
      name: "old",
      memberIds: [],
      archived: true,
      paused: false,
      createdAt: 1,
      updatedAt: 300,
    },
  ],
  activeRoomIds: ["room_1"],
  attentionCounts: { room_1: 1 },
  approvalCounts: {},
  botCreateRequests: [],
};

async function loadWithBotTeams(
  callRpc: (args: CallRpcArgs) => Promise<unknown>,
) {
  const { bb, harness } = createFakePluginHost({
    pluginId: "bb-sidebar",
    sdk: {
      threads: { list: async () => [] },
      plugins: {
        // bb parses the other plugin's answer with the caller's schema; the
        // fake does the same, so the narrowing is exercised here too.
        callRpc: async (args: CallRpcArgs) =>
          args.outputSchema.parse(await callRpc(args)),
      },
    },
  });
  await plugin(bb);
  disposers.push(() => harness.lifecycle.dispose());
  return harness;
}

describe("listChannels", () => {
  it("reads Bot Teams' roster through bb and narrows it to open channels", async () => {
    const harness = await loadWithBotTeams(async () => botTeamsList);

    const result = await harness.behavior.callRpc("listChannels", {});

    expect(result).toEqual({
      available: true,
      channels: [
        {
          id: "room_1",
          name: "bedrock",
          pinned: true,
          unread: true,
          working: true,
          needsYouCount: 1,
          updatedAt: 200,
        },
      ],
    });
    expect(JSON.stringify(result)).not.toContain("/secret/home");
    const calls = harness.inspection.sdk.callsTo("plugins.callRpc");
    expect(calls).toHaveLength(1);
    expect(calls[0]![0]).toMatchObject({
      pluginId: "bot-teams",
      method: "list",
      input: null,
    });
  });

  // Bot Teams is optional. Not installed, disabled, or answering in a shape
  // this sidebar does not understand all mean: no shelf, no error.
  it("answers unavailable when Bot Teams cannot be reached", async () => {
    const harness = await loadWithBotTeams(async () => {
      throw new Error("plugin bot-teams is not installed");
    });

    await expect(harness.behavior.callRpc("listChannels", {})).resolves.toEqual({
      available: false,
      reason: "plugin bot-teams is not installed",
    });
  });

  it("answers unavailable when Bot Teams' answer changes shape", async () => {
    const harness = await loadWithBotTeams(async () => ({ channels: [] }));

    const result = (await harness.behavior.callRpc("listChannels", {})) as {
      available: boolean;
    };
    expect(result.available).toBe(false);
  });
});

describe("setChannelState", () => {
  it("forwards the write to Bot Teams and signals the sidebar to re-read", async () => {
    const harness = await loadWithBotTeams(async ({ input }) => ({
      ...botTeamsList.rooms[0],
      ...(input as object),
    }));

    await expect(
      harness.behavior.callRpc("setChannelState", {
        id: "room_1",
        pinned: false,
      }),
    ).resolves.toEqual({ ok: true });

    const calls = harness.inspection.sdk.callsTo("plugins.callRpc");
    expect(calls.at(-1)![0]).toMatchObject({
      pluginId: "bot-teams",
      method: "channelState",
      input: { id: "room_1", pinned: false },
    });
    expect(harness.inspection.realtimeSignals.at(-1)).toMatchObject({
      channel: "channels",
    });
  });

  it("lets a failed write reach the caller", async () => {
    const harness = await loadWithBotTeams(async () => {
      throw new Error("Channel not found");
    });

    await expect(
      harness.behavior.callRpc("setChannelState", { id: "gone", archived: true }),
    ).rejects.toThrow("Channel not found");
    expect(
      harness.inspection.realtimeSignals.some(
        (signal) => signal.channel === "channels",
      ),
    ).toBe(false);
  });

  it("rejects fields this sidebar never writes", async () => {
    const harness = await loadWithBotTeams(async () => botTeamsList.rooms[0]);

    await expect(
      harness.behavior.callRpc("setChannelState", {
        id: "room_1",
        permissionMode: "full",
      }),
    ).rejects.toThrow();
    expect(harness.inspection.sdk.callsTo("plugins.callRpc")).toHaveLength(0);
  });
});
