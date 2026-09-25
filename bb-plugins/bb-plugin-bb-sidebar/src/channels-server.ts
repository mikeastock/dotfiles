import type { BbPluginApi, JsonValue } from "@get-bb/plugin-sdk";
import { z } from "zod";
import {
  BOT_TEAMS_CHANNEL_STATE_METHOD,
  BOT_TEAMS_LIST_METHOD,
  BOT_TEAMS_PLUGIN_ID,
  CHANNELS_CHANNEL,
  botTeamsListSchema,
  snapshotFromList,
  type ChannelStateInput,
  type ChannelsSnapshot,
} from "./channels";

/**
 * The Channels shelf's backend: Bot Teams' RPCs, called through bb on the
 * frontend's behalf.
 */
export function createChannelsRpc(bb: BbPluginApi) {
  return {
    /**
     * Any failure — Bot Teams not installed, disabled, or answering in a shape
     * this sidebar does not understand — answers "unavailable" rather than
     * throwing. Bot Teams is optional; without it the sidebar has no shelf.
     */
    async listChannels(): Promise<ChannelsSnapshot> {
      try {
        const list = await bb.sdk.plugins.callRpc({
          pluginId: BOT_TEAMS_PLUGIN_ID,
          method: BOT_TEAMS_LIST_METHOD,
          input: null,
          outputSchema: botTeamsListSchema,
        });
        return snapshotFromList(list);
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        bb.log.debug(`channels unavailable: ${reason}`);
        return { available: false, reason };
      }
    },

    /** A write the user asked for, so a failure reaches them as an error. */
    async setChannelState(input: ChannelStateInput): Promise<{ ok: true }> {
      await bb.sdk.plugins.callRpc({
        pluginId: BOT_TEAMS_PLUGIN_ID,
        method: BOT_TEAMS_CHANNEL_STATE_METHOD,
        input: input as JsonValue,
        outputSchema: z.looseObject({ id: z.string() }),
      });
      bb.realtime.publish(CHANNELS_CHANNEL, {});
      return { ok: true };
    },
  };
}
