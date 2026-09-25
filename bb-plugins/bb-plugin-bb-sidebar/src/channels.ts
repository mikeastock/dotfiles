/**
 * Channels, as read from the Bot Teams plugin (patleeman/bb-plugins,
 * `bb-plugin-bot-teams`).
 *
 * A plugin frontend can only call its own backend, so this plugin's server
 * asks bb to call Bot Teams' `list` RPC on its behalf and re-serves a narrowed
 * snapshot. Everything here is pure so both sides and the tests share it.
 */
import { z } from "zod";

/** Bot Teams' runtime id: package `bb-plugin-bot-teams`. */
export const BOT_TEAMS_PLUGIN_ID = "bot-teams";
/** Bot Teams' roster read: bots, channels, and per-channel activity. */
export const BOT_TEAMS_LIST_METHOD = "list";
/** Bot Teams' per-channel state write: pin, archive, read marker. */
export const BOT_TEAMS_CHANNEL_STATE_METHOD = "channelState";

/** This plugin's own realtime signal: re-read channels after a write here. */
export const CHANNELS_CHANNEL = "channels";

/** Where Bot Teams serves a channel. bb routes this link in place. */
export function channelHref(channelId: string): string {
  return `/plugins/${BOT_TEAMS_PLUGIN_ID}/channels/${channelId}`;
}

/** The id of the channel a pathname shows, or null. */
export function channelIdFromPath(pathname: string): string | null {
  const prefix = `/plugins/${BOT_TEAMS_PLUGIN_ID}/channels/`;
  if (!pathname.startsWith(prefix)) return null;
  const id = pathname.slice(prefix.length).split("/")[0];
  return id ? decodeURIComponent(id) : null;
}

/**
 * The part of Bot Teams' `list` answer this sidebar reads. Loose on purpose:
 * bots, bot-creation requests, and fields added later pass through bb's parse
 * and are dropped here, never reaching this plugin's frontend.
 */
const botTeamsRoomSchema = z.looseObject({
  id: z.string().min(1),
  name: z.string(),
  pinned: z.boolean().optional(),
  archived: z.boolean().optional(),
  lastReadAt: z.number().optional(),
  updatedAt: z.number(),
});

export const botTeamsListSchema = z.looseObject({
  rooms: z.array(botTeamsRoomSchema),
  activeRoomIds: z.array(z.string()),
  attentionCounts: z.record(z.string(), z.number()),
  approvalCounts: z.record(z.string(), z.number()),
});
export type BotTeamsList = z.infer<typeof botTeamsListSchema>;

export const sidebarChannelSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    pinned: z.boolean(),
    unread: z.boolean(),
    working: z.boolean(),
    /** Attention requests plus pending approvals: things waiting on the user. */
    needsYouCount: z.number().int().nonnegative(),
    updatedAt: z.number(),
  })
  .strict();
export type SidebarChannel = z.infer<typeof sidebarChannelSchema>;

export const channelsSnapshotSchema = z.discriminatedUnion("available", [
  z
    .object({
      available: z.literal(true),
      channels: z.array(sidebarChannelSchema),
    })
    .strict(),
  z.object({ available: z.literal(false), reason: z.string() }).strict(),
]);
export type ChannelsSnapshot = z.infer<typeof channelsSnapshotSchema>;

/**
 * Bot Teams' roster, reduced to the open channels a sidebar row needs, in
 * Bot Teams' own default order: pinned first, then most recently updated.
 * Archived channels stay on Bot Teams' Channels page.
 */
export function snapshotFromList(list: BotTeamsList): ChannelsSnapshot {
  const working = new Set(list.activeRoomIds);
  const channels = list.rooms
    .filter((room) => room.archived !== true)
    .map((room) => ({
      id: room.id,
      name: room.name,
      pinned: room.pinned === true,
      unread: room.updatedAt > (room.lastReadAt ?? 0),
      working: working.has(room.id),
      needsYouCount: Math.max(
        0,
        (list.attentionCounts[room.id] ?? 0) +
          (list.approvalCounts[room.id] ?? 0),
      ),
      updatedAt: room.updatedAt,
    }))
    .sort(
      (a, b) =>
        Number(b.pinned) - Number(a.pinned) ||
        b.updatedAt - a.updatedAt ||
        a.name.localeCompare(b.name),
    );
  return { available: true, channels };
}

/** The writes this sidebar makes, all through Bot Teams' `channelState`. */
export const channelStateInputSchema = z
  .object({
    id: z.string().min(1),
    pinned: z.boolean().optional(),
    archived: z.boolean().optional(),
    lastReadAt: z.number().optional(),
    markUnread: z.boolean().optional(),
  })
  .strict();
export type ChannelStateInput = z.infer<typeof channelStateInputSchema>;
