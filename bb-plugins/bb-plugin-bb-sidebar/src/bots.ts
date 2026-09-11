/**
 * Bots, as read from tobi/bb-bots-sidebar.
 *
 * That plugin owns the bots: their identity, memory, avatar and the binding
 * from a conversation to the bot it belongs to. This sidebar never writes any
 * of it. It asks the bots plugin's own `bots_list` RPC (through
 * `bb.sdk.plugins.callRpc`, on the server) and shows the answer, so the two
 * sidebars always agree on which conversation is whose.
 *
 * Everything here is pure and shared by the server and the app: the schema
 * that narrows the upstream answer to what a row needs, and the ownership
 * walk that both sidebars use.
 */
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import { z } from "zod";

/** The runtime id of bb-bots-sidebar: package `bb-plugin-bots-sidebar`. */
export const BOTS_PLUGIN_ID = "bots-sidebar";
/** The upstream RPC method this sidebar reads bots from. */
export const BOTS_LIST_METHOD = "bots_list";
/** Channel the frontend re-reads bots on. */
export const BOTS_CHANNEL = "bots";

export const BOT_AVATAR_SHAPES = [
  "round",
  "blob",
  "squircle",
  "capsule",
  "triangle",
  "hexagon",
  "cloud",
  "droplet",
] as const;
export const BOT_AVATAR_EXPRESSIONS = [
  "curious",
  "happy",
  "focused",
  "sleepy",
  "neutral",
  "surprised",
  "excited",
  "laughing",
  "angry",
  "sad",
  "scared",
  "suspicious",
  "confused",
  "proud",
  "shy",
  "unimpressed",
] as const;
export type BotAvatarShape = (typeof BOT_AVATAR_SHAPES)[number];
export type BotAvatarExpression = (typeof BOT_AVATAR_EXPRESSIONS)[number];

const id = z.string().min(1);

// `.catch()` throughout: the bots plugin is somebody else's, and a shape or
// expression it ships tomorrow must degrade to a default here, not take the
// whole shelf down with a validation error.
export const botAvatarSchema = z.object({
  color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/)
    .catch("#6d5efc"),
  shape: z.enum(BOT_AVATAR_SHAPES).catch("round"),
  expression: z.enum(BOT_AVATAR_EXPRESSIONS).catch("curious"),
});
export type BotAvatar = z.infer<typeof botAvatarSchema>;

/**
 * One bot, narrowed to what a sidebar row needs. Unknown keys are dropped at
 * the parse, so none of the bot's private state — instructions, memory,
 * settings — ever crosses into this plugin or its frontend.
 */
export const sidebarBotSchema = z.object({
  id,
  name: z.string(),
  role: z.string().catch(""),
  avatar: botAvatarSchema,
  mainThreadId: z.string().nullable().catch(null),
  hiddenUntilActivity: z.boolean().catch(false),
  hiddenAt: z.number().nullable().catch(null),
  sectionId: z.string().nullable().catch(null),
  order: z.number().catch(0),
  linkedProjectIds: z.array(z.string()).catch([]),
});
export type SidebarBot = z.infer<typeof sidebarBotSchema>;

export const botSectionSchema = z.object({
  id,
  name: z.string(),
  order: z.number().catch(0),
});
export type BotSection = z.infer<typeof botSectionSchema>;

export const botBindingSchema = z.object({ threadId: id, botId: id });
export type BotBinding = z.infer<typeof botBindingSchema>;

/** The part of `bots_list`'s answer this sidebar reads. */
export const botsListSchema = z.object({
  bots: z.array(sidebarBotSchema),
  sections: z.array(botSectionSchema).catch([]),
  threadBindings: z.array(botBindingSchema).catch([]),
});
export type BotsList = z.infer<typeof botsListSchema>;

/**
 * What this plugin's own `listBots` answers with. "Unavailable" is a normal
 * state, not an error: the bots plugin is optional, and a sidebar without it
 * is simply the inbox it always was.
 */
export const botsSnapshotSchema = z.discriminatedUnion("available", [
  z.object({
    available: z.literal(true),
    bots: z.array(sidebarBotSchema),
    sections: z.array(botSectionSchema),
    bindings: z.array(botBindingSchema),
  }),
  z.object({ available: z.literal(false), reason: z.string() }),
]);
export type BotsSnapshot = z.infer<typeof botsSnapshotSchema>;

export function snapshotFromList(list: BotsList): BotsSnapshot {
  return {
    available: true,
    bots: list.bots,
    sections: list.sections,
    bindings: list.threadBindings,
  };
}

/**
 * Which bot each thread belongs to, by thread id.
 *
 * Ownership is explicit or inherited from the nearest bound ancestor, never
 * inferred from a project — several bots can share one project. This is the
 * same walk bb-bots-sidebar does, so a conversation sits under the same bot
 * in both sidebars. Parentage comes from the server and nothing guarantees it
 * is acyclic, so the walk carries a visited set.
 */
export function resolveBotOwners(
  threads: readonly Pick<PluginSidebarThread, "id" | "parentThreadId">[],
  bindings: readonly BotBinding[],
): Map<string, string> {
  const direct = new Map(bindings.map((row) => [row.threadId, row.botId]));
  const byId = new Map(threads.map((thread) => [thread.id, thread]));
  const owners = new Map<string, string>();
  for (const thread of threads) {
    let current: string | null = thread.id;
    const visited = new Set<string>();
    while (current !== null && !visited.has(current)) {
      visited.add(current);
      const owner = direct.get(current);
      if (owner !== undefined) {
        owners.set(thread.id, owner);
        break;
      }
      current = byId.get(current)?.parentThreadId ?? null;
    }
  }
  return owners;
}

/** The newest thing that happened in any of a bot's threads; null with none. */
export function latestActivityAt(
  threads: readonly Pick<PluginSidebarThread, "updatedAt" | "latestAttentionAt">[],
): number | null {
  if (threads.length === 0) return null;
  return threads.reduce(
    (latest, thread) =>
      Math.max(latest, thread.updatedAt, thread.latestAttentionAt),
    0,
  );
}

/**
 * bb-bots-sidebar's "hide until activity": the bot stays out of the list
 * until one of its conversations does something after the hide. Same rule
 * here, so hiding a bot there hides it here too.
 */
export function isBotHidden(
  bot: Pick<SidebarBot, "hiddenUntilActivity" | "hiddenAt">,
  latestActivity: number | null,
): boolean {
  if (!bot.hiddenUntilActivity) return false;
  if (latestActivity === null) return true;
  return latestActivity <= (bot.hiddenAt ?? Number.MAX_SAFE_INTEGER);
}

/** Substring match on the bot's name or role, the way the list matches titles. */
export function botMatchesQuery(
  bot: Pick<SidebarBot, "name" | "role">,
  query: string,
): boolean {
  const normalized = query.trim().toLowerCase();
  if (normalized.length === 0) return true;
  return (
    bot.name.toLowerCase().includes(normalized) ||
    bot.role.toLowerCase().includes(normalized)
  );
}

export interface BotGroup<T> {
  /** Null for bb-bots-sidebar's implicit "Main" section, which has no heading. */
  section: BotSection | null;
  bots: T[];
}

/**
 * Bots in the order bb-bots-sidebar shows them: the unnamed main section
 * first, then each custom section by its order, bots by their order within.
 * A bot pointing at a section that no longer exists falls back to main
 * rather than vanishing. Empty groups are dropped.
 */
export function groupBotsBySection<T extends Pick<SidebarBot, "id" | "sectionId" | "order">>(
  bots: readonly T[],
  sections: readonly BotSection[],
): BotGroup<T>[] {
  const sorted = [...bots].sort(
    (left, right) => left.order - right.order || left.id.localeCompare(right.id),
  );
  const orderedSections = [...sections].sort(
    (left, right) => left.order - right.order || left.id.localeCompare(right.id),
  );
  const known = new Set(orderedSections.map((section) => section.id));
  const groups: BotGroup<T>[] = [
    {
      section: null,
      bots: sorted.filter(
        (bot) => bot.sectionId === null || !known.has(bot.sectionId),
      ),
    },
  ];
  for (const section of orderedSections) {
    groups.push({
      section,
      bots: sorted.filter((bot) => bot.sectionId === section.id),
    });
  }
  return groups.filter((group) => group.bots.length > 0);
}
