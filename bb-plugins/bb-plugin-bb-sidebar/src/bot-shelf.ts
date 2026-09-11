import type { PluginSidebarThread } from "@get-bb/plugin-sdk/app";
import {
  groupBotsBySection,
  isBotHidden,
  latestActivityAt,
  type BotGroup,
  type BotsSnapshot,
  type SidebarBot,
} from "./bots";
import { isWorking } from "./useLifecycle";

export type BotActivityKind =
  | "waiting"
  | "working"
  | "error"
  | "unread"
  | "idle";

/**
 * One bot's conversations, rolled up the way a parent card rolls up its
 * children: a bot row has to keep speaking for what it groups.
 *
 * Waiting outranks working, which outranks a failure, which outranks unread —
 * the same order the card's own status slot follows, so the bot row and the
 * cards under it never disagree about what matters most.
 */
export interface BotActivitySummary {
  kind: BotActivityKind;
  waiting: number;
  working: number;
  total: number;
}

export function summarizeBotActivity(
  threads: readonly PluginSidebarThread[],
): BotActivitySummary {
  let waiting = 0;
  let working = 0;
  let failed = false;
  let unread = false;
  for (const thread of threads) {
    if (thread.hasPendingInteraction) waiting += 1;
    if (isWorking(thread)) working += 1;
    if (thread.isUnread && thread.indicator === "unread-error") failed = true;
    if (thread.isUnread) unread = true;
  }
  const kind: BotActivityKind =
    waiting > 0
      ? "waiting"
      : working > 0
        ? "working"
        : failed
          ? "error"
          : unread
            ? "unread"
            : "idle";
  return { kind, waiting, working, total: threads.length };
}

export interface BotShelfEntry {
  bot: SidebarBot;
  /** The bot's Active-shelf conversations, in the list's own order. */
  threads: PluginSidebarThread[];
  /** Rolled up over EVERY live conversation of the bot, not just the rows. */
  activity: BotActivitySummary;
  /**
   * What clicking the bot opens: its main conversation while that is live,
   * otherwise its newest conversation, otherwise nothing.
   */
  openTarget: string | null;
}

export interface BotShelf {
  groups: BotGroup<BotShelfEntry>[];
  /**
   * The Active-shelf threads left for the list: unassigned ones, and the
   * conversations of any bot that has no row here — hidden, or gone from
   * the bots plugin's list. A thread must always have a row somewhere.
   */
  unassigned: PluginSidebarThread[];
}

/**
 * The Bots shelf: which bots to draw, in what order, with which cards under
 * each — and which threads the Active shelf keeps.
 *
 * `threads` is every live (non-archived) thread, unfiltered: a bot's status
 * and its click target come from all of its work, because a bot that is
 * waiting on you in a project outside the current scope is still waiting on
 * you. `activeThreads` is the Active shelf's unpinned rows, already scoped,
 * ordered, and with children folded into their parents.
 */
export function buildBotShelf(input: {
  snapshot: Extract<BotsSnapshot, { available: true }>;
  ownerByThreadId: ReadonlyMap<string, string>;
  threads: readonly PluginSidebarThread[];
  activeThreads: readonly PluginSidebarThread[];
  /** Project scope, or null for all projects. */
  scopeProjectId: string | null;
}): BotShelf {
  const botIds = new Set(input.snapshot.bots.map((bot) => bot.id));
  const ownedByBot = groupByOwner(input.threads, input.ownerByThreadId, botIds);
  const activeByBot = groupByOwner(
    input.activeThreads,
    input.ownerByThreadId,
    botIds,
  );

  const entries: BotShelfEntry[] = [];
  const shown = new Set<string>();
  for (const bot of input.snapshot.bots) {
    const owned = ownedByBot.get(bot.id) ?? [];
    if (isBotHidden(bot, latestActivityAt(owned))) continue;

    // A scoped list shows a bot that belongs to the project — linked to it, or
    // working in it — and no other. An empty bot row in the wrong project
    // would only say "this bot exists", which the scope picker did not ask.
    if (
      input.scopeProjectId !== null &&
      !bot.linkedProjectIds.includes(input.scopeProjectId) &&
      !owned.some((thread) => thread.projectId === input.scopeProjectId)
    ) {
      continue;
    }

    const main = owned.find((thread) => thread.id === bot.mainThreadId);
    const newest = [...owned].sort(
      (left, right) =>
        right.createdAt - left.createdAt || left.id.localeCompare(right.id),
    )[0];

    shown.add(bot.id);
    entries.push({
      bot,
      threads: activeByBot.get(bot.id) ?? [],
      activity: summarizeBotActivity(owned),
      openTarget: main?.id ?? newest?.id ?? null,
    });
  }

  const unassigned = input.activeThreads.filter((thread) => {
    const owner = input.ownerByThreadId.get(thread.id);
    return owner === undefined || !shown.has(owner);
  });

  const groups = groupBotsBySection(
    entries.map((entry) => ({
      ...entry,
      id: entry.bot.id,
      sectionId: entry.bot.sectionId,
      order: entry.bot.order,
    })),
    input.snapshot.sections,
  ).map((group) => ({
    section: group.section,
    bots: group.bots.map(({ bot, threads, activity, openTarget }) => ({
      bot,
      threads,
      activity,
      openTarget,
    })),
  }));

  return { groups, unassigned };
}

function groupByOwner(
  threads: readonly PluginSidebarThread[],
  ownerByThreadId: ReadonlyMap<string, string>,
  botIds: ReadonlySet<string>,
): Map<string, PluginSidebarThread[]> {
  const grouped = new Map<string, PluginSidebarThread[]>();
  for (const thread of threads) {
    const owner = ownerByThreadId.get(thread.id);
    if (owner === undefined || !botIds.has(owner)) continue;
    const owned = grouped.get(owner);
    if (owned === undefined) grouped.set(owner, [thread]);
    else owned.push(thread);
  }
  return grouped;
}
