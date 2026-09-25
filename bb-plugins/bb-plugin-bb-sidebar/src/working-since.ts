import type { PluginSidebarThread } from "@get-bb/plugin-sdk/app";
import { isThreadWorking } from "./lifecycle";
import { safeSetItem } from "./lib/safe-storage";
import { relativeTimeLabel } from "./relative-time";

/**
 * When each live thread started its current stretch of work, by thread id.
 *
 * The host reports THAT a thread is working, not since when, so the sidebar
 * keeps its own clock: the first render that sees a thread working stamps it,
 * and the first render that sees it idle clears it. A thread that stops to
 * ask a question and then resumes starts over, which is the duration the user
 * cares about — how long since they last had to look.
 *
 * Stamps survive a reload through local storage. A thread that was already
 * working when the sidebar mounted and has no stored stamp counts from the
 * mount, so a label can read short but never long.
 */
export type WorkingSince = ReadonlyMap<string, number>;

export const WORKING_SINCE_STORAGE_KEY = "bb-sidebar:working-since:v1";

export const EMPTY_WORKING_SINCE: WorkingSince = new Map();

/**
 * Stamp threads that started working, clear ones that stopped or left the
 * list. Returns `previous` itself when nothing changed so callers can skip a
 * render.
 */
export function reconcileWorkingSince(
  previous: WorkingSince,
  threads: readonly PluginSidebarThread[],
  now: number,
): WorkingSince {
  const next = new Map<string, number>();
  let changed = false;
  for (const thread of threads) {
    if (!isThreadWorking(thread)) continue;
    const existing = previous.get(thread.id);
    if (existing === undefined) {
      changed = true;
      next.set(thread.id, now);
    } else {
      next.set(thread.id, existing);
    }
  }
  if (next.size !== previous.size) changed = true;
  return changed ? next : previous;
}

/**
 * "Working · 5m" once a minute has passed; bare "Working" before that.
 *
 * Reuses the age buckets so a duration and an age read alike. Under a minute
 * the age label says "now", which is the wrong word after a status, so the
 * duration is left off instead.
 */
export function statusWithDuration(
  label: string,
  startedAt: number | undefined,
  now: number,
): string {
  if (startedAt === undefined) return label;
  const elapsed = relativeTimeLabel(startedAt, now);
  return elapsed === "now" ? label : `${label} · ${elapsed}`;
}

export function readWorkingSince(): WorkingSince {
  try {
    const stored = window.localStorage.getItem(WORKING_SINCE_STORAGE_KEY);
    if (stored === null) return EMPTY_WORKING_SINCE;
    const parsed: unknown = JSON.parse(stored);
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      return EMPTY_WORKING_SINCE;
    }
    const map = new Map<string, number>();
    for (const [id, startedAt] of Object.entries(parsed)) {
      if (typeof startedAt === "number" && Number.isFinite(startedAt)) {
        map.set(id, startedAt);
      }
    }
    return map;
  } catch {
    return EMPTY_WORKING_SINCE;
  }
}

export function writeWorkingSince(workingSince: WorkingSince): void {
  safeSetItem(
    WORKING_SINCE_STORAGE_KEY,
    JSON.stringify(Object.fromEntries(workingSince)),
  );
}
