import type {
  PluginSidebarThread,
  PluginSidebarThreadIndicator,
} from "@get-bb/plugin-sdk/app";

/**
 * What a parent card says about its subtree when the list is collapsed.
 *
 * One kind per thread, most urgent first: a failure beats a raised hand,
 * which beats finished work you have not read, which beats live work. The
 * same order picks the glyph the badge draws when children disagree.
 */
export type ChildStatusKind = "failed" | "needs-you" | "done" | "working";

export const CHILD_STATUS_KINDS: readonly ChildStatusKind[] = [
  "failed",
  "needs-you",
  "done",
  "working",
];

export interface ChildStatusSummary {
  failed: number;
  needsYou: number;
  done: number;
  working: number;
  /** The most urgent kind present, or null when every child is idle and read. */
  dominant: ChildStatusKind | null;
}

export function isWorkingIndicator(
  indicator: PluginSidebarThreadIndicator,
): boolean {
  switch (indicator) {
    case "runtime":
    case "workflow":
    case "background-agent":
    case "background-command":
    case "plan-mode":
    case "goal":
    case "working-draft":
      return true;
    default:
      return false;
  }
}

export function childStatusKind(
  thread: PluginSidebarThread,
): ChildStatusKind | null {
  if (thread.indicator === "unread-error") return "failed";
  if (thread.hasPendingInteraction || thread.indicator === "waiting-for-input")
    return "needs-you";
  if (thread.indicator === "unread-success") return "done";
  if (isWorkingIndicator(thread.indicator)) return "working";
  return null;
}

export function childStatusSummary(
  threads: readonly PluginSidebarThread[],
): ChildStatusSummary {
  const summary: ChildStatusSummary = {
    failed: 0,
    needsYou: 0,
    done: 0,
    working: 0,
    dominant: null,
  };
  for (const thread of threads) {
    if (thread.isArchived) continue;
    switch (childStatusKind(thread)) {
      case "failed":
        summary.failed += 1;
        break;
      case "needs-you":
        summary.needsYou += 1;
        break;
      case "done":
        summary.done += 1;
        break;
      case "working":
        summary.working += 1;
        break;
      default:
        break;
    }
  }
  summary.dominant =
    CHILD_STATUS_KINDS.find((kind) => childStatusCount(summary, kind) > 0) ??
    null;
  return summary;
}

export function childStatusCount(
  summary: ChildStatusSummary,
  kind: ChildStatusKind,
): number {
  switch (kind) {
    case "failed":
      return summary.failed;
    case "needs-you":
      return summary.needsYou;
    case "done":
      return summary.done;
    case "working":
      return summary.working;
  }
}

/**
 * The counts as tooltip text, e.g. ", 1 failed, 2 need you". Empty when
 * nothing in the subtree needs a word.
 */
export function childStatusPhrase(summary: ChildStatusSummary): string {
  const parts: string[] = [];
  if (summary.failed > 0) parts.push(`${summary.failed} failed`);
  if (summary.needsYou > 0) parts.push(`${summary.needsYou} need you`);
  if (summary.done > 0) parts.push(`${summary.done} done`);
  if (summary.working > 0) parts.push(`${summary.working} working`);
  return parts.length > 0 ? `, ${parts.join(", ")}` : "";
}

/** The indicator whose glyph and tone stand for a kind. */
export function childStatusIndicator(
  kind: ChildStatusKind,
): PluginSidebarThreadIndicator {
  switch (kind) {
    case "failed":
      return "unread-error";
    case "needs-you":
      return "waiting-for-input";
    case "done":
      return "unread-success";
    case "working":
      return "runtime";
  }
}

/**
 * The children plus their children, so a grandchild that fails or asks for
 * input still surfaces on the card the user can see.
 */
export function childSubtree(
  children: readonly PluginSidebarThread[],
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>,
): PluginSidebarThread[] {
  const result: PluginSidebarThread[] = [];
  for (const child of children) {
    if (child.isArchived) continue;
    result.push(child);
    for (const grandchild of childrenByParent.get(child.id) ?? []) {
      if (!grandchild.isArchived) result.push(grandchild);
    }
  }
  return result;
}
