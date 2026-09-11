export const DEFAULT_AUTO_SETTLE_AFTER_DAYS = 3;
export const MIN_AUTO_SETTLE_AFTER_DAYS = 1;
export const MAX_AUTO_SETTLE_AFTER_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1_000;

export type SettledOverride = "active" | "settled";

export interface AutoSettleLifecycleState {
  settledAt: number | null;
  settledOverride: SettledOverride | null;
  snoozedUntil: number | null;
}

export interface AutoSettleThread {
  createdAt: number;
  latestAttentionAt: number;
  pinnedAt: number | null;
  status: "active" | "error" | "idle" | "pending" | "starting" | "stopping";
  updatedAt: number;
}

export type AutoSettlePullRequest =
  | { outcome: "absent" }
  | { outcome: "unknown" }
  | {
      outcome: "available";
      state: "closed" | "draft" | "merged" | "open";
      updatedAt: string;
    };

export interface AutoSettleSettings {
  afterDays: number | null;
  onMerge: boolean;
}

export type AutoSettleDecision = "keep" | "settle" | "unsettle";

/** Invalid settings disable inactivity settling instead of hiding work. */
export function parseAutoSettleAfterDays(
  enabled: boolean,
  rawDays: string,
): number | null {
  if (!enabled) return null;
  const days = Number(rawDays);
  return Number.isInteger(days) &&
    days >= MIN_AUTO_SETTLE_AFTER_DAYS &&
    days <= MAX_AUTO_SETTLE_AFTER_DAYS
    ? days
    : null;
}

/**
 * Resolve one automatic transition. Explicit user overrides are immutable
 * here; real thread activity clears them through the lifecycle event handler.
 */
export function decideAutoSettle({
  lifecycle,
  now,
  pullRequest,
  settings,
  thread,
}: {
  lifecycle: AutoSettleLifecycleState | null;
  now: number;
  pullRequest: AutoSettlePullRequest;
  settings: AutoSettleSettings;
  thread: AutoSettleThread;
}): AutoSettleDecision {
  if (lifecycle?.settledOverride != null) return "keep";

  const isAutomaticallySettled = lifecycle?.settledAt != null;
  const cannotSettle =
    thread.pinnedAt !== null ||
    thread.status === "active" ||
    thread.status === "starting" ||
    thread.status === "stopping" ||
    lifecycle?.snoozedUntil != null;
  if (cannotSettle) return isAutomaticallySettled ? "unsettle" : "keep";

  // A failed lookup is not evidence that no open PR exists. Keep the current
  // state until the next evaluation can make a safe decision.
  if (pullRequest.outcome === "unknown") return "keep";

  const activityAt = Math.max(
    thread.createdAt,
    thread.updatedAt,
    thread.latestAttentionAt,
  );
  let shouldSettle = false;

  if (pullRequest.outcome === "available") {
    const terminal =
      pullRequest.state === "closed" ||
      (pullRequest.state === "merged" && settings.onMerge);
    if (terminal) {
      const pullRequestUpdatedAt = Date.parse(pullRequest.updatedAt);
      // A malformed terminal timestamp is not evidence that the PR finished
      // after the thread's last activity. Keep the current state until a
      // trustworthy response arrives rather than hiding active work.
      if (Number.isNaN(pullRequestUpdatedAt)) return "keep";
      shouldSettle = pullRequestUpdatedAt >= activityAt;
    }

    // Draft PRs are open work too. Neither state may fall through to the
    // inactivity rule.
    if (pullRequest.state === "open" || pullRequest.state === "draft") {
      shouldSettle = false;
    }
  }

  if (!shouldSettle && settings.afterDays !== null) {
    const hasOpenPullRequest =
      pullRequest.outcome === "available" &&
      (pullRequest.state === "open" || pullRequest.state === "draft");
    shouldSettle =
      !hasOpenPullRequest &&
      activityAt < now - settings.afterDays * DAY_MS;
  }

  if (shouldSettle === isAutomaticallySettled) return "keep";
  return shouldSettle ? "settle" : "unsettle";
}
