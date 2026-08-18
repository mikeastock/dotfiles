/**
 * Auto-settle sweep: park threads whose pull request reached a terminal
 * merged state.
 *
 * The sweep only writes the same lifecycle rows the manual settle RPC writes,
 * so every guard in `lifecycle.ts` (canPark / resolveShelf) applies unchanged:
 * a thread that starts working or gains new attention after the settle comes
 * straight back to the inbox.
 *
 * Two rules are load-bearing, both inherited from earlier incarnations of
 * this idea (wiki pr-manager, pr-status):
 *
 * - A failed lookup is not information. `unavailable` (gh missing, host
 *   unreachable, timeout) leaves every table untouched.
 * - Once auto-settled, never auto-settle again (`auto_settled_at`). A manual
 *   un-settle is the user overruling the sweep, and merged is terminal, so no
 *   later PR state should re-trigger parking.
 */
import type Database from "better-sqlite3";
import type { BbPluginApi } from "@get-bb/plugin-sdk";

/** Re-probe "no PR" environments at most once a day — a PR may appear later. */
export const NONE_RECHECK_MS = 24 * 60 * 60 * 1000;
/** Max environments probed per tick; the rest wait for the next tick. */
export const TICK_ENV_CAP = 50;
/** Page size for thread enumeration. */
const THREAD_PAGE_SIZE = 200;

export interface AutoSettleSettings {
  autoSettle: boolean;
  settleClosed: boolean;
}

export type PrWatchState = "open" | "draft" | "merged" | "closed" | "none";

export type PrLookup =
  | {
      outcome: "available";
      state: "open" | "draft" | "merged" | "closed";
      url: string;
    }
  | { outcome: "absent" }
  | { outcome: "unavailable" };

export interface PrWatchRow {
  threadId: string;
  environmentId: string;
  prUrl: string | null;
  prState: PrWatchState;
  autoSettledAt: number | null;
  lastCheckedAt: number;
}

export interface SweepCandidate {
  threadId: string;
  environmentId: string;
}

/**
 * The fields the sweep reads off a `threads.list` row. Structural on purpose:
 * the list DTO carries all of these, and tests can build exactly this shape.
 */
export interface SweepThreadRow {
  id: string;
  status: string;
  pinnedAt: number | null;
  visibility: string;
  environmentId: string | null;
  hasPendingInteraction: boolean;
  activity: {
    activeWorkflowCount: number;
    activeBackgroundAgentCount: number;
    activeBackgroundCommandCount: number;
    activePlanModeCount: number;
    activeGoalCount: number;
  };
}

/**
 * The backend half of `canPark` plus the sweep's own parking rules. A session
 * can look `idle` while a workflow, background agent, background command,
 * plan, or goal is still running — every one of them must block parking.
 * Hiding a thread that is still working is the one failure this feature
 * cannot afford.
 */
export function isSweepCandidate(thread: SweepThreadRow): boolean {
  if (thread.status !== "idle") return false;
  if (thread.hasPendingInteraction) return false;
  if (thread.pinnedAt !== null) return false;
  if (thread.visibility !== "visible") return false;
  if (thread.environmentId === null) return false;
  const activity = thread.activity;
  return (
    activity.activeWorkflowCount === 0 &&
    activity.activeBackgroundAgentCount === 0 &&
    activity.activeBackgroundCommandCount === 0 &&
    activity.activePlanModeCount === 0 &&
    activity.activeGoalCount === 0
  );
}

/** Whether a prior watch row excuses a thread from this tick entirely. */
function isHandledByPriorRow(prior: PrWatchRow | undefined, now: number): boolean {
  if (prior === undefined) return false;
  // User-overrule rule: once auto-settled, never auto-settle again.
  if (prior.autoSettledAt !== null) return true;
  // "No PR" answers are sticky for a day: don't re-probe every tick.
  if (prior.prState === "none" && now - prior.lastCheckedAt < NONE_RECHECK_MS) {
    return true;
  }
  return false;
}

export interface SweepPlan {
  /** Threads to settle this tick. */
  settle: string[];
  /** pr_watch rows to upsert. Settled threads carry `autoSettledAt`. */
  record: PrWatchRow[];
}

/**
 * Pure planner: given candidate threads, one PR lookup per environment, and
 * prior watch rows, decide who settles and what gets recorded. No I/O — the
 * driver feeds it and applies the result.
 */
export function planSweep(args: {
  candidates: SweepCandidate[];
  /** One lookup per probed environment, keyed by environmentId. */
  lookups: Map<string, PrLookup>;
  /** Prior watch rows, keyed by threadId. */
  watchRows: Map<string, PrWatchRow>;
  settings: AutoSettleSettings;
  now: number;
}): SweepPlan {
  const settle: string[] = [];
  const record: PrWatchRow[] = [];

  for (const candidate of args.candidates) {
    if (isHandledByPriorRow(args.watchRows.get(candidate.threadId), args.now)) {
      continue;
    }

    const lookup = args.lookups.get(candidate.environmentId);
    // Beyond the tick cap — deferred to a later tick.
    if (lookup === undefined) continue;
    // A failed lookup is not information: leave every table untouched.
    if (lookup.outcome === "unavailable") continue;

    if (lookup.outcome === "absent") {
      record.push({
        threadId: candidate.threadId,
        environmentId: candidate.environmentId,
        prUrl: null,
        prState: "none",
        autoSettledAt: null,
        lastCheckedAt: args.now,
      });
      continue;
    }

    const shouldSettle =
      lookup.state === "merged" ||
      (lookup.state === "closed" && args.settings.settleClosed);

    record.push({
      threadId: candidate.threadId,
      environmentId: candidate.environmentId,
      prUrl: lookup.url,
      prState: lookup.state,
      autoSettledAt: shouldSettle ? args.now : null,
      lastCheckedAt: args.now,
    });
    if (shouldSettle) settle.push(candidate.threadId);
  }

  return { settle, record };
}

interface PrWatchDbRow {
  thread_id: string;
  environment_id: string;
  pr_url: string | null;
  pr_state: string;
  auto_settled_at: number | null;
  last_checked_at: number;
}

export function readWatchRows(db: Database.Database): Map<string, PrWatchRow> {
  const rows = db
    .prepare(
      `SELECT thread_id, environment_id, pr_url, pr_state,
              auto_settled_at, last_checked_at
         FROM pr_watch`,
    )
    .all() as PrWatchDbRow[];
  return new Map(
    rows.map((row) => [
      row.thread_id,
      {
        threadId: row.thread_id,
        environmentId: row.environment_id,
        prUrl: row.pr_url,
        prState: row.pr_state as PrWatchState,
        autoSettledAt: row.auto_settled_at,
        lastCheckedAt: row.last_checked_at,
      },
    ]),
  );
}

function upsertWatchRow(db: Database.Database, row: PrWatchRow): void {
  db.prepare(
    `INSERT INTO pr_watch
       (thread_id, environment_id, pr_url, pr_state, auto_settled_at, last_checked_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(thread_id) DO UPDATE SET
       environment_id  = excluded.environment_id,
       pr_url          = excluded.pr_url,
       pr_state        = excluded.pr_state,
       auto_settled_at = excluded.auto_settled_at,
       last_checked_at = excluded.last_checked_at`,
  ).run(
    row.threadId,
    row.environmentId,
    row.prUrl,
    row.prState,
    row.autoSettledAt,
    row.lastCheckedAt,
  );
}

async function lookupPullRequest(
  sdk: BbPluginApi["sdk"],
  log: BbPluginApi["log"],
  environmentId: string,
): Promise<PrLookup> {
  try {
    const result = await sdk.environments.pullRequest({ environmentId });
    if (result.outcome === "available") {
      return {
        outcome: "available",
        state: result.pullRequest.state,
        url: result.pullRequest.url,
      };
    }
    if (result.outcome === "absent") return { outcome: "absent" };
    log.debug(
      `pr-merge-sweep: lookup unavailable for ${environmentId}: ${result.message}`,
    );
    return { outcome: "unavailable" };
  } catch (error) {
    log.debug(
      `pr-merge-sweep: lookup threw for ${environmentId}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return { outcome: "unavailable" };
  }
}

export interface SweepDeps {
  sdk: BbPluginApi["sdk"];
  db: Database.Database;
  settings: AutoSettleSettings;
  log: BbPluginApi["log"];
  /** Threads already parked (settled or snoozed) — never touched by the sweep. */
  listParkedThreadIds(): Set<string>;
  /** The shared lifecycle write — the same path the manual settle RPC uses. */
  settle(threadId: string): void;
  now?: number;
}

/**
 * One sweep tick: enumerate quiet unparked threads, probe each distinct
 * environment's pull request once (capped), then settle the merged ones.
 * Idempotent — a repeated tick with unchanged GitHub state settles nothing.
 */
export async function runSweep(deps: SweepDeps): Promise<void> {
  const now = deps.now ?? Date.now();
  const parked = deps.listParkedThreadIds();
  const watchRows = readWatchRows(deps.db);

  const candidates: SweepCandidate[] = [];
  const projects = await deps.sdk.projects.list({ includePersonal: true });
  for (const project of projects) {
    let offset = 0;
    for (;;) {
      const threads = await deps.sdk.threads.list({
        projectId: project.id,
        archived: false,
        limit: THREAD_PAGE_SIZE,
        offset,
      });
      for (const thread of threads) {
        if (!isSweepCandidate(thread)) continue;
        if (parked.has(thread.id)) continue;
        const prior = watchRows.get(thread.id);
        if (isHandledByPriorRow(prior, now)) continue;
        // isSweepCandidate guarantees environmentId is non-null.
        candidates.push({
          threadId: thread.id,
          environmentId: thread.environmentId as string,
        });
      }
      if (threads.length < THREAD_PAGE_SIZE) break;
      offset += threads.length;
    }
  }

  // One probe per distinct environment, sequentially: each lookup is a gh
  // round trip, and personal scale is tens of environments.
  const environmentIds = [
    ...new Set(candidates.map((candidate) => candidate.environmentId)),
  ];
  const lookups = new Map<string, PrLookup>();
  for (const environmentId of environmentIds.slice(0, TICK_ENV_CAP)) {
    lookups.set(
      environmentId,
      await lookupPullRequest(deps.sdk, deps.log, environmentId),
    );
  }

  const plan = planSweep({
    candidates,
    lookups,
    watchRows,
    settings: deps.settings,
    now,
  });

  // Settle before recording: a crash after settle but before the upsert just
  // re-settles next tick (same shelf, harmless), while the reverse order
  // could strand a thread marked auto-settled but never parked.
  for (const threadId of plan.settle) {
    deps.settle(threadId);
    const row = plan.record.find((record) => record.threadId === threadId);
    deps.log.info(
      `pr-merge-sweep: settled ${threadId} (PR ${row?.prUrl ?? "unknown"}, state ${row?.prState ?? "unknown"})`,
    );
  }
  for (const row of plan.record) {
    upsertWatchRow(deps.db, row);
  }
}
