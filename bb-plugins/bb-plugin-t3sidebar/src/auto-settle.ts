/**
 * Auto-settle sweep: park threads whose pull request reached a terminal
 * merged state.
 *
 * The sweep only writes the same lifecycle rows the manual settle RPC writes,
 * so every guard in `lifecycle.ts` (canPark / resolveShelf) applies unchanged:
 * a thread that starts working or gains new attention after the settle comes
 * straight back to the inbox.
 *
 * Three rules are load-bearing, all inherited from earlier incarnations of
 * this idea (wiki pr-manager, pr-status):
 *
 * - A failed lookup is not information. `unavailable` (gh missing, host
 *   unreachable, timeout) leaves every table untouched. The same applies to
 *   the open-PR verification: if it cannot run, the settle does not happen.
 * - One merged PR does not make the thread terminal. Threads that produce a
 *   series of PRs from one environment (each on its own `bb/<slug>-<threadId>`
 *   branch) must not be parked while any sibling PR is still open.
 * - Overrule is per PR, not per thread (`auto_settled_pr_url`). A manual
 *   un-settle vetoes re-settling for the PR that triggered it, but when the
 *   thread's NEXT pull request merges the sweep may park it again.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type Database from "better-sqlite3";
import type { BbPluginApi } from "@get-bb/plugin-sdk";

const execFileAsync = promisify(execFile);

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
  /** The PR the auto-settle was for; a manual un-settle vetoes only this PR. */
  autoSettledPrUrl: string | null;
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

/**
 * Whether a prior "no PR" observation excuses a thread from this tick. The
 * user-overrule check is NOT here: it needs the current PR url, so it runs in
 * the planner after the lookup.
 */
function isHandledByPriorRow(prior: PrWatchRow | undefined, now: number): boolean {
  // "No PR" answers are sticky for a day: don't re-probe every tick.
  return (
    prior !== undefined &&
    prior.prState === "none" &&
    now - prior.lastCheckedAt < NONE_RECHECK_MS
  );
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
  /** Threads with open sibling PRs (or unverifiable ones) — never settled. */
  blockedThreads?: Set<string>;
  settings: AutoSettleSettings;
  now: number;
}): SweepPlan {
  const settle: string[] = [];
  const record: PrWatchRow[] = [];

  for (const candidate of args.candidates) {
    const prior = args.watchRows.get(candidate.threadId);
    if (isHandledByPriorRow(prior, args.now)) continue;

    const lookup = args.lookups.get(candidate.environmentId);
    // Beyond the tick cap — deferred to a later tick.
    if (lookup === undefined) continue;
    // A failed lookup is not information: leave every table untouched.
    if (lookup.outcome === "unavailable") continue;

    // User-overrule rule, scoped to the PR that triggered it: the user
    // un-settled after this exact PR settled the thread, so this exact PR
    // must never settle it again. A different PR may.
    if (
      lookup.outcome === "available" &&
      prior?.autoSettledPrUrl != null &&
      lookup.url === prior.autoSettledPrUrl
    ) {
      continue;
    }

    if (lookup.outcome === "absent") {
      record.push({
        threadId: candidate.threadId,
        environmentId: candidate.environmentId,
        prUrl: null,
        prState: "none",
        autoSettledAt: prior?.autoSettledAt ?? null,
        autoSettledPrUrl: prior?.autoSettledPrUrl ?? null,
        lastCheckedAt: args.now,
      });
      continue;
    }

    const terminal =
      lookup.state === "merged" ||
      (lookup.state === "closed" && args.settings.settleClosed);
    const shouldSettle =
      terminal && !(args.blockedThreads?.has(candidate.threadId) ?? false);

    record.push({
      threadId: candidate.threadId,
      environmentId: candidate.environmentId,
      prUrl: lookup.url,
      prState: lookup.state,
      autoSettledAt: shouldSettle ? args.now : (prior?.autoSettledAt ?? null),
      autoSettledPrUrl: shouldSettle
        ? lookup.url
        : (prior?.autoSettledPrUrl ?? null),
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
  auto_settled_pr_url: string | null;
  last_checked_at: number;
}

export function readWatchRows(db: Database.Database): Map<string, PrWatchRow> {
  const rows = db
    .prepare(
      `SELECT thread_id, environment_id, pr_url, pr_state,
              auto_settled_at, auto_settled_pr_url, last_checked_at
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
        autoSettledPrUrl: row.auto_settled_pr_url,
        lastCheckedAt: row.last_checked_at,
      },
    ]),
  );
}

function upsertWatchRow(db: Database.Database, row: PrWatchRow): void {
  db.prepare(
    `INSERT INTO pr_watch
       (thread_id, environment_id, pr_url, pr_state,
        auto_settled_at, auto_settled_pr_url, last_checked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(thread_id) DO UPDATE SET
       environment_id      = excluded.environment_id,
       pr_url              = excluded.pr_url,
       pr_state            = excluded.pr_state,
       auto_settled_at     = excluded.auto_settled_at,
       auto_settled_pr_url = excluded.auto_settled_pr_url,
       last_checked_at     = excluded.last_checked_at`,
  ).run(
    row.threadId,
    row.environmentId,
    row.prUrl,
    row.prState,
    row.autoSettledAt,
    row.autoSettledPrUrl,
    row.lastCheckedAt,
  );
}

/** "owner/repo" from a github.com PR url; null for anything else. */
export function repoFromPrUrl(url: string): string | null {
  const match = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/pull\/\d+/.exec(url);
  return match?.[1] ?? null;
}

/**
 * Lists the head branches of a repo's open PRs. Returns null when the check
 * cannot run — callers must treat null as "unknown" and fail closed.
 */
export type OpenPrBranchLister = (repo: string) => Promise<Set<string> | null>;

const listOpenPrBranchesWithGh: (log: BbPluginApi["log"], repo: string) => Promise<Set<string> | null> =
  async (log, repo) => {
    try {
      const { stdout } = await execFileAsync(
        "gh",
        [
          "pr",
          "list",
          "--repo",
          repo,
          "--state",
          "open",
          "--json",
          "headRefName",
          "--limit",
          "200",
        ],
        { timeout: 15_000 },
      );
      const rows = JSON.parse(stdout) as { headRefName: string }[];
      return new Set(rows.map((row) => row.headRefName));
    } catch (error) {
      log.debug(
        `pr-merge-sweep: open-PR listing failed for ${repo}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return null;
    }
  };

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
  /** Open-PR verification; defaults to `gh pr list` on the server host. */
  listOpenPrBranches?: OpenPrBranchLister;
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

  // One merged PR does not make the thread terminal. A thread can produce a
  // series of PRs from one environment — bb names those branches
  // bb/<slug>-<threadId>, so any open PR whose head branch carries the
  // thread id is unfinished work from the same thread, and it blocks the
  // settle. Verification failing closes the door too: no settle on
  // uncertain evidence.
  const blockedThreads = new Set<string>();
  const listBranches =
    deps.listOpenPrBranches ??
    ((repo: string) => listOpenPrBranchesWithGh(deps.log, repo));
  const branchesByRepo = new Map<string, Promise<Set<string> | null>>();
  for (const candidate of candidates) {
    const lookup = lookups.get(candidate.environmentId);
    if (lookup?.outcome !== "available") continue;
    const terminal =
      lookup.state === "merged" ||
      (lookup.state === "closed" && deps.settings.settleClosed);
    if (!terminal) continue;

    const repo = repoFromPrUrl(lookup.url);
    if (repo === null) {
      deps.log.debug(
        `pr-merge-sweep: not settling ${candidate.threadId}: unrecognized PR url ${lookup.url}`,
      );
      blockedThreads.add(candidate.threadId);
      continue;
    }
    let branchesPromise = branchesByRepo.get(repo);
    if (branchesPromise === undefined) {
      branchesPromise = listBranches(repo);
      branchesByRepo.set(repo, branchesPromise);
    }
    const branches = await branchesPromise;
    if (branches === null) {
      deps.log.info(
        `pr-merge-sweep: not settling ${candidate.threadId}: could not verify open PRs for ${repo}`,
      );
      blockedThreads.add(candidate.threadId);
      continue;
    }
    const open = [...branches].filter((branch) =>
      branch.includes(candidate.threadId),
    );
    if (open.length > 0) {
      deps.log.debug(
        `pr-merge-sweep: not settling ${candidate.threadId}: ${open.length} open PR(s) still in flight (${open.join(", ")})`,
      );
      blockedThreads.add(candidate.threadId);
    }
  }

  const plan = planSweep({
    candidates,
    lookups,
    watchRows,
    blockedThreads,
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
