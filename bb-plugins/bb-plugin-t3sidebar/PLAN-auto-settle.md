# Plan: auto-settle threads when their GitHub PR merges

Status: plan, not yet implemented. Written 2026-08-18.

## Goal

When the pull request attached to a thread's environment reaches a terminal
merged state, move that thread to t3sidebar's **settled** shelf automatically —
without waking the thread, archiving it, or touching GitHub.

The settled shelf is reversible by design: `resolveShelf` in `src/lifecycle.ts`
already un-settles a thread when new attention arrives after the settle
timestamp, and already refuses to show a thread as parked while it is working
or blocked on the user (`canPark`). Auto-settle inherits those guards for free
because it only writes the same lifecycle rows the manual settle RPC writes.

## Non-goals

- No bb-native archive, stop, or delete. Settling is parking, not cleanup.
- No GitHub mutation of any kind (the pr-manager boundary: never comment,
  approve, close, merge, rerun, or edit).
- No wake/notification of the owning thread (pr-manager woke tasks via Codex
  app-server; here the thread stays parked unless the user returns to it).
- No LLM relevance gate. Settling is cheap and self-healing; pr-manager needed
  a Spark gate because waking a task was expensive.
- No global GitHub inventory (pr-manager scanner, pr-status GraphQL poll). bb
  provides the thread↔PR mapping natively, so ownership inference is
  unnecessary. Revisit only if sweep cost ever becomes real.
- No webhook receiver. bb serves on loopback; a cron sweep is enough.

## Lineage (why the design looks like this)

- **wiki `pr-manager`** contributes the state→action policy (merged = terminal,
  keep green/pending visible, never act on uncertain state) and one scar:
  dedupe fingerprints built from volatile check/mergeability fields produced
  duplicate wakes for PRs #10917/#10934 on 2026-07-17. This plan therefore
  keys decisions on **stable fields only** (`state`, `mergedAt`).
- **`pr-status`** contributes the transitions-not-snapshots discipline: keep a
  last-seen table, act on change, leave an audit trail.
- **bb plugin SDK** supplies everything else in-process: `bb.background.schedule`,
  `bb.sdk.threads.list`, `bb.sdk.environments.pullRequest`, the plugin SQLite,
  and the realtime channel the sidebar already re-reads on.

## Policy table

| PR lookup result                          | Sweep action |
|---|---|
| `available`, state `merged`               | Settle the thread (once — see the auto-settled rule) |
| `available`, state `closed` (unmerged)    | Settle only when the `settleClosed` setting is on; default off |
| `available`, state `open` / `draft`       | Nothing |
| `absent` (no PR for the branch)           | Nothing; record so we stop re-checking every tick |
| `unavailable` (gh/host failure)           | Nothing. Never treat a failed lookup as information |

Threads are skipped (never settled) when they are:

- already settled or snoozed (a snooze is a stronger statement than a settle);
- doing any live work — the full `canPark` rule, evaluated in the backend:
  `status !== "idle"`, `hasPendingInteraction`, or any of the list DTO's five
  activity counters (`activeWorkflowCount`, `activeBackgroundAgentCount`,
  `activeBackgroundCommandCount`, `activePlanModeCount`, `activeGoalCount`)
  above zero. A session can look `idle` while a workflow or background agent
  is still running; all six signals must be quiet;
- pinned (a pin is the user asking for visibility);
- hidden, archived, or missing an `environmentId`;
- previously auto-settled (`auto_settled_at` non-null). This is the
  user-overrule rule: if the user un-settles after the sweep parked a thread,
  the sweep must not park it again. Merged is terminal, so there is no later
  PR transition that should re-trigger it.

## Data model

Append one statement to the existing `migrations` array in `src/server.ts`
(append-only by statement index — never reorder):

```sql
CREATE TABLE IF NOT EXISTS pr_watch (
  thread_id       TEXT PRIMARY KEY,
  environment_id  TEXT NOT NULL,
  pr_url          TEXT,
  pr_state        TEXT,           -- last observed: open|draft|merged|closed|none
  auto_settled_at INTEGER,        -- non-null once the sweep has settled this thread
  last_checked_at INTEGER NOT NULL
)
```

Per-thread (not per-environment) so the user-overrule rule survives the
shared-environment case: two threads on one environment each get their own
row, and un-settling one says nothing about the other. Lookup dedupe by
environment happens in-memory during the tick.

Rows for `absent`/non-PR environments are written with `pr_state = 'none'` so
repeated ticks do not re-probe branches that never had a PR. (Re-probe
policy: a `none` row older than 24h is re-checked once, in case a PR appears
later; cheap because the sweep is small.)

## The sweep

Registered in the factory in `src/server.ts`, logic in a new
`src/auto-settle.ts` (pure planning + a thin driver, mirroring how
`src/lifecycle.ts` stays pure):

```ts
bb.background.schedule("pr-merge-sweep", "*/10 * * * *", async () => {
  const settings = await settingsHandle.get();
  if (!settings.autoSettle) return;
  await runSweep(bb, db, settings, bb.log);
});
```

`runSweep` steps:

1. Read the lifecycle table; build the skip set (settled, snoozed,
   `auto_settled_at` non-null, fresh `none` rows).
2. Enumerate candidate threads: `bb.sdk.projects.list({ includePersonal: true })`,
   then `bb.sdk.threads.list({ projectId, archived: false })` per project,
   paged with `limit`/`offset`. Keep threads that pass the full live-work
   filter above (idle status, no pending interaction, all activity counters
   zero), are unpinned, visible, have an `environmentId`, and are not in the
   skip set. All of these read straight off the list DTO.
3. Dedupe by `environmentId`.
4. For each environment, sequentially (each call is a `gh` round trip of
   ~0.5–2s; personal scale is tens of environments, so no parallelism needed —
   cap the tick at 50 environments and defer the rest to the next tick):
   `bb.sdk.environments.pullRequest({ environmentId })`.
   - Route per the policy table. `unavailable` logs at debug and moves on;
     it never increments any failure state that could suppress future ticks.
5. For each thread to settle: write the lifecycle row through the **same
   `write()` path the settle RPC uses** (`settledAt = now`, snooze fields
   null — candidates are never snoozed, so nothing is clobbered), which
   publishes the realtime signal the sidebar re-reads on. Then upsert the
   `pr_watch` row with `auto_settled_at = now`.
6. `bb.log.info` one line per settle: thread id, PR url, previous state.

The schedule's own `last_status`/`last_error` (visible in `bb plugin list`)
is the tick health surface; a throwing tick only marks the schedule row, it
cannot strand the plugin.

### Event-driven complement (phase 2, small)

`bb.events.on("thread.idle", …)`: run the single-thread version of the same
check for that thread's environment. Catches "PR merged just before the agent
finished" immediately instead of up to 10 minutes later. Shares the policy
and `pr_watch` writes with the sweep — one code path, two triggers.

## Settings

Declared via the existing `bb.settings.define` pattern:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `autoSettle` | boolean | `true` | Master switch; a tick with it off is a no-op |
| `settleClosed` | boolean | `false` | Also settle threads whose PR was closed unmerged |

Settings edits do not reload the plugin; the sweep re-reads `settings.get()`
per tick, so toggles take effect on the next tick without a reload. The cron
interval itself is fixed at registration (`*/10 * * * *`) — changing it means
editing code and reloading, which is deliberate.

## Files

- `src/auto-settle.ts` — new. Pure `planSettlements(candidates, prResults,
  watchRows, settings, now) → { settle: threadId[], record: WatchRow[] }`
  plus the `runSweep` driver.
- `src/auto-settle.test.ts` — new. Unit tests for the planner.
- `src/server.ts` — append the migration, define the two settings, register
  the schedule (and the phase-2 idle hook), extract the existing lifecycle
  `write()` so both the RPC and the sweep share it.
- `src/server.test.ts` (new, or extend existing harness coverage) — fake-host
  tests, below.
- `README.md` — document the feature, the policy table, and the settings.

## Testing

Unit (planner, vitest, no harness):

- merged transition settles; open/draft/absent/unavailable do not;
- `settleClosed` off/on for closed-unmerged;
- skip sets respected: settled, snoozed, pinned, non-idle, hidden,
  no-environment, `auto_settled_at` non-null (the user-overrule rule);
- environment dedupe: two threads on one environment → one lookup, two
  settlements; un-settling one thread does not skip the other;
- `none` rows suppress re-probing until the 24h refresh;
- 50-environment tick cap defers the remainder.

Fake host (`createFakePluginHost` from `@get-bb/plugin-sdk/testing`, real
better-sqlite3 — never mock the db):

- seed `sdk` stubs for `projects.list`, `threads.list`,
  `environments.pullRequest`; run the factory, then
  `harness.behavior.runSchedule("pr-merge-sweep")`;
- assert lifecycle rows written (same shape as the manual `settle` RPC),
  `pr_watch` rows upserted, realtime signals published on the lifecycle
  channel, and the exact SDK call list in `harness.inspection.sdk.calls`;
- run the schedule twice: the second tick settles nothing (idempotence);
- user-overrule: call the `unsettle` RPC via `harness.behavior.callRpc`,
  re-run the schedule, assert no re-settle;
- migration is append-only: existing `thread_lifecycle` rows survive the
  added statement (harness reload preserves db state);
- an `unavailable` PR result leaves all tables untouched.

Live loop:

- `bb plugin dev` in the plugin directory; `bb plugin logs t3sidebar -f`;
- force one immediate tick by temporarily pointing the cron at `* * * * *`,
  or drive `runSchedule` from a focused test against a real database copy;
- use a real thread on a branch whose PR is already merged: it should drop to
  the settled shelf within one tick, with one log line; un-settle it by hand
  and confirm it stays un-settled across the next tick.

## Resolved questions

- **List DTO richness (verified against `threadListResponseSchema` in the
  bundled SDK declarations): one `threads.list` call per project is enough —
  no `threads.get` fallback.** The list DTO carries `status`, `pinnedAt`,
  `environmentId`, `visibility`, `archivedAt`, `hasPendingInteraction`,
  `latestAttentionAt`, `environmentHostId`, and the five `activity.*Count`
  live-work counters. That is every signal the candidate filter needs,
  including the full `canPark` activity picture.
- **No settled-reason indicator.** Decided: the thread just settles and
  disappears from the inbox. No `listAutoSettlements` RPC, no card badge.
  The `bb.log` line per settle is the only explanation surface.
- Side-chat threads: sweep whatever `threads.list({ archived: false })`
  returns with default visibility; do not special-case side chats in v1.
