---
name: babysit-pr
description: Babysit a GitHub pull request through CI and review closure. Fetch all review feedback with better-github-skill, use judgment to address or push back on each item, comment on and resolve handled threads, and keep polling until the PR is closed or review/CI state needs user help. Use when the user asks an agent to monitor a PR, watch CI, handle review comments, or keep an eye on failures and feedback on an open PR.
---

# PR Babysitter

## Objective
Babysit a PR persistently until one of these terminal outcomes occurs:

- The PR is merged or closed.
- A situation requires user help (for example CI infrastructure issues, repeated flaky failures after retry budget is exhausted, permission problems, or ambiguity that cannot be resolved safely).
- Optional handoff milestone: the PR is currently green + mergeable + review-clean. Treat this as a progress state, not a watcher stop, so late-arriving review comments are still surfaced promptly while the PR remains open.

Do not stop merely because a single snapshot returns `idle` while checks are still pending.

Use the `gh` CLI exclusively for all GitHub reads and writes. This includes the
`better-github-skill` scripts, which are read-only wrappers around `gh`, plus direct `gh pr`, `gh run`,
and `gh api` (REST and GraphQL) commands for writes. Never use a harness-provided GitHub connector,
even if one is available.

Load and follow `better-github-skill` whenever this skill runs. Its PR snapshot and thread report are
the authoritative way to inspect PR state and feedback; the watcher supplies polling, retry, and
tracked-bot bookkeeping but is not a complete feedback source.

## Inputs
Accept any of the following:

- No PR argument: infer the PR from the current branch (`--pr auto`)
- PR number
- PR URL

## Core Workflow

1. When the user asks to "monitor"/"watch"/"babysit" a PR, start with the watcher's continuous mode (`--watch`) unless you are intentionally doing a one-shot diagnostic snapshot.
2. Run the watcher script to snapshot PR/review/CI state (or consume each streamed snapshot from `--watch`).
3. On every poll, independently run both `better-github-skill` reports: `pr-snapshot.ts` for complete PR state and `pr-threads.ts --all` for the complete review conversation. Do this even when the watcher reports `idle` or omits `process_review_comment`.
4. Inspect every published review body, PR issue comment, and inline thread from every author. Include resolved and outdated threads so follow-ups and feedback hidden by default are not missed. Ignore only pending draft reviews, pure automation/status noise, and the agent's own already-handled replies.
5. Inspect the watcher's `actions` list. If `diagnose_ci_failure` is present, inspect failed run logs and classify the failure.
6. If the failure is likely caused by the current branch, patch code locally, commit, and push. Do not patch random flaky tests, CI infrastructure, dependency outages, runner issues, or other failures that are unrelated to the branch.
7. Independently judge each feedback item; reviewer identity is context, not a substitute for technical validation. If it is correct and actionable, patch and test it. If it is incorrect, already addressed, obsolete, or out of scope, prepare a concise technical pushback. If it is ambiguous or requires a product decision, ask the user rather than guessing.
8. After handling an item, leave a concise reply when it clarifies the fix or pushback, then resolve its inline thread. Do not comment merely to acknowledge an item, do not reply repeatedly, and do not resolve a thread until every substantive point and follow-up in it has been handled. Use direct `gh` commands for comments and GraphQL resolution.
9. If the failure is likely flaky/unrelated and `retry_failed_checks` is present, rerun failed jobs with `--retry-failed-now`.
10. If both actionable review feedback and `retry_failed_checks` are present, prioritize review feedback first; a new commit will retrigger CI, so avoid rerunning flaky checks on the old SHA unless you intentionally defer the review change.
11. On every loop, fetch all feedback with `pr-threads.ts --all` and inspect unresolved threads before acting on CI failures or mergeability state, then verify mergeability, conflicts, and CI with `pr-snapshot.ts`.
12. After any push or rerun action, immediately return to step 1 and continue polling on the updated SHA/state.
13. If you had been using `--watch` before pausing to patch/commit/push, relaunch `--watch` yourself in the same turn immediately after the push (do not wait for the user to re-invoke the skill).
14. Repeat polling until `stop_pr_closed` appears or a user-help-required blocker is reached. A green + review-clean + mergeable PR is a progress milestone, not a reason to stop the watcher while the PR is still open.
15. Maintain terminal/session ownership: while babysitting is active, keep consuming watcher output in the same turn; do not leave a detached `--watch` process running and then end the turn as if monitoring were complete.

## Commands

### One-shot snapshot

```bash
python3 ~/.agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --once
```

### Continuous watch (JSONL)

```bash
python3 ~/.agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --watch
```

### Trigger flaky retry cycle (only when watcher indicates)

```bash
python3 ~/.agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --retry-failed-now
```

### Explicit PR target

```bash
python3 ~/.agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr <number-or-url> --once
```

### Fetch complete PR state and feedback

```bash
node ~/.agents/skills/better-github-skill/scripts/pr-snapshot.ts <pr> --json
node ~/.agents/skills/better-github-skill/scripts/pr-threads.ts <pr> --all --full --json
```

Omit `<pr>` to infer it from the current branch. Use `-R <owner>/<repo>` when outside the repository.
`--all` is required: the default thread report hides resolved and outdated threads. `--full` prevents
truncated feedback from hiding a substantive point. Save or compare the structured reports between
polls so every new comment and follow-up is considered exactly once.

### Resolve a handled tracked-bot review thread

The watcher returns each unresolved tracked-bot thread's GraphQL `id`, its latest bot comment, and
that comment's REST `rest_comment_id`. After making a fix or posting justified pushback, resolve the
exact thread through the guarded CLI command:

```bash
python3 ~/.agents/skills/babysit-pr/scripts/gh_pr_watch.py \
  --pr auto --resolve-review-thread <thread-id>
```

To reply to an inline comment before resolving it, use `gh api`, never a GitHub connector:

```bash
gh api repos/<owner>/<repo>/pulls/<pr>/comments \
  -X POST -f body='[agent] <concise fix or pushback rationale>' \
  -F in_reply_to=<rest-comment-id>
```

## CI Failure Classification
Use `gh` commands to inspect failed runs before deciding to rerun.

- `gh run view <run-id> --json jobs,name,workflowName,conclusion,status,url,headSha`
- `gh api repos/<owner>/<repo>/actions/runs/<run-id>/jobs -X GET -f per_page=100`
- `gh api repos/<owner>/<repo>/actions/jobs/<job-id>/logs > /tmp/codex-gh-job-<job-id>-logs.zip`
- `gh run view <run-id> --log-failed` as a fallback after the overall workflow run is complete

`gh run view --log-failed` is workflow-run scoped and may not expose failed-job logs until the overall run finishes. For faster diagnosis, poll the run's jobs first and, as soon as a specific job has failed, fetch that job's logs directly from the Actions job logs endpoint. The watcher includes a `failed_jobs` list with each failed job's `job_id` and `logs_endpoint` when GitHub exposes one.

Prefer treating failures as branch-related when failed-job logs point to changed code (compile/test/lint/typecheck/snapshots/static analysis in touched areas).

Prefer treating failures as flaky/unrelated when logs show transient infra/external issues (timeouts, runner provisioning failures, registry/network outages, GitHub Actions infra errors).

Do not attempt to fix flaky/unrelated failures by changing tests, build scripts, CI configuration, dependency pins, or infrastructure-adjacent code unless the logs clearly connect the failure to the PR branch. For flaky/unrelated failures, rerun only when the watcher recommends `retry_failed_checks`; otherwise wait or stop for user help.

If classification is ambiguous, perform one manual diagnosis attempt before choosing rerun.

Read `~/.agents/skills/babysit-pr/references/heuristics.md` for a concise checklist.

## Review Comment Handling
The watcher is deliberately selective and is not the complete review source. On every loop, use
`better-github-skill`'s `pr-threads.ts --all --full --json` report to fetch:

- PR issue comments
- Review submission bodies (COMMENT / APPROVED / CHANGES_REQUESTED)
- Every inline review thread, including resolved and outdated threads
- Feedback and follow-ups from humans, known review bots, and previously unknown review bots

Only act on published feedback. Ignore review submissions in GitHub's `PENDING` state and inline
comments attached to those pending reviews. Do not treat pending feedback as seen; reconsider it
after publication. On the first poll, inspect existing feedback as well as newly arriving feedback.

Classify each substantive item as `address`, `push back`, `needs clarification`, or `already handled`.
Validate claims against the current branch, PR diff, tests, and user intent. Batch compatible fixes
into a focused change, but preserve a clear mapping from each comment to its disposition.

`unresolved_bot_review_threads` is only the watcher's tracked-bot gate. The complete review-green gate
comes from the better-github thread report: do not call a PR review-clean while substantive feedback
is unjudged or any actionable inline thread remains unresolved, even if it is outdated or was seen in
an earlier snapshot. A review is green only when the current SHA's CI is green, there is no blocking
GitHub review decision, all published feedback has a disposition, and all handled actionable threads
are resolved. Continue watching after reaching that milestone because new feedback can arrive.

When you agree with actionable feedback:

1. Patch code locally.
2. Run focused validation, commit with `fix: address PR review feedback (#<n>)`, and push to the PR head branch.
3. Reply `[agent]` with the concise fix and commit SHA when it helps the reviewer, then resolve the exact thread.
4. Resume watching on the new SHA immediately (do not stop after reporting the push).
5. If monitoring was running in `--watch` mode, restart `--watch` immediately after the push in the same turn; do not wait for the user to ask again.

When you disagree with any comment, verify the claim against the branch and relevant tests. Reply
with a concise technical rationale, resolve the thread when appropriate, and continue watching. Do
not manufacture a code change merely to silence a reviewer.

Use judgment for human and bot feedback alike. You may reply to and resolve a review thread after
independently handling it; prefix agent-authored replies with `[agent]` so visible automation is
clear. Ask the user before posting only when the response makes a product decision, commits the user
to work beyond this PR, reveals sensitive information, or cannot be supported confidently from the
repository evidence. Treat the agent's own replies as handled and do not reply to them again.
Resolved or outdated threads still need inspection: normally leave them untouched, but act if they
contain an unaddressed substantive point or a new unresolved follow-up.

## GitHub State Mutation Policy

You can read any PR state you need for monitoring. Writes must comply with this policy.

You can push PRs to update the code under review or to force CI re-runs as described above.

You may reply to and resolve any review thread once you have independently judged and handled every
substantive point in it: correct findings receive a focused fix; invalid, obsolete, or out-of-scope
findings receive concise `[agent]` pushback. Use `gh api` for replies. The watcher's guarded
`--resolve-review-thread` command works only for tracked bots; resolve other eligible threads with
the GraphQL `resolveReviewThread` mutation using the thread ID from `pr-threads.ts --json`.

Before making any changes, fetch the PR state yourself instead of relying on the PR watcher script's
output.

Unless explicitly asked, do not:

* post non-substantive acknowledgements or speculative replies
* resolve a thread whose feedback or follow-ups have not been fully handled
* make product decisions or commitments on the user's behalf
* mark PRs as drafts or ready for review
* close or reopen PRs

In general, never act on GitHub in ways that would make it hard to tell whether you or the user did
something visible to other humans. When in doubt, ask the user for clarification in chat.

## Git Safety Rules

- Work only on the PR head branch.
- Avoid destructive git commands.
- Do not switch branches unless necessary to recover context.
- Before editing, check for unrelated uncommitted changes. If present, stop and ask the user.
- After each successful fix, commit and `git push`, then re-run the watcher.
- If you interrupted a live `--watch` session to make the fix, restart `--watch` immediately after the push in the same turn.
- Do not run multiple concurrent `--watch` processes for the same PR/state file; keep one watcher session active and reuse it until it stops or you intentionally restart it.
- A push is not a terminal outcome; continue the monitoring loop unless a strict stop condition is met.

Commit message defaults:

- `fix: resolve CI failure on PR #<n>`
- `fix: address PR review feedback (#<n>)`

## Monitoring Loop Pattern
Use this loop in a live agent session:

1. Run `--once`.
2. Read `actions`.
3. First check whether the PR is now merged or otherwise closed; if so, report that terminal state and stop polling immediately.
4. Run both `better-github-skill` reports. Check the complete published review conversation from every author, all unresolved threads, CI summary, and mergeability/conflict status.
5. Diagnose CI failures and classify branch-related vs flaky/unrelated. If the overall run is still pending but `failed_jobs` already includes a failed job, fetch that job's logs and diagnose immediately instead of waiting for the whole workflow run to finish. Patch only when the failure is branch-related.
6. For each substantive feedback item from any author, fix/push when valid or reply `[agent]` with concise evidence-based pushback when invalid, then resolve the fully handled inline thread. Ask the user only for ambiguous or product-level decisions. Treat later snapshots of your own reply as informational.
7. Process actionable review comments before flaky reruns when both are present; if a review fix requires a commit, push it and skip rerunning failed checks on the old SHA.
8. Retry failed checks only when `retry_failed_checks` is present and you are not about to replace the current SHA with a review/CI fix commit. Do not make code changes for unrelated flakes or infrastructure failures just to get CI green.
9. If you pushed a commit, commented, resolved an eligible review thread, or triggered a rerun, report the action briefly and continue polling (do not stop). Stop and ask only when feedback needs user judgment or a response you cannot support safely.
10. After a review-fix push, proactively restart continuous monitoring (`--watch`) in the same turn unless a strict stop condition has already been reached.
11. If everything is passing, mergeable, not blocked on required review approval, has no unaddressed review items, and has no actionable unresolved threads from any author, report that the PR is currently review-green and ready to merge but keep the watcher running so new review comments are surfaced quickly while the PR remains open.
12. If blocked on a user-help-required issue (infra outage, exhausted flaky retries, unclear reviewer request, permissions), report the blocker and stop.
13. Otherwise sleep according to the polling cadence below and repeat.

When the user explicitly asks to monitor/watch/babysit a PR, prefer `--watch` so polling continues autonomously in one command. Use repeated `--once` snapshots only for debugging, local testing, or when the user explicitly asks for a one-shot check.
Do not stop to ask the user whether to continue polling; continue autonomously until a strict stop condition is met or the user explicitly interrupts.
Do not hand control back to the user after a review-fix push just because a new SHA was created; restarting the watcher and re-entering the poll loop is part of the same babysitting task.
If a `--watch` process is still running and no strict stop condition has been reached, the babysitting task is still in progress; keep streaming/consuming watcher output instead of ending the turn.

## Polling Cadence
Keep review polling aggressive and continue monitoring even after CI turns green:

- While CI is not green (pending/running/queued or failing): poll every 1 minute.
- After CI turns green: keep polling at the base cadence while the PR remains open so newly posted review comments are surfaced promptly instead of waiting on a long green-state backoff.
- Reset the cadence immediately whenever anything changes (new commit/SHA, check status changes, new review comments, mergeability changes, review decision changes).
- If CI stops being green again (new commit, rerun, or regression): stay on the base polling cadence.
- If any poll shows the PR is merged or otherwise closed: stop polling immediately and report the terminal state.

## Stop Conditions (Strict)
Stop only when one of the following is true:

- PR merged or closed (stop as soon as a poll/snapshot confirms this).
- User intervention is required and the agent cannot safely proceed alone.

Keep polling when:

- `actions` contains only `idle` but checks are still pending.
- CI is still running/queued.
- Review state is quiet but CI is not terminal.
- CI is green but mergeability is unknown/pending.
- CI is green and mergeable, but the PR is still open and you are waiting for possible new review comments or merge-conflict changes.
- The PR is green but blocked on review approval (`REVIEW_REQUIRED` / similar); continue polling at the base cadence and surface any new review comments without asking for confirmation to keep watching.
- Any substantive feedback remains unjudged or any actionable inline thread remains unresolved, regardless of author or whether it became outdated after a push.

## Output Expectations
Provide concise progress updates while monitoring and a final summary that includes:

- During long unchanged monitoring periods, avoid emitting a full update on every poll; summarize only status changes plus occasional heartbeat updates.
- Treat push confirmations, intermediate CI snapshots, ready-to-merge snapshots, and review-action updates as progress updates only; do not emit the final summary or end the babysitting session unless a strict stop condition is met.
- A user request to "monitor" is not satisfied by a couple of sample polls; remain in the loop until a strict stop condition or an explicit user interruption.
- A review-fix commit + push is not a completion event; immediately resume live monitoring (`--watch`) in the same turn and continue reporting progress updates.
- When CI first transitions to all green for the current SHA, emit a one-time celebratory progress update (do not repeat it on every green poll). Preferred style: `🚀 CI is all green! 33/33 passed. Still on watch for review approval.`
- Do not send the final summary while a watcher terminal is still running unless the watcher has emitted/confirmed a strict stop condition; otherwise continue with progress updates.

- Final PR SHA
- CI status summary
- Mergeability / conflict status
- Review-green status and all remaining unresolved or unaddressed feedback
- Fixes pushed
- Flaky retry cycles used
- Remaining unresolved failures or review comments

## References

- Heuristics and decision tree: `~/.agents/skills/babysit-pr/references/heuristics.md`
- GitHub CLI/API details used by the watcher: `~/.agents/skills/babysit-pr/references/github-api-notes.md`
