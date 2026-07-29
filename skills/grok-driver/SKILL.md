---
name: grok-driver
description: Use the headless Grok CLI as the coding driver for implementation work, with the host agent as coordinator. Use when delegating implementation from a frozen spec, mechanical migrations, or fixes with a known repro; the coordinator designs and freezes work orders, Grok implements them in fresh headless runs, and the coordinator independently verifies every diff and proof gate before advancing.
---

# Grok Driver

Use headless Grok as the implementation driver while the host agent (Claude)
stays coordinator. This is the complement of `grok-review`: grok-review
reviews, grok-driver implements. The coordinator designs, freezes
specifications into work orders, delegates the build-out to Grok, and then
verifies the result the way a maintainer verifies a contributor PR. Grok's
claims about its own work are advisory until independently verified.

## When to use / when not

Delegate to Grok:

- Implementation of a frozen, fully decided spec.
- Mechanical migrations and refactors with a known shape.
- Fixes with a known reproduction and a clear proof gate.
- Git mechanics inside a work order: merges, rebases, conflict resolution.

Keep in the host session:

- Tiny edits where writing the spec costs more than the change.
- Design work, architecture decisions, and anything with open questions.
- Anything that needs host-session tools, credentials, or interactive state.

Mixed task: design first, freeze the spec, then delegate the build-out.

## Division of labor

The coordinator:

- Designs and freezes specs; a work order contains no open design questions.
- Reviews every resulting diff like a contributor PR.
- Reruns all proof gates itself; Grok's pass/fail claims are advisory.
- Answers open questions from reports with explicit numbered decisions.
- Owns all land/push decisions. Grok never pushes without instruction.
- After 2 failed fix rounds on the same issue, takes over directly instead of
  sending a third fix prompt.

Grok:

- Implements from the frozen work order, including git mechanics within it.
- Reports what it did, with proof output, deviations, and open questions.
- Stops and reports rather than improvising when the spec and repo disagree.

## Invocation contract

One work order = one fresh headless run:

```bash
grok --cwd <repo> --prompt-file <spec.md> \
  --permission-mode bypassPermissions --no-plan --no-memory \
  --reasoning-effort high > out.md 2> err.log
```

- Pass the prompt via `--prompt-file`, never inline quoting.
- Capture stdout as the report (`out.md`) and stderr as the log (`err.log`).
  Read only the report into context; stderr carries thinking noise that
  bloats the coordinator's context for no signal.
- Follow-up fixes on the same work order resume the session, which keeps
  context and is cheaper than a fresh run:

  ```bash
  grok --cwd <repo> --resume --prompt-file <fix.md> \
    --permission-mode bypassPermissions --no-plan --reasoning-effort high \
    > fix-out.md 2> fix-err.log
  ```

- New work orders always get fresh sessions (`--no-memory`). A saturated
  session misreads a new order through the lens of the old one.
- Run each worker as a tracked background command (in Claude Code: Bash with
  `run_in_background`, one chip per worker). Never `&`-fork workers from a
  shared launcher; the host loses liveness tracking and exit status.
- Serialize work orders that share a worktree. Never merge, rebase, or edit
  in a worktree while a Grok run has uncommitted files there.
- `--resume` is cwd-scoped and races with any parallel Grok run on the
  machine; with one run per cwd it is deterministic. Keep it that way.

## Work-order spec contract

Every spec file must contain:

1. **Goal and frozen decisions.** No open design questions; decisions the
   worker might otherwise make are made here.
2. **Verified current-state facts** with exact paths. Verify each fact in the
   repo before writing the spec; a wrong "fact" wastes a whole run.
3. **Steps** with exact table/file/command detail wherever precision matters.
4. **Non-goals.** "Handled in a later work order; expected to be temporarily
   broken" is a valid, explicit state.
5. **Proof required:** the exact commands whose full output must appear in
   the report.
6. **Constraints:** no push without instruction, logical commits, and any
   environment isolation rules (e.g. a per-worktree `DATABASE_URL` when
   workers share a database server).
7. **Escape hatch**, verbatim in spirit: "If a gate fails after honest
   attempts, or the spec contradicts repo reality: STOP, commit what is
   sound, and report the exact diagnosis. A stop-report is a successful
   run." This clause does real work — it lets the worker surface a genuine
   spec error (say, a prerequisite migration the spec forgot) instead of
   hacking around it.
8. **Output shape:** files changed grouped by area, each proof command with
   pass/fail and the tail of its output, deviations from the spec, and open
   questions for the coordinator.

Repo-specific gate quirks belong in the spec, not in this skill. Example: a
test runner that regenerates OpenAPI docs from whatever subset it ran, wiping
paths — the spec must name the full regeneration command to run instead.

## Coordinator verification

After every run, non-negotiable:

1. Read the actual diff (`git diff <pre>..<post>`), not the report. Look
   specifically for spec-dodging: fabricated fallback values, weakened or
   deleted tests, and edits to guard files the spec didn't authorize.
2. Rerun the proof gates yourself before advancing to the next work order.
3. Answer the report's open questions explicitly in the next prompt, as
   numbered decisions, so the resumed session has no room to guess.

## Liveness watchdog

For long runs, watch three signals: the process, the output file's mtime, and
the latest-commit timestamp in the worktree. Alert only past roughly 10–15
minutes of true silence on all three; Grok legitimately goes quiet during
long test runs.

- `pgrep` patterns must use the bracket trick (`pgrep -f "spec-fil[e].md"`).
  Without it the watchdog matches its own command line and never exits.
- If the host session restarts, background Grok runs die silently mid-read.
  On resume, check `pgrep`, the out/err files, and `git log`/`git status` in
  the worktree before assuming anything. If the run hadn't committed,
  relaunch the same spec fresh; that is safe.
