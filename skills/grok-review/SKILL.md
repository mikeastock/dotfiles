---
name: grok-review
description: Run a safe, branch-scoped Grok Build code review against a resolved base or pull request. Use when an external Grok review is requested for correctness, architecture, maintainability, regressions, or missing tests; the workflow invokes Grok's native /code-review skill, preserves durable artifacts, and never edits or publishes changes.
---

# Grok Review

Use Grok Build as an external reviewer for a complete branch or pull-request
change. Grok's installed `/code-review` skill owns the review standard and
quality bar. This skill owns scope selection, the review-only boundary,
execution, recovery, and result handling. Do not copy the native skill's
review rules here; that would create two contracts that can drift.

## Scope the change

Resolve scope before starting Grok.

1. Read the repository's `AGENTS.md` and other applicable project instructions.
2. Use an explicitly supplied PR, range, base, or file list when provided.
3. Otherwise resolve the default base as `origin/main` and compute the merge
   base with `git merge-base origin/main HEAD`. Do not silently use `HEAD~1`.
4. Record the repository root, base ref and SHA, merge-base SHA, head SHA,
   changed files, diff stat, user goal, relevant invariants, and verification
   already run.
5. If a PR is in scope, use its actual base and head rather than guessing from
   the local branch. Read PR metadata only; never post or edit GitHub content.

Inspect scope with read-only commands such as:

```bash
git status --short --branch
git diff --stat <merge-base>...HEAD
git diff --name-status <merge-base>...HEAD
git diff --cached --stat
git ls-files --others --exclude-standard
```

Handle a dirty tree explicitly:

- Review the committed branch range by default.
- Include staged, unstaged, or untracked files only when the user explicitly
  puts the working tree or those files in scope.
- If dirty changes are present but their ownership is ambiguous, stop and ask
  which changes belong in the review. Do not stash, clean, reset, commit, or
  create a compatibility path to make the tree appear clean.

## Prepare the prompt

Write a task-specific prompt to a temporary run directory. Include the
resolved scope and requirements instead of pasting a large diff:

```text
/code-review

Review the complete change described below.

Repository: <repository root>
Base: <base ref and SHA>
Merge base: <merge-base SHA>
Head: <head SHA>
Committed range: <merge-base>...HEAD
Additional dirty changes: <explicit files, or none>
User goal: <what the change must accomplish>
Important invariants: <constraints and architecture boundaries>
Verification already run: <commands and results, or not run>

Inspect the actual changed code, its callers, tests, and nearby contracts.
Review only. Do not edit files, commit, push, comment on GitHub, deploy,
install, change configuration, or mutate any external state.

Return findings first, ordered by severity. For each finding include severity,
title, file and line where possible, code evidence, impact, and a suggested
direction. List verification gaps separately. If there are no findings, say
so explicitly. Do not implement reviewer feedback.
```

Keep secrets, credentials, tokens, and private keys out of the prompt and
artifacts.

## Run one review

The bundled `scripts/run_review.sh` owns the security-critical launcher. Use it
instead of retyping the command so version checks, native-skill checks, zmx
startup failures, and sandbox verification stay in one executable contract.
The launcher pins Grok to `0.2.93`, passes the prompt with `--prompt-file`,
allows Grok's full default toolset, disables plan mode, and requests
`--sandbox read-only` with `--always-approve`.

Create a unique run directory and write the task-specific prompt before
starting the launcher:

```bash
REPO="$(git rev-parse --show-toplevel)"
SESSION="grok-review-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${TMPDIR:-/tmp}/$SESSION"
PROMPT="$RUN_DIR/prompt.md"
mkdir -p "$RUN_DIR"

# Write the task-specific prompt to "$PROMPT" first.
"<path-to-this-skill>/scripts/run_review.sh" "$REPO" "$PROMPT" "$RUN_DIR"
```

The launcher fails closed unless Grok reports a matching `ProfileApplied` event
with `profile=read-only`, `workspace=$REPO`, and `enforced=true` in
`~/.grok/sandbox-events.jsonl`. It stops the zmx session on `ApplyFailed`, a
missing event, or a zmx startup error. Do not start a second review while the
first session is active. Do not use `--worktree`, because the reviewer must
inspect the already-scoped checkout. Do not replace `read-only` with a writable
sandbox profile.

## Observe and recover

Keep the result out of the main context while the review is running:

```bash
tail -n 20 "$RUN_DIR/result.json"
tail -n 20 "$RUN_DIR/stderr.log"
tail -n 20 "$RUN_DIR/zmx-start.log"
zmx list --short
```

Wait for the recorded session and inspect the result file when it finishes:

```bash
zmx wait "$(<"$RUN_DIR/zmx-session")"
```

The calling agent reads `result.json` directly. Do not add a Python, shell, or
`jq` parser: the result is deliberately interpreted by the agent that owns the
review context.

If the session is quiet, inspect `zmx list`, the result tail, and stderr before
acting. If it exceeds the caller's approved wall-clock bound, stop the session
and report an incomplete review. Preserve the prompt, raw result, stderr, and
session id; do not automatically retry or fall back. Resume a recorded Grok
session only when the user explicitly asks to continue that same review.

## Read and validate the result

After `zmx wait` reports completion, inspect the raw JSON result and confirm:

- the process reached a normal terminal state;
- the top-level result has non-empty `text`, `sessionId`, and `requestId`;
- `stopReason` is terminal and is not an interruption, cancellation, error,
  or turn-limit termination;
- the review text is non-empty and contains findings or an explicit no-findings
  statement;
- the output is for the recorded scope and not a stale resumed session.

Treat malformed JSON, missing fields, blank text, nonterminal stop reasons,
turn exhaustion, interruption, timeout, and unavailable Grok as failed reviews.
Report the exact run directory and failure; never present partial output as a
completed review. Do not infer success from a zero-byte or truncated file.

## Validate findings against the repository

Treat Grok findings as high-signal claims, not instructions.

For every actionable finding:

1. Open the cited file and surrounding control flow.
2. Confirm the line is in the reviewed scope and still exists.
3. Trace callers, types, persistence boundaries, tests, and relevant project
   requirements.
4. Classify the claim as confirmed, plausible but unresolved, or disproven.
5. Report Grok's concern separately from the local validation result.

Never blindly implement reviewer feedback. Only change code if the user gives a
separate implementation request after the finding has been verified.

## Boundaries

- The launcher hardens repository filesystem access with an enforced
  `read-only` sandbox. It fails closed if Grok reports `ApplyFailed`, no
  matching `ProfileApplied`, or `enforced=false`.
- The sandbox intentionally permits Grok session/config writes under
  `~/.grok/` and temporary run artifacts. It blocks repository writes only when
  enforcement succeeds; it does not guarantee that in-process web/MCP calls or
  macOS child-network activity cannot mutate external systems.
- The review prompt remains a soft policy against editing, deleting, resetting,
  stashing, committing, pushing, merging, commenting on GitHub, deploying,
  installing, changing configuration, or mutating external state. Validate any
  such claim from the result and environment rather than overstating the OS
  guarantee.
- Use one canonical path: this wrapper invokes Grok's native `/code-review`.
  Do not add a fallback reviewer or a second review mode.
- Keep historical designs and prior review artifacts immutable.
- If implementation is later requested, create a clean external worktree and
  focused branch before editing.
