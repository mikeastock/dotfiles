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

Write only the context that `/code-review` cannot infer from the checkout to a
temporary run directory:

```text
/code-review

Scope: <merge-base>...HEAD
Dirty changes: <explicit files, or none>
Goal: <what the change must accomplish>
Constraints: <material invariants>
Verification: <commands and results, or not run>

Review only. Do not edit, publish, mutate external state, spawn subagents, or
start background commands.
```

Keep secrets, credentials, tokens, and private keys out of the prompt and
artifacts.

## Run one review

The bundled `scripts/run_review.sh` owns the security-critical launcher and
result parser. Use it instead of retyping Grok commands so version checks,
native-skill checks, session identity, zmx failures, sandbox verification, and
JSON validation stay in one executable contract. The launcher supports exactly
Grok `0.2.99`, passes the prompt with `--prompt-file`, disables plan mode,
memory, web search, edit/write tools, and MCP calls, and requests `--sandbox
read-only` without auto-approving shell commands. It leaves Grok's default
read/search/list/shell/background machinery intact because `0.2.99` cannot
construct `run_terminal_cmd` when `--tools`, `--no-subagents`, or a disallowed
`Agent` disables its shared background support.

Create a unique run directory and write the task-specific prompt before
starting the launcher:

```bash
REPO="$(git rev-parse --show-toplevel)"
SESSION="grok-review-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${TMPDIR:-/tmp}/$SESSION"
PROMPT="$RUN_DIR/prompt.md"
mkdir -p "$RUN_DIR"

# Write the task-specific prompt to "$PROMPT" first.
"<path-to-this-skill>/scripts/run_review.sh" start "$REPO" "$PROMPT" "$RUN_DIR"
```

The launcher records both the zmx session and a preassigned Grok session UUID,
and holds one atomic lock per repository while the process is alive. It rejects
the run unless Grok reports a matching `ProfileApplied` event with
`profile=read-only`, `workspace=$REPO`, and `enforced=true` in
`~/.grok/sandbox-events.jsonl`. It stops the zmx session on `ApplyFailed`, a
missing event, or a zmx startup error. Do not start a second review while the
first session is active. Do not use `--worktree`, because the reviewer must
inspect the already-scoped checkout. Do not replace `read-only` with a writable
sandbox profile.

The lock records its owning zmx session. A later run replaces it only when zmx
proves that session is no longer active. If a lock has no owner, or termination
cannot be verified after a sandbox failure, the launcher retains the lock and
reports its path for manual investigation.

## Observe and recover

Keep the result out of the main context while the review is running:

```bash
tail -n 20 "$RUN_DIR/result.json"
tail -n 20 "$RUN_DIR/stderr.log"
tail -n 20 "$RUN_DIR/zmx-start.log"
zmx list --short
```

Wait for the recorded session and validate the result when it finishes:

```bash
"<path-to-this-skill>/scripts/run_review.sh" wait "$RUN_DIR"
```

The wrapper requires one valid JSON object with non-empty `text`, `sessionId`,
and `requestId`, exact `stopReason=EndTurn`, and the preassigned session ID. It
writes the validated review text to `review.md`. Read `review.md` for triage;
retain `result.json` as the authoritative raw response and usage record.

If the session is quiet, inspect `zmx list`, the result tail, and stderr before
acting. If it exceeds the caller's approved wall-clock bound, stop the session
and report an incomplete review. Preserve the prompt, raw result, stderr, and
session ids; do not automatically retry or fall back.

Resume only when the user explicitly asks to continue that same review. Write
a new prompt that asks Grok to finish and return the complete review, use a
fresh run directory, and pass the recorded Grok UUID:

```bash
OLD_RUN_DIR="<original-run-directory>"
RECOVERY_RUN_DIR="${OLD_RUN_DIR}-resume-$(date -u +%Y%m%dT%H%M%SZ)"
RECOVERY_PROMPT="$RECOVERY_RUN_DIR/prompt.md"
mkdir -p "$RECOVERY_RUN_DIR"

# Write the recovery prompt to "$RECOVERY_PROMPT" first.
"<path-to-this-skill>/scripts/run_review.sh" resume \
  "$REPO" "$RECOVERY_PROMPT" "$RECOVERY_RUN_DIR" \
  "$(<"$OLD_RUN_DIR/grok-session")"
```

Grok `0.2.99` fixes a session's sandbox profile for its lifetime. The wrapper
passes the same `read-only` profile on resume so a recovery cannot widen it.

## Read and validate the result

After the wrapper validates completion, inspect `review.md` and confirm:

- the review text is non-empty and contains findings or an explicit no-findings
  statement;
- the output is for the recorded scope and not a stale resumed session.

The wrapper already rejects malformed JSON, missing fields, blank text,
nonterminal stop reasons, turn exhaustion, and mismatched sessions. Treat
interruption, timeout, unavailable Grok, or review text that does not address the
recorded scope as a failed review. Report the exact run directory and failure;
never present partial output as a completed review.

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
  `read-only` sandbox. It rejects a run if Grok reports `ApplyFailed`, no
  matching `ProfileApplied`, or `enforced=false` and serializes wrapper runs per
  workspace so their events cannot be confused. Rejection includes verified
  zmx termination; if termination remains visible, the lock stays in place.
- Grok `0.2.99` documents a residual startup race for built-in profiles: if OS
  enforcement fails, Grok can continue briefly while the wrapper observes the
  failure and kills it. The launcher removes mutating/external built-in tools,
  denies edit/write/MCP tools, and does not use `--always-approve` to reduce that
  exposure. A custom profile would refuse natively, but requires persistent
  Grok configuration this skill does not own. Do not treat a rejected run or
  partial artifact as a review.
- The sandbox intentionally permits Grok session/config writes under
  `~/.grok/` and temporary run artifacts. The launcher removes edit, write,
  web and MCP operations through a combination of
  `--disallowed-tools`, `--deny`, and dedicated disabling flags. Shell commands
  and Grok's agent/background machinery remain available for code inspection
  because `0.2.99` couples them at agent construction; the prompt prohibits
  using subagents or background commands. On Linux, the sandbox blocks
  child-process network access; on macOS, Grok `0.2.99` documents child-network
  restriction as a no-op.
- Detached Linux runs can report `ApplyFailed` when Landlock cannot open
  `/dev/tty`. Preserve the artifacts and report the failure. Never retry by
  dropping the sandbox.
- The review prompt remains a soft policy against editing, deleting, resetting,
  stashing, committing, pushing, merging, commenting on GitHub, deploying,
  installing, changing configuration, or mutating external state. On macOS in
  particular, do not overstate the sandbox as an external-state guarantee.
- Use one canonical path: this wrapper invokes Grok's native `/code-review`.
  Do not add a fallback reviewer or a second review mode.
- Keep historical designs and prior review artifacts immutable.
- If implementation is later requested, create a clean external worktree and
  focused branch before editing.
