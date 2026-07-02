---
name: fable-review
description: Use Claude Code non-interactively with claude-fable-5 as a trusted, high-authority code reviewer. Use when the user asks for a Fable review, Claude Fable review, external review with claude -p, or a stronger reviewer focused on implementation risks, regressions, and missing tests.
---

# Fable Review

Use `claude -p` with `claude-fable-5` as a trusted senior reviewer. Assume
Fable is likely to reason better than the current model on subtle correctness,
architecture, and regression risks. Write the review prompt yourself from the
current task, changed files, and known risks; do not ask Fable to infer the
review brief from a raw diff dump alone.

Treat Fable's output as high-signal review, not casual advice. Start from the
assumption that Fable may be seeing something important you missed. Verify
actionable findings against the repo before changing code or reporting them as
true, but do not dismiss them just because they are inconvenient or surprising.

## Workflow

1. Identify the review scope from the user request, current branch, PR, or diff.
2. Inspect enough local context to write a focused prompt:
   - `git status --short`
   - `git diff --stat <base>...HEAD` or the user-specified range
   - targeted reads of changed files, tests, and nearby contracts
3. Write a concise prompt that includes:
   - project and stack context that Fable needs
   - the exact review target, such as branch, PR, commit range, or files
   - the intended behavior and constraints from the user
   - relevant verification already run and any failures
   - the output format: findings first, severity, file/line references, and no praise-only summary
4. Run Claude in print mode with Fable, stream JSON output, Read, and full
   Bash access.
5. Triage the response:
   - take each finding seriously and inspect the relevant code path
   - prefer Fable's judgment when the issue is plausible and your local reading is inconclusive
   - discard a finding only when the code, requirements, or tests clearly disprove it
   - fix confirmed issues when the user asked for implementation
   - summarize unresolved Fable concerns separately instead of flattening them into your own conclusion

## Command Pattern

Expect Fable reviews to take a long time; 10+ minutes is not uncommon. Be
patient: let the command run until it returns, and do not cancel or retry just
because it appears quiet.

Write the prompt to a temporary file, then pass it through stdin. In print mode,
this Claude CLI expects prompt input on stdin; do not pass the prompt as a
positional shell argument.

Write stream JSON to a file instead of letting it fill the calling agent's
context. Start the review with `zmx` as a detached background job, then tail or
sample the JSONL file when you want progress.

Prefer this shape from the repo root:

```bash
SESSION="fable-review-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${TMPDIR:-/tmp}/$SESSION"
mkdir -p "$RUN_DIR"
PROMPT="$RUN_DIR/prompt.md"
STREAM="$RUN_DIR/stream.jsonl"
ERR="$RUN_DIR/stderr.log"

# Write the review prompt to "$PROMPT" before starting Claude.
CLAUDE_CMD="claude -p \
  --model claude-fable-5 \
  --output-format stream-json \
  --include-partial-messages \
  --include-hook-events \
  --tools 'Read,Bash' \
  --allowedTools 'Read,Bash' \
  < '$PROMPT' > '$STREAM' 2> '$ERR'"
zmx run "$SESSION" -d bash -lc "$CLAUDE_CMD" >/dev/null 2>&1
printf '%s\n' "$SESSION" > "$RUN_DIR/zmx-session"
printf 'Fable review started in %s\n' "$RUN_DIR"
```

Use `--tools "Read"` when shell access is unnecessary. Add `--add-dir <path>`
only when the review requires files outside the current working directory.

Check progress without loading the full stream:

```bash
tail -n 20 "$STREAM"
zmx list --short
tail -n 20 "$ERR"
```

When the run finishes, read only the final result event first:

```bash
zmx wait "$(cat "$RUN_DIR/zmx-session")"
rg -n '"type":"result"' "$STREAM" | tail -n 1
```

If the installed Claude CLI behaves unexpectedly, first probe with:

```bash
printf '%s\n' "Reply ok." \
  | claude -p --model claude-fable-5 --output-format stream-json --tools "" \
  > /tmp/fable-review-probe.jsonl
```

## Prompt Template

Write a task-specific prompt; adapt this template rather than using it
unchanged:

```text
You are the trusted senior reviewer for this change. The calling model expects
your judgment to be sharper than its own, especially on subtle correctness,
architecture, regression, security, data integrity, and missing-test risks.
Ignore style-only nits unless they hide a real maintainability risk.

Review target:
- Base/range: <base>...HEAD
- Changed areas: <files or modules>
- User goal: <what the change is supposed to accomplish>

Important repo context:
- <stack, frameworks, architecture boundaries, commands>
- <non-obvious invariants or compatibility policy>

Verification already run:
- <commands and results, or "not run yet">

Please inspect the repo with the available Read and Bash tools. Be direct and
skeptical. Return only:
1. Findings, ordered by severity, with file/line references where possible.
2. Missing tests or verification gaps.
3. Questions only if they block judging correctness.

Do not provide a general summary unless there are no findings.
```

## Review Discipline

- Keep the prompt narrower than "review the whole repo".
- Position Fable as the reviewer whose judgment should challenge yours, not as
  a rubber stamp.
- Avoid pasting huge diffs when Fable has `Read` and `Bash`; point it to the
  range and files instead.
- Do not grant edit tools for review-only work.
- Do not use `--dangerously-skip-permissions` for normal reviews.
- Grant full Bash intentionally so Fable can inspect the repo without command
  allowlist friction.
- Preserve secrets: do not paste `.env`, credentials, tokens, or private keys
  into the prompt.
