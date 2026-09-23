---
name: fable-review
description: Run a code review with Claude Fable (claude-fable-5-1) through non-interactive `claude -p`, then triage its findings. Use when the user asks for a Fable review, a Claude Fable review, an external review via `claude -p`, or a stronger second reviewer for correctness, regression, and missing-test risks.
---

# Fable Review

Run `claude -p --model claude-fable-5-1` as a senior reviewer, then triage what
it finds.

**Stance:** assume Fable reasons better than you on subtle correctness,
architecture, and regression risks. Its findings are high-signal: verify each
one against the repo, but do not dismiss a finding because it is surprising or
inconvenient.

## Workflow

1. **Scope.** Identify the review target (branch, PR, commit range, or files)
   from the request. Gather context: `git status --short`,
   `git diff --stat <base>...HEAD`, and targeted reads of changed files, tests,
   and nearby contracts.
2. **Prompt.** Write a task-specific prompt from the [template](#prompt-template).
   You write the review brief; do not hand Fable a raw diff and ask it to infer
   intent.
3. **Run.** Start Claude in the background and wait for it
   ([Run](#run)). Reviews often take 10+ minutes. Do not cancel or retry a run
   that looks quiet.
4. **Triage.** For each finding:
   - Inspect the code path it names.
   - If the issue is plausible and your reading is inconclusive, defer to Fable.
   - Discard it only when code, requirements, or tests clearly disprove it.
   - Fix confirmed issues only if the user asked for implementation.
5. **Report.** List confirmed, discarded (with the reason), and unresolved
   findings separately. Do not fold unresolved Fable concerns into your own
   conclusion.

## Run

Run from the repo root. The run goes through `zmx` so it survives agent tool
timeouts. Stream JSON goes to a file, not into your context. The prompt goes in
through stdin, which avoids shell quoting problems.

```bash
SESSION="fable-review-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${TMPDIR:-/tmp}/$SESSION"
mkdir -p "$RUN_DIR"
PROMPT="$RUN_DIR/prompt.md"
STREAM="$RUN_DIR/stream.jsonl"
ERR="$RUN_DIR/stderr.log"

# Write the review prompt to "$PROMPT" before starting Claude.
CLAUDE_CMD="claude -p \
  --model claude-fable-5-1 \
  --effort high \
  --output-format stream-json \
  --verbose \
  --tools 'Read,Bash' \
  --allowedTools 'Read,Bash' \
  < '$PROMPT' > '$STREAM' 2> '$ERR'"
zmx run "$SESSION" -d bash -lc "$CLAUDE_CMD" >/dev/null 2>&1
```

Tool access:

- `Read,Bash` with no Bash allowlist lets Fable run `git`, `rg`, tests, and
  similar commands without getting blocked on permissions. Use `--tools 'Read'`
  (and matching `--allowedTools`) when it does not need a shell.
- Never grant `Edit`/`Write`, and never use `--dangerously-skip-permissions`.
- Add `--add-dir <path>` only when the review needs files outside the repo.

Check progress (recent tool calls; tolerates a partially written last line):

```bash
jq -Rr 'fromjson? | select(.type=="assistant") | .message.content[]?
  | select(.type=="tool_use") | "\(.name): \(.input | tostring | .[0:120])"' \
  "$STREAM" | tail -n 5
tail -n 20 "$ERR"
```

Wait, read the result, then clean up:

```bash
zmx wait "$SESSION"   # returns when claude exits; nonzero exit = failure
jq -Rr 'fromjson? | select(.type=="result")
  | if .is_error then "ERROR (\(.subtype))" else .result end' "$STREAM"
zmx kill "$SESSION" >/dev/null 2>&1
```

- If there is no `result` event, Claude failed. Read `$ERR`.
- Gate on `zmx wait`. Do not poll `zmx list` for the session to disappear:
  finished sessions stay listed until you kill them, so that loop never ends.

`--verbose` is required: `-p` rejects `stream-json` output without it.

If the CLI behaves unexpectedly, run a smoke test with the same output flags:

```bash
printf 'Reply ok.\n' \
  | claude -p --model claude-fable-5-1 --output-format stream-json --verbose --tools "" \
  | jq -Rr 'fromjson? | select(.type=="result") | .result'
```

## Prompt Template

Adapt this template to the task. Point Fable at the range and files instead of
pasting large diffs; it can read them itself. Keep the scope narrower than
"the whole repo". Never include `.env` contents, credentials, tokens, or
private keys.

```text
You are the trusted senior reviewer for this change. The calling model expects
your judgment to be sharper than its own, especially on subtle correctness,
architecture, regression, security, data integrity, and missing-test risks.
Challenge the change; do not rubber-stamp it. Ignore style-only nits unless
they hide a real maintainability risk.

Review target:
- Base/range: <base>...HEAD
- Changed areas: <files or modules>
- User goal: <what the change is supposed to accomplish>

Important repo context:
- <stack, frameworks, architecture boundaries, commands>
- <non-obvious invariants or compatibility policy>

Verification already run:
- <commands and results, or "not run yet">

Inspect the repo with Read and Bash. This is review-only: do not modify files,
the git state, or the environment. Be direct and skeptical. Return only:
1. Findings, ordered by severity, with file/line references where possible.
2. Missing tests or verification gaps.
3. Questions only if they block judging correctness.

Do not provide a general summary unless there are no findings.
```
