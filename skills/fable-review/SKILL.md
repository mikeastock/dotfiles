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
4. Run Claude in print mode with Fable and a small tool surface.
5. Triage the response:
   - take each finding seriously and inspect the relevant code path
   - prefer Fable's judgment when the issue is plausible and your local reading is inconclusive
   - discard a finding only when the code, requirements, or tests clearly disprove it
   - fix confirmed issues when the user asked for implementation
   - summarize unresolved Fable concerns separately instead of flattening them into your own conclusion

## Command Pattern

Prefer this shape from the repo root:

```bash
claude -p \
  --model claude-fable-5 \
  --tools "Read,Bash" \
  --allowedTools "Read,Bash(git *),Bash(rg *),Bash(fd *),Bash(sed *)" \
  "$(cat /tmp/fable-review-prompt.md)"
```

Use `--tools "Read"` when shell access is unnecessary. Add `--add-dir <path>`
only when the review requires files outside the current working directory.

If the installed Claude CLI behaves unexpectedly, first probe with:

```bash
claude -p --model claude-fable-5 --tools "" "Reply ok."
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
- If Fable needs broader shell access, rerun with a more specific
  `--allowedTools` list rather than opening all tools.
- Preserve secrets: do not paste `.env`, credentials, tokens, or private keys
  into the prompt.
