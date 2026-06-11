---
name: codex-session-renamer
description: Manual workflow for one-time Codex session/thread renaming based on session contents and local naming rules. Use only when the user explicitly asks for `$codex-session-renamer` or names `codex-session-renamer`; do not use for generic thread/session rename requests.
agents: [codex]
---

# Codex Session Renamer

Rename Codex threads once, based on their contents, cwd project, and merge state.

## Rules

- Use `codex-remote-tools` for all thread operations.
- Use `codex-prefix-thread-projects` only when the user wants the bulk deterministic prefix pass.
- Derive the project prefix from the thread `cwd` basename:
  - `bizops` -> `biz`
  - `bizops-infra` -> `b-inf`
  - `infrastructure` -> `m-inf`
  - `dotfiles` -> `dot`
  - `marketing` -> `mkt`
  - `release-notes` -> `rel`
  - `app` -> `a1`
  - `app2` -> `a2`
  - `app3` -> `a3`
  - `app4` -> `a4`
  - `app5` -> `a5`
  - `app6` -> `a6`
  - Otherwise use the basename itself.
- Use `<proj>: <title>` for normal sessions.
- Use `<proj>(merged): <title>` when there is strong evidence the branch/work is merged.
- Never remove `(merged)` automatically.
- Keep titles concise and content-derived. Prefer the actual deliverable or outcome over the first prompt if the session contents show a clearer result.

## Workflow

1. Scope the pass:
   - If the user names a thread id, operate only on that thread.
   - If the user asks for all/recent sessions, list with `codex-remote-tools threads list --json --all-sources`.
   - Include archived sessions only if the user asks or the pass is explicitly global.
2. Inspect contents:
   - Read each candidate with `codex-remote-tools threads read <thread-id> --turns --json`.
   - If `turns` are unavailable or the rollout is missing, skip and report the thread id.
3. Decide merge state:
   - Prefer existing `proj(merged):` names.
   - Treat old `MERGED:` markers as merged.
   - If requested, use `codex-prefix-thread-projects --detect-merged --dry-run` as supporting evidence.
   - Otherwise use only strong evidence from the thread contents, branch/PR references, or git/GitHub checks.
4. Propose changes first:
   - Show old name -> new name.
   - Keep the report short for small batches; for large batches, summarize counts and show representative examples.
5. Rename:
   - Use `codex-remote-tools threads rename <thread-id> "<new name>"`.
   - Verify with `codex-remote-tools threads read <thread-id> --json` or a fresh list.

## Safety

- Do not create prompt-backed threads.
- Do not run recurring cron changes from this skill.
- Do not rename stale rows whose rollout is missing.
- Do not infer merged state from branch deletion alone.
