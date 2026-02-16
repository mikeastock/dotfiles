---
summary: 'Index of slash commands (prompts) and where they live.'
read_when:
  - Auditing or updating slash command docs.
---
# Slash Commands

Slash commands are reusable prompt templates that live in `~/.codex/prompts/` (global) and, when present, in repo-local folders (e.g., `.claude/commands/`, `.cursor/commands/`). This folder mirrors the global set so agents can discover and edit them in-repo.

## Available commands
- `/acceptpr` — Land one PR end-to-end (changelog + thanks, lint, merge, back to main).
- `/fixissue` — Fix an issue end-to-end (tests, changelog, commit, push, comment, close).
- `/handoff` — Capture current state for the next agent (running sessions, tmux targets, blockers, next steps).
- `/landpr` — Land PR via temp-branch rebase + full gate (`pnpm lint && pnpm build && pnpm test`) before commit; merge via `gh pr merge` (rebase/squash) and verify GitHub state = `MERGED` (never `CLOSED`).
- `/pickup` — Rehydrate context when starting work (status, tmux sessions, CI/PR state).
- `/raise` — If changelog is released, open next patch `Unreleased` section (commit + push `CHANGELOG.md`).

See the individual files in this directory for details.
