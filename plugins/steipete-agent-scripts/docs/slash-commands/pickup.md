---
summary: 'Codex pickup checklist when starting on a task.'
read_when:
  - Creating a /pickup prompt or onboarding a new task.
---
# /pickup

Purpose: rehydrate context quickly when you start work.

Steps:
1) Read AGENTS.MD pointer + relevant docs (run `pnpm run docs:list` if present).
2) Repo state: `git status -sb`; check for local commits; confirm current branch/PR.
3) CI/PR: `gh pr view <num> --comments --files` (or derive PR from branch) and note failing checks.
4) tmux/processes: list sessions and attach if needed:
   - `tmux list-sessions`
   - If sessions exist: `tmux attach -t codex-shell` or `tmux capture-pane -p -J -t codex-shell:0.0 -S -200`
5) Tests/checks: note what last ran (from handoff notes/CI) and what you will run first.
6) Plan next 2–3 actions as bullets and execute.

Output format: concise bullet summary; include copy/paste tmux attach/capture commands when live sessions are present.

Location: global prompt lives in `~/.codex/prompts/pickup.md`; this file mirrors it for easy edits.
