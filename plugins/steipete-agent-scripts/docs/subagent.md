---
summary: 'Multi-agent system directives and coordination rules. Master reference for agent behavior.'
read_when:
  - Coordinating subagents or running tmux-based agent sessions.
---

# Claude Subagent Quickstart

## CLI Basics
- Launch long-running subagents inside tmux so the session can persist. Example:

  ```bash
  tmux new-session -d -s claude-haiku 'claude --model haiku'
  tmux attach -t claude-haiku
  ```

  Once inside the session, run `/model` to confirm the active alias (`haiku` maps to Claude 3.5 Haiku) and switch models if needed.
- Need to queue instructions without attaching? Use `bun scripts/agent-send.ts --session <name> -- "your command"` to inject text into a running agent session (single Enter is sent by default).
- Always switch to the fast Haiku model upfront (`claude --model haiku --dangerously-skip-permissions …` or `/model haiku` in-session) to keep turnaround fast.
- Two modes:
  - **One-shot tasks** (single summary, short answer): run `claude --model haiku --dangerously-skip-permissions --print …` in a tmux session, wait with `sleep 30`, then read the output buffer.
  - **Interactive tasks** (multi-file edits, iterative prompts): start `claude --model haiku --dangerously-skip-permissions` in tmux, send prompts with `tmux send-keys`, and capture completed responses with `tmux capture-pane`. Expect to sleep between turns so Haiku can finish before you scrape the pane.
- Ralph’s supervisor loop launches Claude the same way (`claude --dangerously-skip-permissions "<prompt>"`) to keep the tmux automation flowing.

## One-Shot Prompts
- The CLI accepts the prompt as a trailing argument in one-shot mode. Multi-line prompts can be piped: `echo "..." | claude --print`.
- Add `--output-format json` when you need structured fields (e.g., summary + bullets) for post-processing.
- Keep prompts explicit about reading full files: “Read docs/example.md in full and produce a 2–3 sentence summary covering all sections.”

## Bulk Markdown Conversion
- Produce the markdown inventory first (`pnpm run docs:list`) and feed batches of filenames to your Claude session.
- For each batch, issue a single instruction like “Rewrite these files with YAML front matter summaries, keep all other content verbatim.” Haiku can loop over multi-file edits when you provide the explicit list.
- After Claude reports success, diff each file locally (`git diff docs/<file>.md`) before moving to the next batch.

## Ralph Integration Notes
- Ralph (see `scripts/ralph.ts`) spins up tmux sessions, auto-wakes the worker, and calls Claude as the supervisor via `claude --dangerously-skip-permissions`.
- Supervisor responses must end with either `CONTINUE`, `SEND: <message>`, or `RESTART`; Ralph parses these tokens to decide the next action.
- To start Ralph manually: `bun scripts/ralph.ts start --goal "…" [--markdown path]`. Progress is tracked in `.ralph/progress.md` by default.
- Send ad-hoc instructions to the worker session with `bun scripts/ralph.ts send-to-worker -- "your guidance"`.
