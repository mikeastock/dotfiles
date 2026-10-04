# pstack for Pi

A Pi port of poteto's [pstack](https://github.com/cursor/plugins/tree/e43c7ee/pstack) (v0.15.9, `cursor/plugins` commit `e43c7ee`, MIT, see `LICENSE.pstack`). The skills live in this repo's `skills/` directory (`poteto-mode`, the 24 `principle-*` skills, `how`, `why`, `arena`, `swarm`, `interrogate`, and the rest). This extension supplies the runtime pieces that Cursor provides natively.

| Cursor | Pi (this extension) |
|---|---|
| `Task` tool, `subagent_type`, `model`, `run_in_background` | `task` tool: `agent`, `model`, `readonly`, `cwd`, `background` |
| Background agent status in the dashboard | `task_status` tool: list running background tasks, `stop` by id, or `wait` for ids and get their reports inline |
| `TodoWrite` | `todo_write` tool, with a widget above the editor |
| Sticky `/poteto-mode` with a per-turn reminder | `/poteto-mode [task]`, `/poteto-mode off`, `/poteto-mode status`. Running `/skill:poteto-mode` also turns it on. |
| `~/.cursor/rules/pstack-models.mdc` | `~/.pi/agent/pstack-models.md`, written by `/skill:setup-pstack` and injected into every session |
| `agent-transcripts/` path in the system prompt | `pstack_session` system prompt section naming the session file and directory |

## Subagents

Each `task` entry runs `pi --mode json -p` as a child process with its own context.
- `agent` picks a bundled system prompt: `general` (none), `poteto-agent` (the installed poteto-mode skill, inlined), or `comment-sicko` (the no-comments reviewer, which cannot delegate).
- `model` takes `provider/id:thinking`. Omit it, or pass `inherit-parent` or `auto`, to use the parent's model and thinking level.
- `readonly` removes the `edit` and `write` tools, keeps MCP access, and makes every subagent the child spawns read-only too. It is not a sandbox: `bash` and other tools can still write.

A call runs up to 12 subagents, 6 at a time; background tasks share one pool of 6 across calls. Subagents can spawn one more level, no deeper, and children at the limit do not get the `task` tools. A call whose every task fails returns an error result.

Each child leads its own process group. Aborting a task, stopping it with `task_status`, or ending the session kills the group, so a child's own subagents die with it.

## Background reports

With `background: true` the call returns at once and each report is delivered without being lost (`courier.ts`):
- While a run is active, the report is steered in at the next tool boundary. A steer that Esc drops is attached to your next message instead of waking the session.
- While idle, the report wakes the session as a user message, so `before_agent_start` keeps the pstack prompt sections. If your own prompt starts first, the reports are steered into that run.
- During a manual compaction, reports wait until the session is idle again.

Reports start with `[pstack background report]` and say they are subagent output, not user instructions. `task_status` with `wait` collects reports inline instead, and lists reports that finished but have not reached the model yet. Background needs an interactive top-level session, so subagents and print mode run in the foreground.

## Transcripts

Child transcripts are saved per project under `~/.pi/agent/pstack/task-sessions/--<cwd>--/`, and each report names its file, so a parent can audit what a subagent actually did. Nothing prunes them.

## Not ported

- `make-bot-ui` and the Benny automations (Cursor bot and automation infrastructure).
- pstack's `bro`, `unslop`, and `teach`: this repo already ships skills with those names.
- Cursor cloud agents and `/loop`. The playbooks use local worktrees, background `task` watchers, and `sleep` heartbeats instead.
