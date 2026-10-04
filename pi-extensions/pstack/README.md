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

Each `task` entry runs `pi --mode json -p` as a child process with its own context. `agent` picks a bundled system prompt: `general` (none), `poteto-agent` (reads `~/.agents/skills/poteto-mode/SKILL.md` first), or `comment-sicko` (the no-comments reviewer). `model` takes `provider/id:thinking`; omit it, or pass `inherit-parent` or `auto`, to use the parent's model and thinking level. `readonly` removes the `edit` and `write` tools, keeps MCP access, and makes every subagent the child spawns read-only too. It does not sandbox `bash`, so a read-only child can still write files through the shell. `poteto-agent` gets the installed poteto-mode skill inlined into its system prompt.

A call runs up to 12 subagents, 6 at a time. In the foreground it blocks until all finish. With `background: true` it returns at once and each report arrives later as its own message: at the next tool boundary when the session is busy, or as a new turn when it is idle. `task_status` with `wait` collects reports inline instead. Background needs an interactive top-level session, so subagents and print mode fall back to the foreground. Subagents can spawn one more level of subagents, no deeper: children at the limit do not get the `task` tools. A call whose every task fails returns an error result.

Child transcripts are saved under `~/.pi/agent/pstack/task-sessions/`, and each report names its file, so a parent can audit what a subagent actually did.

## Not ported

- `make-bot-ui` and the Benny automations (Cursor bot and automation infrastructure).
- pstack's `bro`, `unslop`, and `teach`: this repo already ships skills with those names.
- Cursor cloud agents and `/loop`. The playbooks use local worktrees, background `task` watchers, and `sleep` heartbeats instead.
