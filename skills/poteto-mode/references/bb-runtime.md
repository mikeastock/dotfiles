# Running poteto-mode on bb

The bundled playbooks and skills were written for Cursor. On bb, read every Cursor term through this file. Where this file and a bundled file disagree, this file wins.

`<skill>` below is the directory that holds poteto-mode's `SKILL.md`. Use its absolute path.

## Spawning subagents

Cursor's `Task` tool is `<skill>/scripts/bb-task spawn`. Each spawn is a bb child thread parented to this thread. Archiving this thread archives its children.

| Cursor `Task` field | bb |
|---|---|
| `subagent_type: "poteto-agent"` | `--agent poteto-agent` (the default) |
| `subagent_type: "comment-sicko"` | `--agent comment-sicko` |
| `subagent_type: generalPurpose` | `--agent none` |
| `readonly: true` | `--readonly`. bb has no read-only sandbox, so the brief forbids writes and you check `git status` after the child returns. The child shares this workspace and sees uncommitted changes. |
| `readonly: false`, agent mode | Omit `--readonly`. MCP tools stay available either way. |
| `model` | `--model <slug>`, see Models |
| `run_in_background: true` | Always true. `spawn` prints the child thread ID and returns. |
| `environment: "local"` | The default. The child works in this thread's workspace. |
| `environment: "cloud"` | `--worktree`. The child gets a fresh managed worktree from the project's default branch, or from `--base-branch <ref>`. It does not see uncommitted or unpushed work. |
| Spawn all N in one message | Run every `spawn` in one shell call, collect the IDs, then run one `bb-task wait <id>...`. |
| The `Task` response body | `bb-task wait <id>...` prints each child's final reply and exits non-zero if any child failed. bb also posts a completion notice to this thread. |
| Resume, message, or queue a follow-up | `bb thread tell <id> --mode queue --message-file -`. Only in the strict reuse cases in the Subagents section. |
| Stop or hold order, cancel | `bb thread stop <id>` |
| Nested spawn | Children can run `bb-task` too. |
| Inspect a child | `bb thread show <id>`, `bb thread log <id>`, `bb thread show <id> --git-diff` |

Write long briefs to a file under `$BB_THREAD_STORAGE` and pass `--prompt-file`. Name each child with `--title` so the sidebar shows its role.

## Models

bb has no `pstack-models.mdc` rule and no `/setup-pstack`. Every role uses the default slug the skill names. `bb-task` maps slugs to bb execution settings.

| Slug | bb provider, model, reasoning level |
|---|---|
| `claude-opus-5-5-<effort>` | `pi`, `anthropic/claude-opus-5-5`, `<effort>` |
| `grok-4.7-<effort>` or `grok-4.7-<effort>-fast` | `pi`, `xai/grok-4.7`, `<effort>` (`max` becomes `xhigh`, the highest Grok level) |
| `inherit-parent`, `auto` | This thread's provider, model, and reasoning level |
| `<provider>:<model>[:<effort>]` | An explicit bb tuple. List choices with `bb provider list` and `bb provider models <provider>`. |

`composer-*` and `cursor-grok-*` belong to the Grok family. Pi has no fast service tier, so the fast or standard speed choice does not apply. Choose only the reasoning level. When bb rejects a tuple, `spawn` fails with bb's error. Apply the skill's fallback rule for a rejected slug.

## Other Cursor terms

| Cursor term | bb |
|---|---|
| `AskQuestion` | The `AskUserQuestion` tool when the harness provides it. Otherwise ask in the reply. |
| Open a todolist | Use the harness's todo tool. Without one, keep the checklist in `$BB_THREAD_STORAGE/todo.md` and update it as steps finish. |
| `create-skill` (Cursor's built-in) | bb's `skill-creator` skill |
| `deslop` from `cursor-team-kit` | The `simplify` skill on the diff. Without it, review the diff for slop yourself. |
| `control-ui` from `cursor-team-kit` | The `agent-browser` skill |
| `control-cli` from `cursor-team-kit` | The `tmux` skill |
| Cursor's `/loop` command, the loop skill | bb's `automations` skill, or a timed self-message: `bb thread tell "$BB_THREAD_ID" --mode queue --send-at 30m '<wake reason>'` |
| Cursor's built-in babysit skill | The `babysit-pr` skill. The Babysit playbook replaces it for the same requests. |
| A Cursor cloud agent (owners, verifiers) | A child thread spawned with `--worktree` |
| Cloud agent status in the Cursor dashboard | `bb thread show <id>` and `bb thread list --parent-thread "$BB_THREAD_ID"` |
| A Cursor restart | A bb server or app restart. Child threads and their history survive. |
| `agent-transcripts/`, a transcript path | `bb thread log --self --all` for this thread, `bb thread log <id> --all` for a child. Read only threads this run spawned or the user named. |
| `.cursor/skills/<name>/` (project skills) | `.bb/skills/<name>/SKILL.md` in the workspace |
| `~/.cursor/plugins/...`, `pstack/skills/poteto-mode/...` | Paths under `<skill>` |
| The `mcps/` directory, MCP list | The MCP tools the harness exposes |
| Origin CLI | Not available. Land through `gh`. |

## bb-managed worktrees

bb creates and removes worktrees for threads. Never prune a worktree under `~/.bb/` by hand in the Worktree and simulator cleanup playbook. Archive its thread instead, and bb tears the worktree down.
