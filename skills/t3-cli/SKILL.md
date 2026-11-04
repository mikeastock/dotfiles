---
name: t3-cli
description: "Inspect or manage T3 Code with the t3 CLI: start, message, and read threads; projects; pairing and auth; the background service, updates, and remote access. Use for t3 commands and T3 Code configuration on this host."
---

# T3 CLI

Use `t3` for T3 Code state and actions on the machine that runs the server.
`t3 <command> --help` is the reference for flags and defaults; this skill says
where to look and how to use t3 well. references/command-index.md lists every
command path with a one-line summary.

## Start with context

```sh
t3 --version
t3 status --json            # service installed?, version, T3 Connect, LAN
t3 service status
t3 thread list --json       # threads of the project containing this folder
```

- `t3` is a symlink in `~/.local/bin` to the active version under
  `$T3CODE_HOME/runtime/versions/<version>/t3` (default `~/.t3`).
- `t3 service install` runs the server as a background service (on Linux, the
  `t3code.service` systemd user unit). Its active version lives in
  `~/.t3/runtime/service-state.json`.
- `t3 thread` commands talk to the running server. If it is down they fail with
  a "not running" error; check `t3 service status` before anything else.

## Find the command

| Task                                                              | Command                                   |
| ----------------------------------------------------------------- | ----------------------------------------- |
| Start a thread, optionally in a new worktree or with a model       | `t3 thread start`                         |
| Send a follow-up turn to a thread                                  | `t3 thread send`                          |
| Read a thread's state and latest messages                          | `t3 thread show`                          |
| List a project's threads, newest first                             | `t3 thread list`                          |
| Add, rename, or remove a project                                   | `t3 project add/rename/remove`            |
| Pairing code / QR for a phone, browser, or another machine         | `t3 pair` or `t3 auth pairing create`     |
| List or revoke pairing codes and sessions; issue a bearer token    | `t3 auth pairing ...`, `t3 auth session ...` |
| Remote access (T3 Connect, LAN/tailnet) and service setup          | `t3 up`, `t3 connect ...`                 |
| Let agents here work in another T3 environment                     | `t3 environment link/list/unlink`         |
| Install, restart, or remove the background service                 | `t3 service ...`                          |
| Update t3 and the service                                          | `t3 update`                               |
| Diagnose or repair the data directory                              | `t3 doctor --dry-run`, then `t3 doctor`   |
| Server latency and request rates                                   | `t3 trace summary --since 30m`            |
| Environment-wide theme                                             | `t3 theme show/set/clear`                 |
| Linux deps for T3's headless browser                               | `t3 browser setup`                        |
| Investigate a T3 bug and draft an issue                            | `t3 triage`                               |

Not in the CLI: listing projects, searching thread text, renaming, pinning,
interrupting, or archiving threads. Those are tools on the server's MCP
endpoint (`t3_project_list`, `t3_thread_search`, `t3_thread_update`,
`t3_thread_organize`, `t3_thread_interrupt`, ...). Agents that T3 starts get
them automatically as the `t3-code` MCP server. Outside agents connect with
`claude mcp add --transport http t3 <origin>/mcp` or
`codex mcp add t3 --url <origin>/mcp`, then `mcp login`, approving with a code
from `t3 auth pairing create`. The source docs are
`docs/user/outside-agents.md` and `docs/orchestration-v2/orchestrator-mcp-server.md`
in the t3code repo (https://github.com/pingdotgg/t3code).

## Command habits

- A project argument is a project id or any path inside the project folder;
  `.` means the project containing the current directory, and the deepest
  matching project wins. There is no `t3 project list`; get project ids from
  `t3 thread list --json` (`projectId`) run inside the project.
- Thread ids look like `mcp:<uuid>` or `mcp:launch:<hash>`. Quote them and copy
  them exactly from `list` or `start` output.
- Use `--json` when output drives later work. Errors go to stderr with exit 1
  and stdout stays empty, so parse stdout only and check the exit code.
- Pass long or multi-line messages on stdin with `-` as the message, from a
  file or quoted heredoc. Inside double quotes the shell expands backticks and
  `$(...)` before t3 sees the text.

  ```sh
  t3 thread start . - --title "Fix flaky export test" <<'EOF'
  ...prompt...
  EOF
  ```

- Prefer non-interactive commands. `t3 update`, `t3 uninstall`, and
  `t3 up` prompt in a terminal; pass `--yes` only after the user confirmed.
- Read the whole error before reaching for `--help`; it usually names the bad
  argument.

## Working with threads

- `t3 thread start <project> <message>` prints the new thread id (or, with
  `--json`, the launch result including `threadId` and `runId`). A new thread
  uses the project's default model and permission mode and runs in the project
  folder.
- `--worktree <base-ref>` runs it in a new git worktree based on that branch,
  tag, or commit; add `--branch <name>` to name the branch. `--provider` and
  `--model` must be passed together (for example `--provider claudeAgent
  --model claude-opus-5-5`; copy real values from `t3 thread list --json`).
- Give each thread one clear task: objective, constraints, expected
  deliverable, validation to run, and what to report back.
- `t3 thread send` never interrupts. A busy thread gets the message as its next
  turn and the command prints `Queued.`; that is not a failure, do not resend.
- `--wait` on `start` or `send` blocks until that run ends, with no timeout,
  and prints the agent's final reply. Exit 0 completed, 1 failed or stopped,
  2 waiting for an answer the user must give in the app. With `--json` it
  always prints `{threadId, runId, status, reply, error}`, even on failure.
  Give the shell call a long timeout, or start without `--wait` and check later.
- Do not poll with sleep loops. Use `--wait` when you must block; otherwise
  check once with `t3 thread show <id> --json` (`thread.status`,
  `activeRunId`, `pendingRequestCount`, `branch`, `worktreePath`,
  `pullRequests`) and `--messages <n>` for recent turns.
- Before following up on a failed or stopped thread, read
  `t3 thread show <id> --messages 5`. Treat a thread the user stopped as
  intentionally stopped unless they ask you to continue.
- Threads started from the CLI show `createdBy: agent` and appear in the app
  like any other thread; share the `link` field when the user wants to open it.

## Safety

- `t3 update --yes`, `t3 service restart`, `t3 up --yes`, and `t3 doctor`
  restart the server and stop every running agent turn, terminal, and remote
  client. Check for running threads first and confirm with the user.
- `t3 project remove --force` deletes the project and all of its threads.
  `t3 uninstall` removes the service, launcher, and every downloaded version.
  Never run either without explicit confirmation in this conversation.
- Pairing codes and bearer tokens grant access to this machine. `t3 pair` and
  `t3 auth pairing create` default to every scope (including terminal and
  filesystem write); narrow with repeated `--scope` and keep `--ttl` short.
  Show a code only to the user who asked for it; never write tokens to files,
  commits, or logs. Revoke strays with `t3 auth pairing list` / `revoke`.
- `t3 pair --tailscale` persists a Tailscale Serve mapping on the HTTPS port;
  remove it with `tailscale serve --https=<port> off` if it was not wanted.
- Keep secrets out of thread messages; they are stored in the thread history.

## Common checks

```sh
t3 status --json
t3 service status
systemctl --user status t3code.service --no-pager   # Linux
t3 thread list --project <path-or-id> --json
t3 thread show '<thread-id>' --messages 3 --json
t3 auth pairing list --json
t3 auth session list --json
t3 environment list --json
t3 connect status --json
t3 doctor --dry-run
t3 trace summary --since 30m
```

## Completion

Confirm the command result and the affected thread, project, or service.
Report the thread id and `link`, the pairing URL and its expiry, or the
version now running, whichever the user needs next.
