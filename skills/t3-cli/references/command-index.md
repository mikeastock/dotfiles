# t3 command index

Generated from `t3 --help` for t3 v0.1.7-nightly.20261101.4035. Every command also accepts `--base-dir <dir>` (same as `T3CODE_HOME`) and `--log-level`. Run `t3 <command> --help` for current flags and defaults.


## serve

- `t3 serve [flags] [<cwd>]` — Run T3 Code in this terminal without opening a browser, and print pairing details. The background service runs this. To set up access from your other devices, run `t3 up`.

## app

- `t3 app [flags] [<path>]` — Open a project in the running T3 Code desktop app.

## pair

- `t3 pair [flags]` — Mint a pairing token for a running T3 Code server and print it as a QR code.

## auth

- `t3 auth <subcommand> [flags]` — Manage the local auth control plane for headless deployments.
- `t3 auth pairing <subcommand> [flags]` — Manage one-time client pairing tokens.
- `t3 auth pairing create [flags]` — Issue a new client pairing token.
- `t3 auth pairing list [flags]` — List active client pairing tokens without revealing their secrets.
- `t3 auth pairing revoke [flags] <id>` — Revoke an active client pairing token.
- `t3 auth session <subcommand> [flags]` — Manage bearer sessions.
- `t3 auth session issue [flags]` — Issue a scoped bearer access token for headless or remote clients.
- `t3 auth session list [flags]` — List active sessions without revealing bearer tokens.
- `t3 auth session revoke [flags] <session-id>` — Revoke an active session.

## environment

- `t3 environment <subcommand> [flags]` — Link other T3 Code environments, so agents here can work there.
- `t3 environment link [flags] <url>` — Link another T3 Code environment, so agents here can work there. It shows up there under Settings → Connections, where it can be revoked.
- `t3 environment list [flags]` — List linked environments and whether each answers now.
- `t3 environment unlink [flags] <environment-id>` — Forget a linked environment here. Revoke it in that environment's Connections to end its session there too.

## browser

- `t3 browser <subcommand> [flags]` — Manage T3's headless browser on this host.
- `t3 browser setup [flags]` — Set up this Linux host for T3's browser: allow Chrome's sandbox and install its libraries and fonts.

## project

- `t3 project <subcommand> [flags]` — Manage projects.
- `t3 project add [flags] <path>` — Add a project.
- `t3 project remove [flags] <project>` — Remove a project.
- `t3 project rename [flags] <project> <title>` — Rename a project.

## thread

- `t3 thread <subcommand> [flags]` — Start, message, and read threads on the running server.
- `t3 thread list [flags]` — List a project's threads, newest first.
- `t3 thread start [flags] <project> <message>` — Start a thread in a project and print its id.
- `t3 thread send [flags] <thread> <message>` — Send a message to a thread. A busy thread gets it as its next turn; nothing is interrupted.
- `t3 thread show [flags] <thread>` — Show a thread's state and its latest messages.

## up

- `t3 up [flags]` — Set up remote access and the T3 Code background service. Access flags skip the question, and routes not named keep their settings. Without a terminal, a needed restart runs without asking and stops running agent turns.

## status

- `t3 status [flags]` — Show service setup and remote access settings.

## service

- `t3 service <subcommand> [flags]` — Manage the T3 Code background service.
- `t3 service install [flags]` — Install T3 Code as a background service for this user. `t3 up` also chooses how your other devices reach it.
- `t3 service restart [flags]` — Restart the background service. Picks up a version installed by `t3 update` that was not restarted at the time.
- `t3 service uninstall [flags]` — Stop and remove the T3 Code background service.
- `t3 service status [flags]` — Show whether the T3 Code background service is installed.
- `t3 service protect [flags]` — Protect the T3 Code server from agents under memory pressure (Linux with systemd). Asks for sudo.

## update

- `t3 update [flags] [<version>]` — Download a newer t3 and switch this machine to it, including the background service when one is installed.

## uninstall

- `t3 uninstall [flags]` — Remove t3 from this machine: the background service, the launcher, and every downloaded version. Your projects and threads are kept.

## theme

- `t3 theme <subcommand> [flags]` — Inspect and set environment-wide theme defaults.
- `t3 theme set [flags] <theme>` — Set the environment's theme; connected clients switch to it.
- `t3 theme clear [flags]` — Remove the environment's theme; clients keep what they have.
- `t3 theme show [flags]` — Show the environment's theme and its published themes.

## trace

- `t3 trace <subcommand> [flags]` — Inspect the local server trace file.
- `t3 trace summary [flags]` — Summarize the local server trace file: counts, rates, and latency.

## doctor

- `t3 doctor [flags]` — Inspect this T3 Code data directory and repair it. Pauses and restarts the background service as needed.

## triage

- `t3 triage [flags]` — Investigate a T3 Code problem on this machine with claude or codex, and help file a good issue.

## connect

- `t3 connect <subcommand> [flags]` — Set up T3 Connect for this machine. Same as `t3 up --connect`.
- `t3 connect login [flags]` — Authorize the T3 Connect CLI without enabling remote access.
- `t3 connect link [flags]` — Authorize this environment for T3 Connect on next start.
- `t3 connect publish [flags]` — Toggle publishing agent activity (push notifications and Live Activities) to your mobile clients.
- `t3 connect status [flags]` — Show T3 Connect setup and check that other devices can reach this machine.
- `t3 connect unlink [flags]` — Disable T3 Connect while retaining the stored authorization.
- `t3 connect logout [flags]` — Disable T3 Connect and clear the stored CLI authorization.

## Bare `t3`

- `t3 [flags] [<cwd>]` — Run T3 Code in this terminal and open it in the browser. On a host with the background service, use `t3 serve` or the service instead.

## Server MCP tools (not exposed as CLI commands)

Reachable at `<origin>/mcp` as the `t3-code` server for agents T3 starts, or after `claude mcp add` / `codex mcp add` plus `mcp login` for outside agents. Thread tools: `t3_thread_launch`, `t3_thread_list`, `t3_thread_read`, `t3_thread_search`, `t3_thread_send`, `t3_thread_send_attachments`, `t3_thread_wait`, `t3_thread_interrupt`, `t3_thread_update` (rename, regenerate title, link pull requests), `t3_thread_organize`, `t3_thread_configure`, `t3_thread_transfer`. Project tools: `t3_project_list`, `t3_project_read`, `t3_project_create`, `t3_project_update`, `t3_project_delete`, `t3_project_clone`. Delegation: `delegate_task`, `task_status`, `task_cancel`, `create_threads`. See `docs/orchestration-v2/orchestrator-mcp-server.md` in the t3code repo for inputs and results.
