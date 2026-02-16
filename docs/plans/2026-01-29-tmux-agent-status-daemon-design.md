# tmux-agent-status Go Daemon Design (JSON-RPC)

Date: 2026-01-29

## Overview

We will replace the current bash/python scripts with a single Go binary that runs a Unix socket daemon and exposes JSON-RPC over NDJSON. Agents (Pi extension and Codex bridge) register over a socket connection and send state updates. The daemon holds all state in memory and removes agents immediately when their socket disconnects. The tmux status command connects, queries status, renders the string, and exits. This is a big-bang migration; backwards compatibility with the JSON file is not required.

## Goals

- Fast, dependency-free status rendering (no jq, no python).
- Accurate multi-agent tracking per tmux session.
- Immediate cleanup on agent exit (no PID polling).
- Simple, debuggable protocol (JSON-RPC over NDJSON).

## Non-Goals

- Backwards compatibility with the legacy JSON state file.
- Full “push” updates to tmux (can be a future enhancement).
- Persisting state across daemon restarts.

## Architecture

**Binary:** `agent-status` with subcommands. The daemon listens on `~/.config/agents/agent-status.sock` and maintains an in-memory registry keyed by connection ID. Agents are registered to their tmux session/pane and agent type. The status command queries the daemon, aggregates by session, and renders tmux formatting.

**Connection = liveness:** when a client disconnects, the daemon removes its state immediately. This replaces PID-based cleanup.

## JSON-RPC Protocol (NDJSON)

Transport: one JSON-RPC object per line. Requests needing responses include `id`; fire-and-forget updates omit `id`.

- `register {session, pane, agent, state?}` → `{agent_id}`
- `update {state}`
- `unregister {}`
- `status {}` → `{sessions:[{name, agents:[...]}]}`
- `ping {}` → `{pong}`

Errors use standard JSON-RPC error codes.

## Data Flow

**Pi:** extension opens a socket on startup, sends `register`, then `update` on state transitions, and closes on shutdown.

**Codex:** Codex invokes a notify hook once per completed turn, passing JSON as argv. A bridge subcommand (`agent-status notify <json>`) parses the payload and sends `update state=waiting` to the daemon. Codex is one-shot; it will not hold a connection.

**tmux:** status bar executes `agent-status status`, which connects, calls `status`, renders combined indicators per session (`◉` waiting, `●` working, `○` idle), and exits.

## Rendering Rules

- Group agents by session; combine indicators in priority order: waiting → working → idle.
- Sort sessions alphabetically.
- Output tmux-compatible formatting with no trailing newline.

## CLI Surface

- `agent-status daemon`
- `agent-status status` (default)
- `agent-status notify <json>` (Codex bridge)
- `agent-status register/update/unregister` (debug/testing)
- `agent-status list --json` (debug)

## Error Handling

- If the daemon is unavailable, `status` prints nothing and exits 0 (tmux-safe).
- `daemon` logs malformed JSON-RPC requests and keeps running.
- `notify` validates payload and no-ops on unknown event types.

## Testing

- Unit tests for JSON-RPC codec and store lifecycle.
- Rendering tests for combined indicators and sort order.
- Integration tests using a temp socket (start daemon, connect client, verify output).
- Extend the existing `test-harness.sh` to use the Go daemon.

## Open Decisions

- Autostart: should `status` start the daemon if missing, or require explicit `daemon`?
- Service management: add launchd/systemd unit or keep manual start?
- Socket path override: default vs configurable flag/env.
