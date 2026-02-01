# AGENTS.md

Guidance for AI assistants working on `tmux-agent-status`.

## Scope

This directory contains the Go-based tmux status daemon:

- `main.go` – CLI entry point with subcommand dispatch
- `cmd/` – Subcommand implementations (daemon, status, notify, debug commands)
- `internal/` – Core packages (server, store, render, jsonrpc, types)
- `test-harness.sh` – End-to-end test harness (not CI)

## Architecture

A Go daemon listens on `~/.config/agents/agent-status.sock`. Agents connect via Unix socket and send JSON-RPC messages. Connection lifecycle = agent liveness for registered agents (no PID polling); stateless upsert updates (Codex) persist until overwritten or explicitly removed.

```
┌─────────────┐     Unix socket      ┌─────────────┐
│ Pi extension│─────────────────────▶│   daemon    │
└─────────────┘                      │  (Go)       │
┌─────────────┐     notify cmd       │             │
│ Codex CLI   │─────────────────────▶│             │──▶ tmux status
└─────────────┘                      └─────────────┘
```

## JSON-RPC Protocol

Messages are newline-delimited JSON (NDJSON):

```json
{"method": "register", "params": {"session": "dev", "pane": "%1", "agent": "pi", "state": "idle"}}
{"method": "upsert", "params": {"session": "dev", "pane": "%1", "agent": "codex", "state": "waiting"}}
{"method": "update", "params": {"state": "working"}}
{"method": "unregister"}
```

## Conventions

- Keep the daemon minimal and fast (called every 2s by tmux)
- Connection close = automatic cleanup for registered agents (no explicit unregister required)
- States: `idle`, `working`, `waiting`
- Output must be tmux-compatible (no extra newlines)

## Testing

Run the test harness during development:

```bash
./test-harness.sh
```

Run unit tests:

```bash
go test ./...
```

## launchd

The daemon runs as a launchd service on macOS. Installed via `make install-tmux`.

Plist: `~/Library/LaunchAgents/com.agents.agent-status.plist`
Logs: `~/Library/Logs/agent-status.log`
