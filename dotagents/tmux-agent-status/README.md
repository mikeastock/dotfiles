# tmux-agent-status

Display AI coding agent states in your tmux status bar. Supports multiple agents per session.

```
dev ◉●  staging ○
```

- **◉** Yellow = waiting for user input
- **●** Green = working
- **○** Dim = idle

## Architecture

A Go daemon (`agent-status daemon`) listens on `~/.config/agents/agent-status.sock`. Agents connect via Unix socket and send state updates. When a connection closes, the agent is removed. No PID polling.

## Supported Agents

| Agent | Integration |
|-------|-------------|
| **Pi** | Extension holds a persistent socket connection |
| **Codex** | `notify` subcommand called via `--notify-command` |

## Installation

```bash
# From the dotagents repo
make install-tmux
```

This installs the `agent-status` binary to `~/.local/bin/`.

## Usage

### Start the daemon

```bash
agent-status daemon
```

Run it from your shell startup, launchd, or systemd.

### tmux configuration

Add to `~/.tmux.conf`:

```tmux
set -g status-right '#(agent-status)'
set -g status-interval 2
```

### Codex CLI

```bash
codex --notify-command 'agent-status notify'
```

Or in `~/.codex/config.toml`:

```toml
notify_command = "agent-status notify"
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `agent-status daemon` | Start the daemon |
| `agent-status status` | Query and render (default) |
| `agent-status notify <json>` | Handle Codex notification |
| `agent-status list` | List all agents as JSON |
| `agent-status register/update/unregister` | Debug commands |

## Testing

```bash
cd tmux-agent-status
go test ./...
```

## Files

```
tmux-agent-status/
├── main.go                   # CLI entry point
├── cmd/                      # Subcommand implementations
├── internal/
│   ├── types/                # Core types
│   ├── jsonrpc/              # NDJSON codec
│   ├── store/                # In-memory agent registry
│   ├── server/               # Unix socket daemon
│   └── render/               # Tmux output formatting
├── bin/                      # Legacy scripts (deprecated)
└── test-harness.sh           # E2E tests (update for Go)
```
