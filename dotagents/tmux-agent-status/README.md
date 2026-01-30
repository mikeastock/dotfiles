# tmux-agent-status

Display AI coding agent states in your tmux status bar. Supports multiple agents per session.

```
dev ◉●  staging ○
```

- **◉** Yellow = waiting for user input
- **●** Green = working
- **○** Dim = idle

## Supported Agents

| Agent | States | Integration |
|-------|--------|-------------|
| **Pi** | idle, working, waiting | Extension writes state on lifecycle events |
| **Codex** | working, waiting | Notification script called via `--notify-command` |

## Installation

```bash
# From the dotagents repo
make install-tmux
```

This creates symlinks in `~/.local/bin/`:
- `agent-status` → display script for tmux
- `codex-notify` → notification handler for Codex

## tmux Configuration

Add to your `~/.tmux.conf`:

```tmux
# Right status: agent states
set -g status-right '#(agent-status)'

# Refresh every 2 seconds to catch state changes
set -g status-interval 2
```

Reload tmux config:
```bash
tmux source-file ~/.tmux.conf
```

## Agent Setup

### Pi Agent

The `agent-status` Pi extension is installed automatically with `make install-extensions`. It tracks:
- **idle** → session started, waiting for first prompt
- **working** → agent is processing
- **waiting** → agent finished, awaiting user input

### Codex CLI

Configure Codex to call the notification script:

```bash
# In your shell config or when running codex
codex --notify-command codex-notify
```

Or add to `~/.codex/config.toml`:
```toml
notify_command = "codex-notify"
```

## How It Works

### State File

All agents write to `~/.config/agents/state.json`, keyed by PID:

```json
{
  "agents": {
    "12345": {
      "session": "dev",
      "pane": "%1",
      "agent": "pi",
      "state": "working",
      "timestamp": 1234567890000
    },
    "67890": {
      "session": "dev",
      "pane": "%3",
      "agent": "codex",
      "state": "waiting",
      "timestamp": 1234567890000
    }
  }
}
```

### Display Logic

1. Read all agents from state file
2. Check each PID is still running (cleanup stale entries)
3. Group agents by tmux session
4. Show combined indicators per session (priority: waiting > working > idle)
5. Sort sessions alphabetically

### Stale Cleanup

When `agent-status` runs, it checks if each PID is alive. Dead processes are automatically removed from the state file (async, won't block your status bar).

## Files

```
tmux-agent-status/
├── bin/
│   ├── agent-status      # Bash script for tmux status bar
│   └── codex-notify      # Python script for Codex notifications
├── config/
│   └── state.json        # Template state file
├── test-harness.sh       # End-to-end test suite
└── README.md
```

## Testing

Run the test harness during development:

```bash
./tmux-agent-status/test-harness.sh
```

Tests spawn real processes and verify display output. Not for CI—use for local iteration.

## Troubleshooting

### No output in status bar

1. Check `~/.local/bin` is in your PATH
2. Verify state file exists: `cat ~/.config/agents/state.json`
3. Run manually: `agent-status`

### Agent not showing

1. Confirm agent process is running: `ps aux | grep -E 'pi|codex'`
2. Check state file has entry for agent's PID
3. For Codex, verify `--notify-command` is set

### Debug logging (Codex)

The notify script logs to `~/.config/agents/notify.log`:

```bash
tail -f ~/.config/agents/notify.log
```

## Requirements

- **jq** - JSON processor (for agent-status)
- **Python 3** - For codex-notify
- **tmux** - Obviously
