# AGENTS.md

Guidance for AI assistants working on `tmux-agent-status`.

## Scope

This directory contains the tmux status integration scripts and tests:

- `bin/agent-status` (bash) – reads `~/.config/agents/state.json`, groups agents by tmux session, renders status symbols, and cleans up stale PIDs.
- `bin/codex-notify` (python) – Codex notification handler that writes state updates.
- `config/state.json` – template state file (PID-keyed).
- `test-harness.sh` – end-to-end local test harness (not CI).

## State File Format

The state file is PID-keyed and supports multiple agents per tmux session:

```json
{
  "agents": {
    "12345": {
      "session": "dev",
      "pane": "%1",
      "agent": "pi",
      "state": "working",
      "timestamp": 1234567890000
    }
  }
}
```

## Conventions

- Keep `agent-status` bash 3.2 compatible (macOS default). Avoid associative arrays.
- Use `jq` for JSON operations.
- Always check PID liveness with `kill -0` and remove stale entries asynchronously.
- Keep output strictly tmux-compatible (no extra newlines).

## Testing

Run the local harness during development:

```bash
./tmux-agent-status/test-harness.sh
```

It spawns real processes and validates output. Not for CI.
