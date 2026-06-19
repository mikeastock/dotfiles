---
name: codex-appctl
description: Manage Codex app threads and remote-control state from remote or CLI-only environments. Use when Codex needs to list, search, read, create, send to, rename, archive, fork, or resume Codex app threads, or inspect/enable/disable Codex remote control without native harness thread tools.
metadata:
  agents: codex
---

# Codex App Control

- Prefer native harness thread tools when they are available.
- Otherwise use `bin/codex-appctl` from dotfiles, or `codex-appctl` when it is already on `PATH`.
- Start with `codex-appctl doctor` before relying on app-server RPC behavior.
- Use read-only commands before mutating commands.
- Do not run mutating commands unless the user explicitly asks.
- Use `--json` for machine-readable output and `--plain` for readable summaries.
- Do not depend on `codex-remote-tools`.

## Common Commands

```bash
codex-appctl doctor
codex-appctl schema methods
codex-appctl threads list --limit 20
codex-appctl threads search "text" --limit 20
codex-appctl threads read THREAD_ID --turns
codex-appctl threads turns THREAD_ID --limit 20
codex-appctl threads start --cwd PATH --message TEXT --name NAME
codex-appctl threads send THREAD_ID --message TEXT
codex-appctl threads rename THREAD_ID NAME
codex-appctl threads archive THREAD_ID
codex-appctl threads unarchive THREAD_ID
codex-appctl threads fork THREAD_ID --cwd PATH
codex-appctl threads resume THREAD_ID
codex-appctl remote status
codex-appctl remote enable
codex-appctl remote disable
codex-appctl remote clients
```
