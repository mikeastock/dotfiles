---
name: zmx
description: Manage persistent background terminal work with zmx in Pi Agent sessions. Use when running long-lived or background commands in Pi, including tests, dev servers, build jobs, migrations, one-off scripts, or any task that should continue independently of the current terminal invocation.
metadata:
  category: tooling
  agents: pi
---

# zmx

Use `zmx` as the persistent session runner for long-lived or background
terminal work in Pi Agent sessions.

## Rules

- Prefer `zmx run` when work should continue independently of the current
  terminal invocation.
- Use one stable, descriptive session name per concern, such as `tests`,
  `server-api`, or `build-ios`.
- Reuse a session when iterative commands should share shell state; create a
  new session when isolation is safer.
- For recurring workflows, keep session names consistent across runs.

## Non-Interactive Safety

`zmx run` can hang agent tool execution in non-interactive environments because
the daemon may keep inherited stdio open. Always redirect stdout and stderr
when starting work from an agent/tool:

```bash
zmx run <session> <command> >/dev/null 2>&1
```

Redirect to a file instead when output must be captured.

## Workflow

Start work:

```bash
zmx run <session> <command> >/dev/null 2>&1
```

Wait for completion when needed:

```bash
zmx wait <session>
```

Inspect output:

```bash
zmx history <session>
```

Check active sessions:

```bash
zmx list
```

Stop stale or finished work:

```bash
zmx kill <session>
```
