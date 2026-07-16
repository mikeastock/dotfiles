---
name: zmx
description: Use zmx for durable, long-running processes that must persist beyond the current agent session, such as an app server the user will test later.
metadata:
  category: tooling
---

# zmx

Use `zmx` for durable, long-running work that must persist beyond the current
agent session, such as an app server the user will test later.

## Rules

- Use `zmx run` only when work must remain available after the current agent
  session ends.
- Do not use `zmx` for a server or process needed only while the agent performs
  its own testing. Start, manage, and stop that process directly within the
  session instead.
- Use one stable, descriptive session name per concern, such as `app-server`,
  `user-preview`, or `persistent-review`.
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
