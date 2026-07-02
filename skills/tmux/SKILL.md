---
name: tmux
description: "Remote control tmux sessions for interactive CLIs (python, gdb, etc.) by sending keystrokes and scraping pane output."
license: Vibecoded
---

# tmux Skill

Use tmux as a programmable terminal multiplexer for interactive work. Works on Linux and macOS with stock tmux. Prefer the active tmux server so the user's existing sessions and config are visible; only create a private fallback socket when no active server exists.

## Quickstart (active server, socket fallback)

```bash
# Prefer the actively running/default tmux server. If none exists, create an
# agent-owned socket so interactive work still has a server to attach to.
if tmux has-session 2>/dev/null; then
  TMUX_CMD=(tmux)
  TMUX_LABEL="active tmux server"
else
  RUNTIME_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
  SOCKET_DIR="${TMUX_FALLBACK_SOCKET_DIR:-$RUNTIME_DIR/agent-tmux-sockets-$(id -u)}"
  mkdir -p -m 700 "$SOCKET_DIR"
  chmod 700 "$SOCKET_DIR"
  SOCKET="$SOCKET_DIR/agent.sock"
  TMUX_CMD=(tmux -S "$SOCKET")
  TMUX_LABEL="fallback socket $SOCKET"
fi

SESSION="agent-python-$(date -u +%Y%m%dT%H%M%SZ)"  # slug-like names; avoid spaces
"${TMUX_CMD[@]}" new -d -s "$SESSION" -n shell
"${TMUX_CMD[@]}" send-keys -t "$SESSION":0.0 -- 'PYTHON_BASIC_REPL=1 python3 -q' Enter
"${TMUX_CMD[@]}" capture-pane -p -J -t "$SESSION":0.0 -S -200  # watch output
"${TMUX_CMD[@]}" kill-session -t "$SESSION"                   # clean up
```

After starting a session ALWAYS tell the user how to monitor the session by giving them a command to copy paste. Use plain `tmux ...` commands when `TMUX_LABEL` is `active tmux server`; use `tmux -S "$SOCKET" ...` commands when running on the fallback socket.

Active server example:

```text
To monitor this session yourself:
  tmux attach -t agent-lldb

Or to capture the output once:
  tmux capture-pane -p -J -t agent-lldb:0.0 -S -200
```

Fallback socket example:

```text
To monitor this session yourself:
  tmux -S "$SOCKET" attach -t agent-lldb

Or to capture the output once:
  tmux -S "$SOCKET" capture-pane -p -J -t agent-lldb:0.0 -S -200
```

This must ALWAYS be printed right after a session was started and once again at the end of the tool loop. But the earlier you send it, the happier the user will be.

## Server selection convention

- Agents MUST first try the active/default tmux server with plain `tmux` commands: `tmux has-session`, `tmux new`, `tmux send-keys`, `tmux capture-pane`, etc.
- Only if `tmux has-session` fails, create a fallback socket under `TMUX_FALLBACK_SOCKET_DIR` (defaults to `${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/agent-tmux-sockets-$(id -u)`) and use `tmux -S "$SOCKET"` consistently for that session.
- Default fallback socket path to use unless you must isolate further: `SOCKET="$SOCKET_DIR/agent.sock"` after computing `SOCKET_DIR` as shown in the quickstart.
- Keep the selected command in an array, e.g. `TMUX_CMD=(tmux)` or `TMUX_CMD=(tmux -S "$SOCKET")`, then invoke it as `"${TMUX_CMD[@]}" ...` to avoid accidentally switching servers. Do not name this variable `TMUX`; tmux uses `$TMUX` internally.

## Targeting panes and naming

- Target format: `{session}:{window}.{pane}`, defaults to `:0.0` if omitted. Keep names short and prefixed with `agent-` (e.g., `agent-py`, `agent-gdb`). Add a timestamp or task suffix before creating a session, or check `has-session -t`, to avoid colliding with an existing session on the active server.
- Use the selected `TMUX_CMD` command consistently to stay on either the active server or the fallback socket. If you need user config, the active server path already uses it; for fallback sockets, avoid `-f /dev/null` unless you specifically need a clean config.
- Inspect: `"${TMUX_CMD[@]}" list-sessions`, `"${TMUX_CMD[@]}" list-panes -a`.

## Finding sessions

- List sessions on the active/default server with metadata: `./scripts/find-sessions.sh`; add `-q partial-name` to filter.
- List sessions on the fallback socket when used: `./scripts/find-sessions.sh -S "$SOCKET"`.
- Scan all fallback sockets under the shared directory: `./scripts/find-sessions.sh --all` (uses `TMUX_FALLBACK_SOCKET_DIR` or `${TMPDIR:-/tmp}/agent-tmux-sockets`).

## Sending input safely

- Prefer literal sends to avoid shell splitting: `"${TMUX_CMD[@]}" send-keys -t target -l -- "$cmd"`.
- When composing inline commands, use single quotes or ANSI C quoting to avoid expansion: `"${TMUX_CMD[@]}" send-keys -t target -- $'python3 -m http.server 8000'`.
- To send control keys: `"${TMUX_CMD[@]}" send-keys -t target C-c`, `C-d`, `C-z`, `Escape`, etc.

## Watching output

- Capture recent history (joined lines to avoid wrapping artifacts): `"${TMUX_CMD[@]}" capture-pane -p -J -t target -S -200`.
- For continuous monitoring, poll with the helper script (below) instead of `tmux wait-for` (which does not watch pane output). The helper uses the active/default tmux server; if you are on the fallback socket, pass `-S "$SOCKET"`.
- You can also temporarily attach to observe: `"${TMUX_CMD[@]}" attach -t "$SESSION"`; detach with `Ctrl+b d`.
- When giving instructions to a user, **explicitly print a copy/paste monitor command** alongside the action; don't assume they remembered the command.

## Spawning Processes

Some special rules for processes:

- when asked to debug, use lldb by default
- when starting a python interactive shell, always set the `PYTHON_BASIC_REPL=1` environment variable. This is very important as the non-basic console interferes with your send-keys.

## Synchronizing / waiting for prompts

- Use timed polling to avoid races with interactive tools. Example: wait for a Python prompt before sending code:
  ```bash
  ./scripts/wait-for-text.sh -t "$SESSION":0.0 -p '^>>>' -T 15 -l 4000
  ```
- If the session is on the fallback socket, pass the socket to the helper:
  ```bash
  ./scripts/wait-for-text.sh -S "$SOCKET" -t "$SESSION":0.0 -p '^>>>' -T 15 -l 4000
  ```
- For long-running commands, poll for completion text (`"Type quit to exit"`, `"Program exited"`, etc.) before proceeding.

## Interactive tool recipes

- **Python REPL**: `"${TMUX_CMD[@]}" send-keys -- 'PYTHON_BASIC_REPL=1 python3 -q' Enter`; wait for `^>>>`; send code with `-l`; interrupt with `C-c`.
- **gdb**: `"${TMUX_CMD[@]}" send-keys -- 'gdb --quiet ./a.out' Enter`; disable paging `"${TMUX_CMD[@]}" send-keys -- 'set pagination off' Enter`; break with `C-c`; issue `bt`, `info locals`, etc.; exit via `quit` then confirm `y`.
- **Other TTY apps** (ipdb, psql, mysql, node, bash): same pattern—start the program, poll for its prompt, then send literal text and Enter.

## Cleanup

- Kill a session when done: `"${TMUX_CMD[@]}" kill-session -t "$SESSION"`.
- Kill only agent-created sessions on the selected server:
  ```bash
  "${TMUX_CMD[@]}" list-sessions -F '#{session_name}' | rg '^agent-' | while IFS= read -r session; do
    "${TMUX_CMD[@]}" kill-session -t "$session"
  done
  ```
- Remove everything on the fallback socket only when you created one: `tmux -S "$SOCKET" kill-server`. Never run `kill-server` against the active/default server.

## Helper: wait-for-text.sh

`./scripts/wait-for-text.sh` polls a pane for a regex (or fixed string) with a timeout. Works on Linux/macOS with bash + tmux + rg.

```bash
./scripts/wait-for-text.sh [-S socket-path] -t session:0.0 -p 'pattern' [-F] [-T 20] [-i 0.5] [-l 2000]
```

- `-S`/`--socket-path` fallback tmux socket path (optional; omit for the active/default server)
- `-t`/`--target` pane target (required)
- `-p`/`--pattern` regex to match (required); add `-F` for fixed string
- `-T` timeout seconds (integer, default 15)
- `-i` poll interval seconds (default 0.5)
- `-l` history lines to search from the pane (integer, default 1000)
- Exits 0 on first match, 1 on timeout. On failure prints the last captured text to stderr to aid debugging.
