#!/usr/bin/env bash
set -euo pipefail

export TERM=${TERM:-xterm-256color}

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "OPENAI_API_KEY is required." >&2
  exit 1
fi

ROOT_DIR=${ROOT_DIR:-/workspace}
AGENT_STATUS_DIR="$ROOT_DIR/tmux-agent-status"
PI_EXTENSION_DIR="$ROOT_DIR/extensions/pi/agent-status"

if [[ ! -d "$AGENT_STATUS_DIR" ]]; then
  echo "Missing $AGENT_STATUS_DIR" >&2
  exit 1
fi

if [[ ! -d "$PI_EXTENSION_DIR" ]]; then
  echo "Missing $PI_EXTENSION_DIR" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain not found in PATH." >&2
  exit 1
fi

mkdir -p "$HOME/.local/bin" "$HOME/.config/agents" "$HOME/.codex" "$HOME/.pi/agent/extensions"

printf "Building agent-status...\n"
(cd "$AGENT_STATUS_DIR" && go build -o agent-status .)

ln -sf "$AGENT_STATUS_DIR/agent-status" "$HOME/.local/bin/agent-status"

cat > "$HOME/.codex/config.toml" <<EOF_CFG
approval_policy = "never"
sandbox_mode = "danger-full-access"
notify = [ "$HOME/.local/bin/agent-status", "notify" ]

[tui]
notifications = [ "agent-turn-complete" ]
EOF_CFG

mkdir -p "$HOME/.pi/agent/extensions/agent-status"
cp -R "$PI_EXTENSION_DIR/"* "$HOME/.pi/agent/extensions/agent-status/"

cat > "$HOME/.tmux.conf" <<'EOF_TMUX'
set -g status-right '#(agent-status)'
set -g status-interval 2
EOF_TMUX

"$HOME/.local/bin/agent-status" daemon >"$HOME/agent-status-daemon.log" 2>&1 &
DAEMON_PID=$!

cleanup() {
  tmux kill-server 2>/dev/null || true
  kill "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

for _ in {1..50}; do
  if [[ -S "$HOME/.config/agents/agent-status.sock" ]]; then
    break
  fi
  sleep 0.1
done

if [[ ! -S "$HOME/.config/agents/agent-status.sock" ]]; then
  echo "agent-status socket not available." >&2
  exit 1
fi

tmux start-server
TMUX_SESSION="agent-status-test"
tmux new-session -d -s "$TMUX_SESSION"
tmux split-window -t "$TMUX_SESSION" -h

CODEX_PROMPT=${CODEX_PROMPT:-codex-ok}
PI_PROVIDER=${PI_PROVIDER:-openai}
PI_MODEL=${PI_MODEL:-gpt-4o-mini}
PI_PROMPT=${PI_PROMPT:-pi-ok}

API_KEY_Q=$(printf %q "$OPENAI_API_KEY")
CODEX_PROMPT_Q=$(printf %q "$CODEX_PROMPT")
PI_PROVIDER_Q=$(printf %q "$PI_PROVIDER")
PI_MODEL_Q=$(printf %q "$PI_MODEL")
PI_PROMPT_Q=$(printf %q "$PI_PROMPT")

printf "Running Codex + Pi inside tmux...\n"
tmux send-keys -t "$TMUX_SESSION":0.0 "CODEX_API_KEY=$API_KEY_Q codex exec $CODEX_PROMPT_Q" C-m
tmux send-keys -t "$TMUX_SESSION":0.1 "pi --provider $PI_PROVIDER_Q --model $PI_MODEL_Q --api-key $API_KEY_Q --no-session --print $PI_PROMPT_Q" C-m

WAIT_SECONDS=${WAIT_SECONDS:-25}
sleep "$WAIT_SECONDS"

STATUS_JSON=$($HOME/.local/bin/agent-status list || true)
printf "%s\n" "$STATUS_JSON" > "$HOME/agent-status-list.json"

missing=0
if ! printf "%s\n" "$STATUS_JSON" | rg -q '"agent":"codex"'; then
  echo "codex entry missing from agent-status list" >&2
  missing=1
fi

if ! printf "%s\n" "$STATUS_JSON" | rg -q '"agent":"pi"'; then
  echo "pi entry missing from agent-status list" >&2
  missing=1
fi

if [[ "$missing" -ne 0 ]]; then
  echo "agent-status list:" >&2
  printf "%s\n" "$STATUS_JSON" >&2
  exit 1
fi

printf "Success: codex + pi detected in agent-status list.\n"
