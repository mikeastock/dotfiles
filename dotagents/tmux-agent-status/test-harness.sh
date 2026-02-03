#!/usr/bin/env bash
#
# End-to-end test harness for tmux-agent-status
#
# Spawns a daemon, connects test agents, and verifies tmux output.
# Run manually during development - not for CI.
#
# Usage: ./test-harness.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -n "${AGENT_STATUS_BIN:-}" ]]; then
	AGENT_STATUS="$AGENT_STATUS_BIN"
else
	HOST_GOOS=$(go env GOOS)
	HOST_GOARCH=$(go env GOARCH)
	AGENT_STATUS="$SCRIPT_DIR/../build/agent-status/${HOST_GOOS}-${HOST_GOARCH}/agent-status"
fi
REAL_HOME="$HOME"
CODEX_CONFIG_PATH="$REAL_HOME/.codex/config.toml"

if [[ ! -x "$AGENT_STATUS" ]]; then
	mkdir -p "$(dirname "$AGENT_STATUS")"
	(cd "$SCRIPT_DIR" && CGO_ENABLED=1 GOOS="$(go env GOOS)" GOARCH="$(go env GOARCH)" \
		go build -o "$AGENT_STATUS" .)
fi

TEST_HOME=$(mktemp -d)
AGENT_PIDS=()
DAEMON_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
NC='\033[0m'

# Track results
PASSED=0
FAILED=0
SKIPPED=0

cleanup() {
	echo -e "\n${DIM}Cleaning up...${NC}"
	for pid in "${AGENT_PIDS[@]:-}"; do
		if [[ -n "${pid}" ]]; then
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	done
	if [[ -n "${DAEMON_PID}" ]]; then
		kill "${DAEMON_PID}" 2>/dev/null || true
		wait "${DAEMON_PID}" 2>/dev/null || true
	fi
	rm -rf "$TEST_HOME"
}
trap cleanup EXIT

start_daemon() {
	HOME="$TEST_HOME" "$AGENT_STATUS" daemon >/dev/null 2>&1 &
	DAEMON_PID=$!
	sleep 0.2
}

spawn_agent() {
	local session="$1"
	local pane="$2"
	local agent="$3"
	local state="$4"

	SESSION="$session" PANE="$pane" AGENT="$agent" STATE="$state" HOME="$TEST_HOME" \
		python3 - <<'PY' &
import json
import os
import socket
import time

sock_path = os.path.join(os.environ["HOME"], ".config", "agents", "agent-status.sock")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
req = {
    "id": 1,
    "method": "register",
    "params": {
        "session": os.environ["SESSION"],
        "pane": os.environ["PANE"],
        "agent": os.environ["AGENT"],
        "state": os.environ["STATE"],
    },
}
s.sendall((json.dumps(req) + "\n").encode())
try:
    s.settimeout(1)
    s.recv(4096)
except Exception:
    pass
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
PY

	local pid=$!
	AGENT_PIDS+=("$pid")
	sleep 0.1
}

reset_agents() {
	for pid in "${AGENT_PIDS[@]:-}"; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	AGENT_PIDS=()
	sleep 0.2
}

run_status() {
	HOME="$TEST_HOME" "$AGENT_STATUS" status 2>/dev/null | sed 's/#\[fg=[^]]*\]//g'
}

assert_eq() {
	local actual="$1"
	local expected="$2"
	local desc="$3"

	if [[ "$actual" == "$expected" ]]; then
		echo -e "${GREEN}✓${NC} $desc"
		PASSED=$((PASSED + 1))
	else
		echo -e "${RED}✗${NC} $desc"
		echo -e "  ${DIM}expected:${NC} '$expected'"
		echo -e "  ${DIM}actual:${NC}   '$actual'"
		FAILED=$((FAILED + 1))
	fi
}

assert_contains() {
	local actual="$1"
	local expected="$2"
	local desc="$3"

	if [[ "$actual" == *"$expected"* ]]; then
		echo -e "${GREEN}✓${NC} $desc"
		PASSED=$((PASSED + 1))
	else
		echo -e "${RED}✗${NC} $desc"
		echo -e "  ${DIM}expected to contain:${NC} '$expected'"
		echo -e "  ${DIM}actual:${NC} '$actual'"
		FAILED=$((FAILED + 1))
	fi
}

assert_empty() {
	local actual="$1"
	local desc="$2"

	if [[ -z "$actual" ]]; then
		echo -e "${GREEN}✓${NC} $desc"
		PASSED=$((PASSED + 1))
	else
		echo -e "${RED}✗${NC} $desc"
		echo -e "  ${DIM}expected empty, got:${NC} '$actual'"
		FAILED=$((FAILED + 1))
	fi
}

skip() {
	local desc="$1"
	echo -e "${YELLOW}~${NC} $desc"
	SKIPPED=$((SKIPPED + 1))
}

has_notify_config() {
	python3 - <<'PY'
import os
import pathlib
import sys
import tomllib

path = pathlib.Path(os.environ["CODEX_CONFIG_PATH"])
if not path.exists():
    sys.exit(1)
try:
    data = tomllib.loads(path.read_text())
except Exception:
    sys.exit(2)
sys.exit(0 if data.get("notify") else 1)
PY
}

run_codex_exec() {
	local label="$1"
	local cmd=("${@:2}")

	if "${cmd[@]}" >/dev/null 2>&1; then
		echo -e "${GREEN}✓${NC} $label"
		PASSED=$((PASSED + 1))
	else
		echo -e "${RED}✗${NC} $label"
		FAILED=$((FAILED + 1))
	fi
}

assert_codex_visible() {
	local output="$1"
	local desc="$2"

	if echo "$output" | rg -q '"agent":\s*"codex"'; then
		echo -e "${GREEN}✓${NC} $desc"
		PASSED=$((PASSED + 1))
	else
		echo -e "${RED}✗${NC} $desc"
		FAILED=$((FAILED + 1))
	fi
}

echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo -e "${YELLOW}  tmux-agent-status Test Harness${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo -e "${DIM}  Test HOME: $TEST_HOME${NC}"

echo

echo -e "${YELLOW}▸ Starting daemon${NC}"
start_daemon

# ============================================================
echo -e "${YELLOW}▸ Test: Empty state${NC}"
# ============================================================
reset_agents
output=$(run_status)
assert_empty "$output" "Empty state produces no output"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Single agent working${NC}"
# ============================================================
reset_agents
spawn_agent "dev" "%1" "pi" "working"
output=$(run_status)
assert_eq "$output" "dev ●" "Single working agent shows green dot"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Single agent waiting${NC}"
# ============================================================
reset_agents
spawn_agent "dev" "%1" "pi" "waiting"
output=$(run_status)
assert_eq "$output" "dev ◉" "Single waiting agent shows yellow dot"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Single agent idle${NC}"
# ============================================================
reset_agents
spawn_agent "dev" "%1" "pi" "idle"
output=$(run_status)
assert_eq "$output" "dev ○" "Single idle agent shows dim dot"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Multiple agents same session${NC}"
# ============================================================
reset_agents
spawn_agent "dev" "%1" "pi" "working"
spawn_agent "dev" "%3" "codex" "waiting"
output=$(run_status)
assert_eq "$output" "dev ◉●" "Two agents same session show combined dots"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Multiple agents different sessions${NC}"
# ============================================================
reset_agents
spawn_agent "alpha" "%1" "pi" "working"
spawn_agent "beta" "%3" "codex" "waiting"
output=$(run_status)
assert_eq "$output" "alpha ●  beta ◉" "Two sessions render in order"

# ============================================================
echo -e "\n${YELLOW}▸ Test: All three states in one session${NC}"
# ============================================================
reset_agents
spawn_agent "dev" "%1" "pi" "waiting"
spawn_agent "dev" "%3" "codex" "working"
spawn_agent "dev" "%5" "pi" "idle"
output=$(run_status)
assert_eq "$output" "dev ◉●○" "Three agents show all indicators"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Deduplicate states${NC}"
# ============================================================
reset_agents
spawn_agent "dev" "%1" "pi" "working"
spawn_agent "dev" "%3" "codex" "working"
output=$(run_status)
assert_eq "$output" "dev ●" "Duplicate states show one indicator"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Disconnect cleanup${NC}"
# ============================================================
reset_agents
spawn_agent "dev" "%1" "pi" "working"
output=$(run_status)
assert_eq "$output" "dev ●" "Agent registers on connect"
reset_agents
output=$(run_status)
assert_empty "$output" "Agent removed after disconnect"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Codex integration (optional)${NC}"
# ============================================================
if [[ "${CODEX_INTEGRATION:-}" != "1" ]]; then
	skip "CODEX_INTEGRATION=1 not set"
elif [[ -z "${TMUX:-}" ]]; then
	skip "TMUX not set (run inside tmux)"
elif ! command -v codex >/dev/null 2>&1; then
	skip "codex not found on PATH"
elif [[ ! -S "$REAL_HOME/.config/agents/agent-status.sock" ]]; then
	skip "agent-status daemon socket not found in real HOME"
else
	run_codex_exec "Codex exec runs with notify override" \
		codex exec -c "notify=[\"$AGENT_STATUS\",\"notify\"]" "agent-status integration probe"
	output=$(HOME="$REAL_HOME" "$AGENT_STATUS" list 2>/dev/null || true)
	assert_codex_visible "$output" "Codex notify hook updates daemon (override)"

	has_notify_config
	notify_status=$?
	if [[ $notify_status -eq 0 ]]; then
		run_codex_exec "Codex exec runs with config notify" \
			codex exec "agent-status config probe"
		output=$(HOME="$REAL_HOME" "$AGENT_STATUS" list 2>/dev/null || true)
		assert_codex_visible "$output" "Codex notify hook updates daemon (config)"
	elif [[ $notify_status -eq 2 ]]; then
		skip "Could not parse $CODEX_CONFIG_PATH"
	else
		skip "No top-level notify in $CODEX_CONFIG_PATH"
	fi
fi

# ============================================================
# Summary
# ============================================================
echo
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASSED"
echo -e "  ${RED}Failed:${NC} $FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"

if [[ $FAILED -gt 0 ]]; then
	exit 1
fi
