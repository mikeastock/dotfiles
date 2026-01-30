#!/usr/bin/env bash
#
# End-to-end test harness for tmux-agent-status
#
# Spawns real processes, writes state, verifies display output.
# Run manually during development - not for CI.
#
# Usage: ./test-harness.sh
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_STATUS="$SCRIPT_DIR/bin/agent-status"
CODEX_NOTIFY="$SCRIPT_DIR/bin/codex-notify"

# Create temp home with proper structure
TEST_HOME=$(mktemp -d)
TEST_STATE_DIR="$TEST_HOME/.config/agents"
TEST_STATE_FILE="$TEST_STATE_DIR/state.json"
mkdir -p "$TEST_STATE_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
NC='\033[0m'

# Track results
PASSED=0
FAILED=0

# PIDs to clean up
FAKE_PIDS=()

cleanup() {
    echo -e "\n${DIM}Cleaning up...${NC}"
    for pid in "${FAKE_PIDS[@]:-}"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$TEST_HOME"
}
trap cleanup EXIT

# Spawn a fake agent (sleep process) and store PID in LAST_SPAWNED_PID
# Usage: spawn_fake_agent; pid=$LAST_SPAWNED_PID
LAST_SPAWNED_PID=""
spawn_fake_agent() {
    sleep 10 &
    LAST_SPAWNED_PID=$!
    FAKE_PIDS+=("$LAST_SPAWNED_PID")
}

# Kill a fake agent by PID
kill_fake_agent() {
    local pid="$1"
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null || true
    # Remove from FAKE_PIDS array
    local new_pids=()
    for p in "${FAKE_PIDS[@]:-}"; do
        [[ "$p" != "$pid" ]] && new_pids+=("$p")
    done
    FAKE_PIDS=("${new_pids[@]:-}")
}

# Write state file directly
write_state() {
    echo "$1" > "$TEST_STATE_FILE"
}

# Read current state
read_state() {
    cat "$TEST_STATE_FILE"
}

# Run agent-status with test HOME
run_status() {
    HOME="$TEST_HOME" "$AGENT_STATUS" 2>/dev/null | sed 's/#\[fg=[^]]*\]//g'
}

# Run codex-notify with test HOME
run_notify() {
    local payload="$1"
    echo "$payload" | HOME="$TEST_HOME" python3 "$CODEX_NOTIFY" 2>/dev/null || true
}

# Assert output equals expected
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

# Assert output contains substring
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

# Assert output is empty
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

# Assert JSON field value
assert_json() {
    local field="$1"
    local expected="$2"
    local desc="$3"
    
    local actual
    actual=$(jq -r "$field" "$TEST_STATE_FILE" 2>/dev/null) || actual="<invalid json>"
    
    if [[ "$actual" == "$expected" ]]; then
        echo -e "${GREEN}✓${NC} $desc"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗${NC} $desc"
        echo -e "  ${DIM}field:${NC}    $field"
        echo -e "  ${DIM}expected:${NC} '$expected'"
        echo -e "  ${DIM}actual:${NC}   '$actual'"
        FAILED=$((FAILED + 1))
    fi
}

echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo -e "${YELLOW}  tmux-agent-status Test Harness${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo -e "${DIM}  Test HOME: $TEST_HOME${NC}"
echo

# ============================================================
echo -e "${YELLOW}▸ Test: Empty state${NC}"
# ============================================================
write_state '{"agents":{}}'
output=$(run_status)
assert_empty "$output" "Empty state produces no output"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Single agent working${NC}"
# ============================================================
spawn_fake_agent; pid1=$LAST_SPAWNED_PID
write_state "{\"agents\":{\"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"working\",\"timestamp\":$(date +%s)000}}}"
output=$(run_status)
assert_eq "$output" "dev ●" "Single working agent shows green dot"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Single agent waiting${NC}"
# ============================================================
write_state "{\"agents\":{\"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"waiting\",\"timestamp\":$(date +%s)000}}}"
output=$(run_status)
assert_eq "$output" "dev ◉" "Single waiting agent shows yellow dot"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Single agent idle${NC}"
# ============================================================
write_state "{\"agents\":{\"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"idle\",\"timestamp\":$(date +%s)000}}}"
output=$(run_status)
assert_eq "$output" "dev ○" "Single idle agent shows dim dot"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Multiple agents same session${NC}"
# ============================================================
spawn_fake_agent; pid2=$LAST_SPAWNED_PID
write_state "{\"agents\":{
  \"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"working\",\"timestamp\":$(date +%s)000},
  \"$pid2\":{\"session\":\"dev\",\"pane\":\"%3\",\"agent\":\"codex\",\"state\":\"waiting\",\"timestamp\":$(date +%s)000}
}}"
output=$(run_status)
assert_eq "$output" "dev ◉●" "Two agents same session shows combined dots (waiting first)"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Multiple agents different sessions${NC}"
# ============================================================
spawn_fake_agent; pid3=$LAST_SPAWNED_PID
write_state "{\"agents\":{
  \"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"working\",\"timestamp\":$(date +%s)000},
  \"$pid2\":{\"session\":\"dev\",\"pane\":\"%3\",\"agent\":\"codex\",\"state\":\"waiting\",\"timestamp\":$(date +%s)000},
  \"$pid3\":{\"session\":\"staging\",\"pane\":\"%5\",\"agent\":\"pi\",\"state\":\"idle\",\"timestamp\":$(date +%s)000}
}}"
output=$(run_status)
assert_contains "$output" "dev ◉●" "Dev session has combined dots"
assert_contains "$output" "staging ○" "Staging session has idle dot"

# ============================================================
echo -e "\n${YELLOW}▸ Test: All three states in one session${NC}"
# ============================================================
write_state "{\"agents\":{
  \"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"waiting\",\"timestamp\":$(date +%s)000},
  \"$pid2\":{\"session\":\"dev\",\"pane\":\"%3\",\"agent\":\"codex\",\"state\":\"working\",\"timestamp\":$(date +%s)000},
  \"$pid3\":{\"session\":\"dev\",\"pane\":\"%5\",\"agent\":\"claude\",\"state\":\"idle\",\"timestamp\":$(date +%s)000}
}}"
output=$(run_status)
assert_eq "$output" "dev ◉●○" "Three agents shows all three indicators"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Stale PID cleanup${NC}"
# ============================================================
# Put pid3 back in a different session for stale test
write_state "{\"agents\":{
  \"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"waiting\",\"timestamp\":$(date +%s)000},
  \"$pid2\":{\"session\":\"dev\",\"pane\":\"%3\",\"agent\":\"codex\",\"state\":\"working\",\"timestamp\":$(date +%s)000},
  \"$pid3\":{\"session\":\"staging\",\"pane\":\"%5\",\"agent\":\"pi\",\"state\":\"idle\",\"timestamp\":$(date +%s)000}
}}"

# Kill one agent
kill_fake_agent "$pid3"
sleep 0.2  # Let process die

# Run status - should exclude dead PID
output=$(run_status)
assert_eq "$output" "dev ◉●" "Stale PID excluded from display"

# Wait for async cleanup and check state file
sleep 0.6
stale_check=$(jq -r ".agents[\"$pid3\"] // \"removed\"" "$TEST_STATE_FILE" 2>/dev/null)
assert_eq "$stale_check" "removed" "Stale PID removed from state file"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Sessions sorted alphabetically${NC}"
# ============================================================
spawn_fake_agent; pid4=$LAST_SPAWNED_PID
write_state "{\"agents\":{
  \"$pid1\":{\"session\":\"zebra\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"working\",\"timestamp\":$(date +%s)000},
  \"$pid2\":{\"session\":\"alpha\",\"pane\":\"%3\",\"agent\":\"codex\",\"state\":\"waiting\",\"timestamp\":$(date +%s)000},
  \"$pid4\":{\"session\":\"middle\",\"pane\":\"%5\",\"agent\":\"pi\",\"state\":\"idle\",\"timestamp\":$(date +%s)000}
}}"
output=$(run_status)
first_session=$(echo "$output" | awk '{print $1}')
assert_eq "$first_session" "alpha" "Sessions sorted alphabetically (alpha first)"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Invalid JSON handling${NC}"
# ============================================================
write_state "not valid json at all"
output=$(run_status)
assert_empty "$output" "Invalid JSON produces no output (no crash)"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Missing agents key${NC}"
# ============================================================
write_state '{"sessions":{}}'
output=$(run_status)
assert_empty "$output" "Old format (sessions key) produces no output"

# ============================================================
echo -e "\n${YELLOW}▸ Test: Unknown state value${NC}"
# ============================================================
write_state "{\"agents\":{\"$pid1\":{\"session\":\"dev\",\"pane\":\"%1\",\"agent\":\"pi\",\"state\":\"unknown_state\",\"timestamp\":$(date +%s)000}}}"
output=$(run_status)
assert_empty "$output" "Unknown state value produces no indicator"

# ============================================================
echo -e "\n${YELLOW}▸ Test: No state file${NC}"
# ============================================================
rm -f "$TEST_STATE_FILE"
output=$(run_status)
assert_empty "$output" "Missing state file produces no output (no crash)"

# ============================================================
# Summary
# ============================================================
echo
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASSED"
echo -e "  ${RED}Failed:${NC} $FAILED"
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
