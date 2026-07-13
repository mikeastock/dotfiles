#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

TESTS_PASSED=0
TESTS_FAILED=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN="$TMP_DIR/bin"
EVENTS="$TMP_DIR/sandbox-events.jsonl"
PROMPT="$TMP_DIR/prompt.md"
REPO="$TMP_DIR/repo"
RUN_DIR="$TMP_DIR/run"
RUN_DIR_FAILED="$TMP_DIR/run-failed"
RUN_DIR_RESUMED="$TMP_DIR/run-resumed"
COMMAND_LOG="$TMP_DIR/command.log"
KILLED_MARKER="$TMP_DIR/killed"
ACTIVE_SESSION="$TMP_DIR/active-session"
GROK_SESSION_ID="019f4d7b-7517-7021-9dbf-9b9dcd20bd43"
OTHER_SESSION_ID="019f4d7b-7517-7021-9dbf-9b9dcd20bd44"
TEST_HOME="$TMP_DIR/home"

mkdir -p "$FAKE_BIN" "$REPO" "$TEST_HOME/.grok/bundled/skills/review"
git -C "$REPO" init -q
printf '%s\n' '/review --branch test-branch' > "$PROMPT"
printf '%s\n' '# Native test skill' > "$TEST_HOME/.grok/bundled/skills/review/SKILL.md"

cat > "$FAKE_BIN/grok" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
    printf '%s\n' "${FAKE_GROK_VERSION:-grok 0.2.99 (test) [stable]}"
    exit 0
fi

session_id=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --session-id|--resume)
            session_id="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ "${FAKE_RESULT_TYPE:-result}" == "error" ]]; then
    printf '%s\n' '{"type":"error","message":"agent building failed"}'
    exit 0
fi

session_id="${FAKE_RESULT_SESSION:-$session_id}"
printf '{"text":"PROBE_OK","stopReason":"%s","sessionId":"%s","requestId":"test-request"}\n' \
  "${FAKE_STOP_REASON:-EndTurn}" "$session_id" \
  | sed "s/PROBE_OK/${FAKE_RESULT_TEXT-PROBE_OK}/"
EOF

cat > "$FAKE_BIN/zmx" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
run)
    if [[ "${FAKE_ZMX_RUN_STATUS:-0}" != 0 ]]; then
        exit "$FAKE_ZMX_RUN_STATUS"
    fi
    command_string="${@: -1}"
    printf '%s\n' "$2" > "$FAKE_ZMX_ACTIVE_FILE"
    printf '%s\n' "$command_string" > "$FAKE_ZMX_COMMAND_LOG"
    if [[ "${FAKE_SANDBOX_EVENT:-applied}" == failed ]]; then
        printf '{"event_type":"ApplyFailed","profile":"read-only","workspace":"%s","enforced":false}\n' "$REPO" >> "$GROK_SANDBOX_EVENTS"
    elif [[ "${FAKE_SANDBOX_EVENT:-applied}" == applied ]]; then
        printf '{"event_type":"ProfileApplied","profile":"read-only","workspace":"%s","enforced":true}\n' "$REPO" >> "$GROK_SANDBOX_EVENTS"
    fi
    bash -lc "$command_string"
    if [[ "${FAKE_ZMX_STAYS_ACTIVE:-0}" == 0 ]]; then
        rm -f "$FAKE_ZMX_ACTIVE_FILE"
    else
        mkdir -p "$(dirname "$LOCK_OWNER")"
        printf '%s\n' "$2" > "$LOCK_OWNER"
    fi
    ;;
kill)
    : > "$FAKE_ZMX_KILLED"
    if [[ "${FAKE_ZMX_KILL_STATUS:-0}" != 0 ]]; then
        exit "$FAKE_ZMX_KILL_STATUS"
    fi
    rm -f "$FAKE_ZMX_ACTIVE_FILE"
    ;;
wait)
    ;;
list)
    if [[ "${FAKE_ZMX_LIST_STATUS:-0}" != 0 ]]; then
        exit "$FAKE_ZMX_LIST_STATUS"
    fi
    if [[ -s "$FAKE_ZMX_ACTIVE_FILE" ]]; then
        cat "$FAKE_ZMX_ACTIVE_FILE"
    fi
    ;;
esac
EOF

chmod +x "$FAKE_BIN/grok" "$FAKE_BIN/zmx"

run_launcher() {
    HOME="$TEST_HOME" \
      PATH="$FAKE_BIN:$PATH" \
      GROK_BIN="$FAKE_BIN/grok" \
      GROK_SANDBOX_EVENTS="$EVENTS" \
      GROK_REVIEW_TEST_SESSION_ID="$GROK_SESSION_ID" \
      FAKE_ZMX_COMMAND_LOG="$COMMAND_LOG" \
      FAKE_ZMX_KILLED="$KILLED_MARKER" \
      FAKE_ZMX_ACTIVE_FILE="$ACTIVE_SESSION" \
      FAKE_ZMX_KILL_STATUS="${FAKE_ZMX_KILL_STATUS:-0}" \
      FAKE_ZMX_LIST_STATUS="${FAKE_ZMX_LIST_STATUS:-0}" \
      FAKE_ZMX_STAYS_ACTIVE="${FAKE_ZMX_STAYS_ACTIVE:-0}" \
      FAKE_GROK_VERSION="${FAKE_GROK_VERSION:-grok 0.2.99 (test) [stable]}" \
      FAKE_RESULT_TYPE="${FAKE_RESULT_TYPE:-result}" \
      FAKE_RESULT_SESSION="${FAKE_RESULT_SESSION:-}" \
      FAKE_RESULT_TEXT="${FAKE_RESULT_TEXT-PROBE_OK}" \
      FAKE_STOP_REASON="${FAKE_STOP_REASON:-EndTurn}" \
      FAKE_SANDBOX_EVENT="${FAKE_SANDBOX_EVENT:-applied}" \
      FAKE_ZMX_RUN_STATUS="${FAKE_ZMX_RUN_STATUS:-0}" \
      "$PROJECT_DIR/skills/grok-review/scripts/run_review.sh" start "$REPO" "$PROMPT" "$1"
}

resume_launcher() {
    HOME="$TEST_HOME" \
      PATH="$FAKE_BIN:$PATH" \
      GROK_BIN="$FAKE_BIN/grok" \
      GROK_SANDBOX_EVENTS="$EVENTS" \
      FAKE_ZMX_COMMAND_LOG="$COMMAND_LOG" \
      FAKE_ZMX_KILLED="$KILLED_MARKER" \
      FAKE_ZMX_ACTIVE_FILE="$ACTIVE_SESSION" \
      "$PROJECT_DIR/skills/grok-review/scripts/run_review.sh" resume \
        "$REPO" "$PROMPT" "$1" "$GROK_SESSION_ID"
}

wait_for_launcher() {
    HOME="$TEST_HOME" PATH="$FAKE_BIN:$PATH" FAKE_ZMX_ACTIVE_FILE="$ACTIVE_SESSION" \
      "$PROJECT_DIR/skills/grok-review/scripts/run_review.sh" wait "$1"
}

log_test "Testing launcher requires the Git root"
mkdir -p "$REPO/subdirectory"
if "$PROJECT_DIR/skills/grok-review/scripts/run_review.sh" start \
  "$REPO/subdirectory" "$PROMPT" "$TMP_DIR/run-subdirectory" >"$TMP_DIR/subdirectory.log" 2>&1; then
    log_error "FAIL: Launcher accepted a repository subdirectory"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher rejects a repository subdirectory"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

log_test "Testing Grok review launcher success path"
output=$(run_launcher "$RUN_DIR" 2>&1)
assert_output_contains "$output" "Sandbox enforced" "Launcher reports sandbox enforcement"
assert_file_exists "$RUN_DIR/result.json" "Launcher writes the result artifact"
assert_output_contains "$(<"$RUN_DIR/result.json")" "PROBE_OK" "Launcher captures Grok output"
assert_output_contains "$(<"$COMMAND_LOG")" "--sandbox read-only" "Launcher passes the read-only sandbox"
assert_output_contains "$(<"$COMMAND_LOG")" "--prompt-file" "Launcher passes the prompt file"
assert_output_contains "$(<"$COMMAND_LOG")" "--no-plan" "Launcher disables plan mode"
assert_output_not_contains "$(<"$COMMAND_LOG")" "--always-approve" "Launcher does not auto-approve shell commands"
assert_output_contains "$(<"$COMMAND_LOG")" '--disable-web-search' "Launcher disables web search"
assert_output_contains "$(<"$COMMAND_LOG")" '--disallowed-tools "search_replace,write,web_search,web_fetch"' "Launcher removes mutating and external built-in tools"
assert_output_contains "$(<"$COMMAND_LOG")" '--deny MCPTool' "Launcher denies MCP calls"
assert_output_not_contains "$(<"$COMMAND_LOG")" '--tools' "Launcher avoids Grok 0.2.99 shell allowlist incompatibility"
assert_output_not_contains "$(<"$COMMAND_LOG")" '--no-subagents' "Launcher preserves Grok 0.2.99 shell background support"
assert_output_contains "$(<"$RUN_DIR/grok-session")" "$GROK_SESSION_ID" "Launcher records the Grok session"

log_test "Testing structured result validation"
output=$(wait_for_launcher "$RUN_DIR" 2>&1)
assert_output_contains "$output" "Validated review" "Wait validates a completed review"
assert_output_contains "$(<"$RUN_DIR/review.md")" "PROBE_OK" "Wait extracts validated review text"
assert_file_not_exists "$(<"$RUN_DIR/workspace-lock")" "Successful review releases the workspace lock"

log_test "Testing explicit session recovery"
: > "$EVENTS"
output=$(resume_launcher "$RUN_DIR_RESUMED" 2>&1)
assert_output_contains "$output" "Sandbox enforced" "Resume requires sandbox enforcement"
assert_output_contains "$(<"$COMMAND_LOG")" "--resume" "Resume passes the recorded Grok session"
assert_output_contains "$(<"$COMMAND_LOG")" "--sandbox read-only" "Resume preserves the read-only sandbox"
wait_for_launcher "$RUN_DIR_RESUMED" >/dev/null
assert_output_contains "$(<"$RUN_DIR_RESUMED/review.md")" "PROBE_OK" "Resume result validates"

log_test "Testing Grok review launcher fails closed on sandbox failure"
: > "$EVENTS"
rm -f "$KILLED_MARKER"
if FAKE_SANDBOX_EVENT=failed run_launcher "$RUN_DIR_FAILED" >"$TMP_DIR/failure.log" 2>&1; then
    log_error "FAIL: Launcher accepted an unenforced sandbox"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher rejects an unenforced sandbox"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_exists "$KILLED_MARKER" "Launcher stops a review after sandbox failure"
if wait_for_launcher "$RUN_DIR_FAILED" >"$TMP_DIR/rejected-wait.log" 2>&1; then
    log_error "FAIL: Wait accepted a sandbox-rejected run"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Wait rejects a sandbox-rejected run"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_not_exists "$RUN_DIR_FAILED/review.md" "Rejected sandbox run does not produce review text"

log_test "Testing Grok review launcher fails closed when no sandbox event arrives"
: > "$EVENTS"
rm -f "$KILLED_MARKER"
if GROK_SANDBOX_WAIT_ATTEMPTS=1 FAKE_SANDBOX_EVENT=none run_launcher "$TMP_DIR/run-no-event" >"$TMP_DIR/no-event.log" 2>&1; then
    log_error "FAIL: Launcher accepted a review without sandbox evidence"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher rejects a review without sandbox evidence"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_exists "$KILLED_MARKER" "Launcher stops a review after missing sandbox evidence"

log_test "Testing Grok review launcher rejects version drift"
rm -f "$COMMAND_LOG"
if FAKE_GROK_VERSION='grok 0.3.0 (test) [stable]' run_launcher "$TMP_DIR/run-version" >"$TMP_DIR/version.log" 2>&1; then
    log_error "FAIL: Launcher accepted an unsupported Grok version"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher rejects an unsupported Grok version"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_not_exists "$COMMAND_LOG" "Version failure occurs before zmx launch"

log_test "Testing result validation rejects a mismatched session"
: > "$EVENTS"
FAKE_RESULT_SESSION="$OTHER_SESSION_ID" run_launcher "$TMP_DIR/run-mismatch" >/dev/null
if wait_for_launcher "$TMP_DIR/run-mismatch" >"$TMP_DIR/mismatch.log" 2>&1; then
    log_error "FAIL: Wait accepted a result for another Grok session"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Wait rejects a result for another Grok session"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_not_exists "$TMP_DIR/run-mismatch/review.md" "Rejected result does not produce review text"

log_test "Testing result validation rejects Grok error JSON"
: > "$EVENTS"
FAKE_RESULT_TYPE=error run_launcher "$TMP_DIR/run-error" >/dev/null
if wait_for_launcher "$TMP_DIR/run-error" >"$TMP_DIR/error.log" 2>&1; then
    log_error "FAIL: Wait accepted Grok error JSON"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Wait rejects Grok error JSON"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_not_exists "$TMP_DIR/run-error/review.md" "Error result does not produce review text"

log_test "Testing result validation rejects a nonterminal stop reason"
: > "$EVENTS"
FAKE_STOP_REASON=MaxTurns run_launcher "$TMP_DIR/run-max-turns" >/dev/null
if wait_for_launcher "$TMP_DIR/run-max-turns" >"$TMP_DIR/max-turns.log" 2>&1; then
    log_error "FAIL: Wait accepted a turn-limited result"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Wait rejects a turn-limited result"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_not_exists "$TMP_DIR/run-max-turns/review.md" "Nonterminal result does not produce review text"

log_test "Testing result validation rejects blank review text"
: > "$EVENTS"
FAKE_RESULT_TEXT='' run_launcher "$TMP_DIR/run-blank" >/dev/null
if wait_for_launcher "$TMP_DIR/run-blank" >"$TMP_DIR/blank.log" 2>&1; then
    log_error "FAIL: Wait accepted blank review text"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Wait rejects blank review text"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_not_exists "$TMP_DIR/run-blank/review.md" "Blank result does not produce review text"

log_test "Testing one active review per workspace"
lock_key="$(printf '%s\n' "$REPO" | git hash-object --stdin)"
lock_dir="${TMPDIR:-/tmp}/grok-review-lock-$lock_key"
mkdir "$lock_dir"
printf '%s\n' 'existing-review' > "$lock_dir/zmx-session"
printf '%s\n' 'existing-review' > "$ACTIVE_SESSION"
if run_launcher "$TMP_DIR/run-locked" >"$TMP_DIR/locked.log" 2>&1; then
    log_error "FAIL: Launcher accepted a concurrent workspace review"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher rejects a concurrent workspace review"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
rm -f "$ACTIVE_SESSION" "$lock_dir/zmx-session"
rmdir "$lock_dir"

log_test "Testing stale workspace lock recovery"
mkdir "$lock_dir"
printf '%s\n' 'stale-review' > "$lock_dir/zmx-session"
: > "$EVENTS"
output=$(run_launcher "$TMP_DIR/run-stale-lock" 2>&1)
assert_output_contains "$output" "Sandbox enforced" "Launcher replaces a demonstrably stale lock"

log_test "Testing zmx list failure does not reclaim a lock"
mkdir "$lock_dir"
printf '%s\n' 'unknown-review' > "$lock_dir/zmx-session"
if FAKE_ZMX_LIST_STATUS=1 run_launcher "$TMP_DIR/run-list-failed" >"$TMP_DIR/list-failed.log" 2>&1; then
    log_error "FAIL: Launcher reclaimed a lock without zmx evidence"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher retains a lock when zmx list fails"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_exists "$lock_dir/zmx-session" "Unverifiable stale lock is retained"
rm -f "$lock_dir/zmx-session"
rmdir "$lock_dir"

log_test "Testing sandbox abort retains lock when termination is unverified"
: > "$EVENTS"
if GROK_ABORT_WAIT_ATTEMPTS=1 FAKE_SANDBOX_EVENT=failed FAKE_ZMX_STAYS_ACTIVE=1 \
  FAKE_ZMX_KILL_STATUS=1 run_launcher "$TMP_DIR/run-kill-failed" >"$TMP_DIR/kill-failed.log" 2>&1; then
    log_error "FAIL: Launcher accepted an unverified sandbox abort"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher rejects an unverified sandbox abort"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_exists "$lock_dir/zmx-session" "Unverified termination retains the workspace lock"
rm -f "$ACTIVE_SESSION" "$lock_dir/zmx-session"
rmdir "$lock_dir"

print_summary
