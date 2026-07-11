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
COMMAND_LOG="$TMP_DIR/command.log"
KILLED_MARKER="$TMP_DIR/killed"

mkdir -p "$FAKE_BIN" "$REPO"
git -C "$REPO" init -q
printf '%s\n' '/code-review Reply with exactly PROBE_OK.' > "$PROMPT"

cat > "$FAKE_BIN/grok" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
    printf '%s\n' "${FAKE_GROK_VERSION:-grok 0.2.93 (test) [stable]}"
    exit 0
fi
printf '%s\n' '{"text":"PROBE_OK","stopReason":"EndTurn","sessionId":"test-session","requestId":"test-request"}'
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
    printf '%s\n' "$command_string" > "$FAKE_ZMX_COMMAND_LOG"
    if [[ "${FAKE_SANDBOX_EVENT:-applied}" == failed ]]; then
        printf '{"event_type":"ApplyFailed","profile":"read-only","workspace":"%s","enforced":false}\n' "$REPO" >> "$GROK_SANDBOX_EVENTS"
    else
        printf '{"event_type":"ProfileApplied","profile":"read-only","workspace":"%s","enforced":true}\n' "$REPO" >> "$GROK_SANDBOX_EVENTS"
    fi
    bash -lc "$command_string"
    ;;
kill)
    : > "$FAKE_ZMX_KILLED"
    ;;
esac
EOF

chmod +x "$FAKE_BIN/grok" "$FAKE_BIN/zmx"

run_launcher() {
    PATH="$FAKE_BIN:$PATH" \
      GROK_BIN="$FAKE_BIN/grok" \
      GROK_SANDBOX_EVENTS="$EVENTS" \
      FAKE_ZMX_COMMAND_LOG="$COMMAND_LOG" \
      FAKE_ZMX_KILLED="$KILLED_MARKER" \
      FAKE_GROK_VERSION="${FAKE_GROK_VERSION:-grok 0.2.93 (test) [stable]}" \
      FAKE_SANDBOX_EVENT="${FAKE_SANDBOX_EVENT:-applied}" \
      FAKE_ZMX_RUN_STATUS="${FAKE_ZMX_RUN_STATUS:-0}" \
      "$PROJECT_DIR/skills/grok-review/scripts/run_review.sh" "$REPO" "$PROMPT" "$1"
}

log_test "Testing Grok review launcher success path"
output=$(run_launcher "$RUN_DIR" 2>&1)
assert_output_contains "$output" "Sandbox enforced" "Launcher reports sandbox enforcement"
assert_file_exists "$RUN_DIR/result.json" "Launcher writes the result artifact"
assert_output_contains "$(<"$RUN_DIR/result.json")" "PROBE_OK" "Launcher captures Grok output"
assert_output_contains "$(<"$COMMAND_LOG")" "--sandbox read-only" "Launcher passes the read-only sandbox"
assert_output_contains "$(<"$COMMAND_LOG")" "--prompt-file" "Launcher passes the prompt file"
assert_output_contains "$(<"$COMMAND_LOG")" "--no-plan" "Launcher disables plan mode"

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

log_test "Testing Grok review launcher rejects version drift"
rm -f "$COMMAND_LOG"
if FAKE_GROK_VERSION='grok 0.2.94 (test) [stable]' run_launcher "$TMP_DIR/run-version" >"$TMP_DIR/version.log" 2>&1; then
    log_error "FAIL: Launcher accepted an unsupported Grok version"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Launcher rejects an unsupported Grok version"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
assert_file_not_exists "$COMMAND_LOG" "Version failure occurs before zmx launch"

print_summary
