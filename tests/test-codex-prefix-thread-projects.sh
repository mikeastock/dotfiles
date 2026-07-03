#!/usr/bin/env bash
#
# Tests for codex-prefix-thread-projects
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

server_pid=""

cleanup_test() {
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    cleanup
}

trap cleanup_test EXIT

log_test "codex-prefix-thread-projects removes merged labels from thread names"

setup_sandbox

export PROJECT_DIR
socket_path="$SANDBOX_DIR/codex-app-server.sock"
ready_path="$SANDBOX_DIR/codex-rpc-ready"
node "$PROJECT_DIR/tests/mock-codex-rpc-server.js" "$socket_path" "$ready_path" >"$SANDBOX_DIR/mock-codex-rpc.log" 2>&1 &
server_pid=$!
for _ in {1..50}; do
    [ -e "$ready_path" ] && break
    sleep 0.1
done
assert_file_exists "$ready_path" "mock Codex RPC server started"

output=$(HOME="$SANDBOX_DIR" CODEX_APP_SERVER_SOCKET="$socket_path" node "$PROJECT_DIR/bin/codex-prefix-thread-projects" --dry-run --json)
next_name=$(node -e 'const report = JSON.parse(process.argv[1]); console.log(report.changes[0]?.nextName || "");' "$output")
assert_equals "$next_name" "a6: Fix checkout flow" "merged prefix is normalized to the plain project prefix"

help_output=$(node "$PROJECT_DIR/bin/codex-prefix-thread-projects" --help)
assert_output_not_contains "$help_output" "--detect-merged" "help does not advertise merged detection"

cron_config=$(<"$PROJECT_DIR/configs/cron/codex-prefix-thread-projects.cron")
assert_output_not_contains "$cron_config" "--detect-merged" "cron job does not request merged detection"

kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""

print_summary
