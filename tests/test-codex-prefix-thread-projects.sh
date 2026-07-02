#!/usr/bin/env bash
#
# Tests for codex-prefix-thread-projects
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

log_test "codex-prefix-thread-projects removes merged labels from thread names"

setup_sandbox

FAKE_CODEX_APPCTL="$SANDBOX_DIR/codex-appctl"
export PROJECT_DIR
cat >"$FAKE_CODEX_APPCTL" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

method="$2"
params="$3"

if [ "$method" != "thread/list" ]; then
    echo "unexpected method: $method" >&2
    exit 1
fi

archived=$(node -e 'const params = JSON.parse(process.argv[1]); console.log(params.archived ? "true" : "false");' "$params")
if [ "$archived" = "true" ]; then
    printf '{"data":[],"nextCursor":null}\n'
else
    printf '{"data":[{"id":"thread-1","cwd":"%s","path":"%s","name":"a6(merged): Fix checkout flow"}],"nextCursor":null}\n' "$PROJECT_DIR/../app6" "$PROJECT_DIR"
fi
EOF
chmod +x "$FAKE_CODEX_APPCTL"

output=$(HOME="$SANDBOX_DIR" CODEX_APPCTL_BIN="$FAKE_CODEX_APPCTL" node "$PROJECT_DIR/bin/codex-prefix-thread-projects" --dry-run --json)
next_name=$(node -e 'const report = JSON.parse(process.argv[1]); console.log(report.changes[0]?.nextName || "");' "$output")
assert_equals "$next_name" "a6: Fix checkout flow" "merged prefix is normalized to the plain project prefix"

help_output=$(node "$PROJECT_DIR/bin/codex-prefix-thread-projects" --help)
assert_output_not_contains "$help_output" "--detect-merged" "help does not advertise merged detection"

cron_config=$(<"$PROJECT_DIR/configs/cron/codex-prefix-thread-projects.cron")
assert_output_not_contains "$cron_config" "--detect-merged" "cron job does not request merged detection"

print_summary
