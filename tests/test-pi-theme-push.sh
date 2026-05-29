#!/usr/bin/env bash
#
# Test pi-theme-push helper.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT
setup_sandbox

log_test "Testing pi-theme-push explicit dark push"

fake_bin="$SANDBOX_DIR/fake-bin"
ssh_args="$SANDBOX_DIR/ssh-args.txt"
ssh_stdin="$SANDBOX_DIR/ssh-stdin.json"
mkdir -p "$fake_bin"
cat > "$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" > "$ssh_args"
cat > "$ssh_stdin"
EOF
chmod +x "$fake_bin/ssh"

output=$(PATH="$fake_bin:$PATH" "$PROJECT_DIR/bin/pi-theme-push" devbox dark 2>&1)
assert_output_contains "$output" "pushed dark theme override to devbox" "Push reports target and appearance"
assert_file_exists "$ssh_args" "ssh command was invoked"
assert_file_exists "$ssh_stdin" "override JSON was sent over stdin"

args=$(<"$ssh_args")
if [[ "$args" == devbox\ sh\ -c\ * && "$args" == *"theme-sync-override.json"* ]]; then
    log_info "PASS: ssh forces POSIX sh and receives override path"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_error "FAIL: ssh forces POSIX sh and receives override path"
    log_error "  Args: $args"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

json=$(<"$ssh_stdin")
appearance=$(node -e 'const fs = require("node:fs"); const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(data.appearance);' "$ssh_stdin")
source=$(node -e 'const fs = require("node:fs"); const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(data.source);' "$ssh_stdin")
assert_equals "$appearance" "dark" "Override JSON records dark appearance"
assert_equals "$source" "$(hostname)" "Override JSON records local hostname source"

print_summary
