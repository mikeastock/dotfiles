#!/usr/bin/env bash
#
# Test pi-theme-watch helper.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT
setup_sandbox

log_test "Testing pi-theme-watch forwards dark-notify events"

fake_bin="$SANDBOX_DIR/fake-bin"
push_log="$SANDBOX_DIR/push-log.txt"
mkdir -p "$fake_bin"
cat > "$fake_bin/dark-notify" <<'EOF'
#!/usr/bin/env bash
printf 'light\ndark\n'
EOF
cat > "$fake_bin/pi-theme-push" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$push_log"
EOF
chmod +x "$fake_bin/dark-notify" "$fake_bin/pi-theme-push"

PATH="$fake_bin:$PATH" "$PROJECT_DIR/bin/pi-theme-watch" devbox backupbox

expected=$'devbox light\nbackupbox light\ndevbox dark\nbackupbox dark'
actual=$(<"$push_log")
assert_equals "$actual" "$expected" "Watcher forwards each appearance to each target"

print_summary
