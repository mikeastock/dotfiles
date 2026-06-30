#!/usr/bin/env bash
#
# Test script for amp-worktree.
#
# Usage: ./tests/test-amp-worktree.sh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

write_fake_command() {
    local path="$1"
    local body="$2"

    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$body" > "$path"
    chmod +x "$path"
}

test_amp_worktree_prepares_bdev_and_launches_tmux() {
    log_test "Testing amp-worktree prepares bdev worktree and launches tmux"

    local fake_bin repo output worktree_path log_path
    fake_bin="$SANDBOX_DIR/fake-bin"
    repo="$SANDBOX_DIR/repos/app"
    mkdir -p "$fake_bin" "$repo/bin"

    write_fake_command "$fake_bin/amp" '#!/usr/bin/env bash
set -euo pipefail
printf "pwd=%s\n" "$PWD" > "$AMP_WORKTREE_TEST_DIR/amp.log"
printf "argc=%s\n" "$#" >> "$AMP_WORKTREE_TEST_DIR/amp.log"
printf "arg1=%s\n" "${1:-}" >> "$AMP_WORKTREE_TEST_DIR/amp.log"
printf "arg2=%s\n" "${2:-}" >> "$AMP_WORKTREE_TEST_DIR/amp.log"
printf "amp ok\n"
'

    write_fake_command "$fake_bin/fake-shell" '#!/usr/bin/env bash
exit 0
'

    write_fake_command "$fake_bin/tmux" '#!/usr/bin/env bash
set -euo pipefail
printf "%s\n" "$*" > "$AMP_WORKTREE_TEST_DIR/tmux.log"
command="${*: -1}"
eval "set -- $command"
script="$3"
bash -c "${script%%; status=*}"
'

    write_fake_command "$repo/bin/bdev" '#!/usr/bin/env bash
set -euo pipefail
printf "pwd=%s\n" "$PWD" > "$AMP_WORKTREE_TEST_DIR/bdev.log"
printf "args=%s\n" "$*" >> "$AMP_WORKTREE_TEST_DIR/bdev.log"
printf "{\"status\":\"ok\"}\n"
'

    (
        cd "$repo"
        git init --quiet
        git config user.email "test@example.com"
        git config user.name "Test User"
        printf 'hello\n' > README.md
        git add README.md bin/bdev
        git commit --quiet -m "Initial commit"
    )

    output=$(
        cd "$repo"
        AMP_WORKTREE_TEST_DIR="$SANDBOX_DIR" HOME="$SANDBOX_DIR" PATH="$fake_bin:$PATH" SHELL="$fake_bin/fake-shell" "$PROJECT_DIR/bin/amp-worktree" "fix quoted prompt"
    )

    assert_output_contains "$output" "Worktree:" "Prints created worktree path"
    assert_output_contains "$output" "tmux window:" "Prints tmux window name"
    assert_output_contains "$output" "Log:" "Prints amp output log path"

    worktree_path=$(printf '%s\n' "$output" | sed -n 's/^Worktree: //p')
    log_path=$(printf '%s\n' "$output" | sed -n 's/^Log: //p')
    assert_dir_exists "$worktree_path" "Creates sibling git worktree"
    assert_file_exists "$log_path" "Writes amp output log"
    assert_file_exists "$SANDBOX_DIR/bdev.log" "Runs bdev worktree setup"
    assert_file_exists "$SANDBOX_DIR/tmux.log" "Creates tmux window"
    assert_file_exists "$SANDBOX_DIR/amp.log" "Launches amp inside tmux command"

    local bdev_log amp_log tmux_log
    bdev_log=$(cat "$SANDBOX_DIR/bdev.log")
    amp_log=$(cat "$SANDBOX_DIR/amp.log")
    tmux_log=$(cat "$SANDBOX_DIR/tmux.log")

    assert_output_contains "$(cat "$log_path")" "amp ok" "Captures amp output in log file"
    assert_output_contains "$bdev_log" "pwd=$worktree_path" "Runs bdev from new worktree"
    assert_output_contains "$bdev_log" "args=worktree setup --output json --from $repo --name" "Passes bdev setup options"
    assert_output_contains "$amp_log" "pwd=$worktree_path" "Runs amp from new worktree"
    assert_output_contains "$amp_log" "argc=2" "Passes execute flag and prompt to amp"
    assert_output_contains "$amp_log" "arg1=--execute" "Uses Amp execute mode"
    assert_output_contains "$amp_log" "arg2=fix quoted prompt" "Preserves prompt text"
    assert_output_contains "$tmux_log" "new-window -d -n" "Uses detached tmux new-window"
    assert_output_contains "$tmux_log" 'bash -lc' "Runs tmux command through bash"
    assert_output_contains "$tmux_log" 'amp\ exited\ with\ status' "Prints amp exit status before holding the window"
    assert_output_contains "$tmux_log" 'SHELL:-/bin/bash' "Keeps tmux window open with the user shell"
}

setup_sandbox
test_amp_worktree_prepares_bdev_and_launches_tmux
print_summary
