#!/usr/bin/env bash
#
# Test script for Pi install wrapper workflow
#
# Usage: ./tests/test-pi-install.sh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

TEST_BIN_DIR=""
LOG_DIR=""

setup_test_path() {
    TEST_BIN_DIR="$SANDBOX_DIR/test-bin"
    LOG_DIR="$SANDBOX_DIR/logs"
    mkdir -p "$TEST_BIN_DIR" "$LOG_DIR"

    cat > "$TEST_BIN_DIR/npm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG_DIR/npm.log"
prefix=""
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  if [[ "${args[$i]}" == "--prefix" ]]; then
    prefix="${args[$((i + 1))]}"
    break
  fi
done
if [[ -n "$prefix" ]]; then
  mkdir -p "$prefix/bin" "$prefix/lib/node_modules/@mariozechner/pi-coding-agent"
  cat > "$prefix/bin/pi" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG_DIR/canonical-pi.log"
SCRIPT
  chmod +x "$prefix/bin/pi"
fi
EOF
    chmod +x "$TEST_BIN_DIR/npm"

    cat > "$TEST_BIN_DIR/make" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG_DIR/make.log"
EOF
    chmod +x "$TEST_BIN_DIR/make"

    cat > "$TEST_BIN_DIR/test-patch" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG_DIR/patch.log"
EOF
    chmod +x "$TEST_BIN_DIR/test-patch"

    export TEST_LOG_DIR="$LOG_DIR"
    export PATH="$TEST_BIN_DIR:$PATH"
}

run_pi_install() {
    HOME="$SANDBOX_DIR" TEST_LOG_DIR="$LOG_DIR" PI_PATCH_SCRIPT="$TEST_BIN_DIR/test-patch" "$PROJECT_DIR/bin/pi-install"
}

run_pi_wrapper() {
    HOME="$SANDBOX_DIR" TEST_LOG_DIR="$LOG_DIR" "$PROJECT_DIR/bin/pi" "$@"
}

reset_logs() {
    rm -f "$LOG_DIR"/*.log
}

test_pi_install_uses_canonical_prefix() {
    reset_logs
    log_test "Testing pi installer uses canonical npm prefix"

    run_pi_install >/dev/null 2>&1

    local npm_args
    npm_args=$(cat "$LOG_DIR/npm.log")
    assert_output_contains "$npm_args" 'install -g --prefix' "Installer runs npm install"
    assert_output_contains "$npm_args" "$SANDBOX_DIR/.local/share/pi-coding-agent" "Installer uses canonical prefix"
}

test_pi_install_is_idempotent() {
    reset_logs
    log_test "Testing pi installer reruns against same canonical paths"

    run_pi_install >/dev/null 2>&1
    run_pi_install >/dev/null 2>&1

    local npm_log
    npm_log=$(cat "$LOG_DIR/npm.log")
    local prefix_count
    prefix_count=$(printf '%s\n' "$npm_log" | rg -c --fixed-strings -- "$SANDBOX_DIR/.local/share/pi-coding-agent")
    assert_equals "$prefix_count" "2" "Installer uses same canonical prefix on repeat runs"
}

test_pi_install_runs_make_install_configs() {
    reset_logs
    log_test "Testing pi installer runs make install-configs"

    run_pi_install >/dev/null 2>&1

    local make_args
    make_args=$(cat "$LOG_DIR/make.log")
    assert_output_contains "$make_args" 'install-configs' "Installer runs make install-configs"
}

test_pi_install_validates_root_and_runs_patch() {
    reset_logs
    log_test "Testing pi installer validates install root and runs patch with canonical package root"

    run_pi_install >/dev/null 2>&1

    local patch_args
    patch_args=$(cat "$LOG_DIR/patch.log")
    assert_output_contains "$patch_args" "$SANDBOX_DIR/.local/share/pi-coding-agent/lib/node_modules/@mariozechner/pi-coding-agent" "Installer patches canonical package root"
}

test_pi_wrapper_passes_through_arguments() {
    reset_logs
    log_test "Testing pi wrapper passes through arguments"

    mkdir -p "$SANDBOX_DIR/.local/share/pi-coding-agent/bin"
    cat > "$SANDBOX_DIR/.local/share/pi-coding-agent/bin/pi" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG_DIR/canonical-pi.log"
EOF
    chmod +x "$SANDBOX_DIR/.local/share/pi-coding-agent/bin/pi"

    run_pi_wrapper one two >/dev/null 2>&1

    local wrapper_args
    wrapper_args=$(cat "$LOG_DIR/canonical-pi.log")
    assert_output_contains "$wrapper_args" 'one two' "Wrapper forwards arguments to canonical pi"
}

test_pi_wrapper_fails_when_missing() {
    reset_logs
    log_test "Testing pi wrapper fails clearly when canonical binary is missing"

    rm -f "$SANDBOX_DIR/.local/share/pi-coding-agent/bin/pi"

    local output
    output=$(run_pi_wrapper 2>&1 || true)
    assert_output_contains "$output" 'bin/pi-install' "Wrapper tells user to run bin/pi-install"
}

test_pi_scripts_work_via_symlink() {
    reset_logs
    log_test "Testing pi scripts resolve shared paths when invoked via symlink"

    local link_dir
    link_dir="$SANDBOX_DIR/links"
    mkdir -p "$link_dir"
    ln -s "$PROJECT_DIR/bin/pi-install" "$link_dir/pi-install"
    ln -s "$PROJECT_DIR/bin/pi" "$link_dir/pi"

    HOME="$SANDBOX_DIR" TEST_LOG_DIR="$LOG_DIR" PI_PATCH_SCRIPT="$TEST_BIN_DIR/test-patch" "$link_dir/pi-install" >/dev/null 2>&1
    HOME="$SANDBOX_DIR" TEST_LOG_DIR="$LOG_DIR" "$link_dir/pi" alpha beta >/dev/null 2>&1

    local wrapper_args
    wrapper_args=$(cat "$LOG_DIR/canonical-pi.log")
    assert_output_contains "$wrapper_args" 'alpha beta' "Symlinked wrapper forwards arguments to canonical pi"
}

main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Pi Install Wrapper Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    setup_sandbox
    setup_test_path

    test_pi_install_uses_canonical_prefix
    test_pi_install_is_idempotent
    test_pi_install_runs_make_install_configs
    test_pi_install_validates_root_and_runs_patch
    test_pi_wrapper_passes_through_arguments
    test_pi_wrapper_fails_when_missing
    test_pi_scripts_work_via_symlink

    print_summary
}

main "$@"
