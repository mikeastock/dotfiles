#!/usr/bin/env bash
#
# Test script for Pi install workflow
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

    cat > "$TEST_BIN_DIR/mise" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG_DIR/mise.log"
install_root="$HOME/.local/share/mise/installs/npm-mariozechner-pi-coding-agent/latest"
case "$1" in
  use)
    exit 0
    ;;
  install)
    mkdir -p "$install_root/bin" "$install_root/lib/node_modules/@mariozechner/pi-coding-agent"
    cat > "$install_root/bin/pi" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG_DIR/canonical-pi.log"
SCRIPT
    chmod +x "$install_root/bin/pi"
    ;;
  where)
    printf '%s\n' "$install_root"
    ;;
  which)
    printf '%s\n' "$install_root/bin/pi"
    ;;
  *)
    echo "unexpected mise command: $*" >&2
    exit 1
    ;;
esac
EOF
    chmod +x "$TEST_BIN_DIR/mise"

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

reset_logs() {
    rm -f "$LOG_DIR"/*.log
}

test_pi_install_uses_mise_npm_backend() {
    reset_logs
    log_test "Testing pi installer uses mise npm backend"

    run_pi_install >/dev/null 2>&1

    local mise_args
    mise_args=$(cat "$LOG_DIR/mise.log")
    assert_output_contains "$mise_args" 'use -g npm:@mariozechner/pi-coding-agent@latest' "Installer records Pi as global mise npm tool"
    assert_output_contains "$mise_args" 'install' "Installer installs configured mise tools"
}

test_pi_install_is_idempotent() {
    reset_logs
    log_test "Testing pi installer reruns through mise"

    run_pi_install >/dev/null 2>&1
    run_pi_install >/dev/null 2>&1

    local mise_log
    mise_log=$(cat "$LOG_DIR/mise.log")
    local use_count
    use_count=$(printf '%s\n' "$mise_log" | rg -c --fixed-strings -- 'use -g npm:@mariozechner/pi-coding-agent@latest')
    assert_equals "$use_count" "2" "Installer uses same mise tool on repeat runs"
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
    assert_output_contains "$patch_args" "$SANDBOX_DIR/.local/share/mise/installs/npm-mariozechner-pi-coding-agent/latest/lib/node_modules/@mariozechner/pi-coding-agent" "Installer patches mise-managed package root"
}

test_pi_install_works_via_symlink() {
    reset_logs
    log_test "Testing pi installer resolves shared paths when invoked via symlink"

    local link_dir
    link_dir="$SANDBOX_DIR/links"
    mkdir -p "$link_dir"
    ln -s "$PROJECT_DIR/bin/pi-install" "$link_dir/pi-install"

    HOME="$SANDBOX_DIR" TEST_LOG_DIR="$LOG_DIR" PI_PATCH_SCRIPT="$TEST_BIN_DIR/test-patch" "$link_dir/pi-install" >/dev/null 2>&1

    local patch_args
    patch_args=$(cat "$LOG_DIR/patch.log")
    assert_output_contains "$patch_args" "$SANDBOX_DIR/.local/share/mise/installs/npm-mariozechner-pi-coding-agent/latest/lib/node_modules/@mariozechner/pi-coding-agent" "Symlinked installer patches mise-managed package root"
}

main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Pi Install Wrapper Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    setup_sandbox
    setup_test_path

    test_pi_install_uses_mise_npm_backend
    test_pi_install_is_idempotent
    test_pi_install_runs_make_install_configs
    test_pi_install_validates_root_and_runs_patch
    test_pi_install_works_via_symlink

    print_summary
}

main "$@"
