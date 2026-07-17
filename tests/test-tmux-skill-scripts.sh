#!/usr/bin/env bash
#
# Test tmux skill helper scripts.
#
# Usage: ./tests/test-tmux-skill-scripts.sh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

SOCKET_DIR=""
SOCKET=""

cleanup_tmux() {
    if [ -n "$SOCKET" ]; then
        tmux -S "$SOCKET" kill-server >/dev/null 2>&1 || true
    fi
    if [ -n "$SOCKET_DIR" ] && [ -d "$SOCKET_DIR" ]; then
        rm -rf "$SOCKET_DIR"
    fi
}

trap cleanup_tmux EXIT

skip_without_tmux() {
    if ! command -v tmux >/dev/null 2>&1; then
        log_info "SKIP: tmux not installed"
        print_summary
        exit 0
    fi
}

test_scripts_are_syntax_valid() {
    log_test "Testing tmux skill script syntax"

    assert_success "find-sessions.sh syntax is valid" bash -n "$PROJECT_DIR/skills/tmux/scripts/find-sessions.sh"
    assert_success "wait-for-text.sh syntax is valid" bash -n "$PROJECT_DIR/skills/tmux/scripts/wait-for-text.sh"
}

test_find_sessions_on_socket() {
    log_test "Testing find-sessions.sh against a fallback socket"

    SOCKET_DIR="$(mktemp -d)"
    SOCKET="$SOCKET_DIR/test.sock"
    tmux -f /dev/null -S "$SOCKET" new -d -s agent-test -n shell 'printf ready; sleep 30'

    local output
    output="$($PROJECT_DIR/skills/tmux/scripts/find-sessions.sh -S "$SOCKET")"

    assert_output_contains "$output" "Sessions on socket path '$SOCKET':" "Output labels the requested socket"
    assert_output_contains "$output" "agent-test (detached, started" "Output parses session fields"
    assert_output_not_contains "$output" '\t' "Output does not contain literal tab escapes"
}

test_wait_for_text_on_socket() {
    log_test "Testing wait-for-text.sh against a fallback socket"

    if [ -z "$SOCKET" ]; then
        SOCKET_DIR="$(mktemp -d)"
        SOCKET="$SOCKET_DIR/test.sock"
        tmux -f /dev/null -S "$SOCKET" new -d -s agent-test -n shell 'printf ready; sleep 30'
    fi

    assert_success "wait-for-text finds pane text" \
        "$PROJECT_DIR/skills/tmux/scripts/wait-for-text.sh" -S "$SOCKET" -t agent-test:0.0 -p ready -T 3 -l 100
}

test_wait_for_text_fails_fast_for_bad_target() {
    log_test "Testing wait-for-text.sh fails fast for a bad target"

    local start
    local elapsed
    local err_file
    err_file="$(mktemp)"
    start=$(date +%s)

    if "$PROJECT_DIR/skills/tmux/scripts/wait-for-text.sh" -S "$SOCKET" -t no-such:0.0 -p ready -T 10 > /dev/null 2> "$err_file"; then
        log_error "FAIL: bad target should fail"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        rm -f "$err_file"
        return 1
    fi

    elapsed=$(($(date +%s) - start))
    if [ "$elapsed" -lt 5 ]; then
        log_info "PASS: bad target failed fast"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: bad target waited ${elapsed}s"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local err
    err="$(<"$err_file")"
    rm -f "$err_file"
    assert_output_contains "$err" "Failed to capture tmux pane no-such:0.0" "Bad target reports capture failure"
}

main() {
    cd "$PROJECT_DIR"
    skip_without_tmux
    test_scripts_are_syntax_valid
    test_find_sessions_on_socket
    test_wait_for_text_on_socket
    test_wait_for_text_fails_fast_for_bad_target
    print_summary
}

main "$@"
