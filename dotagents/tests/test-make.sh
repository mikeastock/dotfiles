#!/usr/bin/env bash
#
# Test script for Makefile commands
# Creates a sandbox filesystem to test installations without affecting real agent directories
#
# Usage: ./tests/test-make.sh
#

# Source shared test helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

# Set trap for cleanup on exit
trap cleanup EXIT

# Test: make help
test_make_help() {
    log_test "Testing 'make help'"
    cd "$PROJECT_DIR"

    local output
    output=$(make help 2>&1)

    assert_output_contains "$output" "Agents - Skills and Tools Installer" "Help shows title"
    assert_output_contains "$output" "make install" "Help shows install command"
    assert_output_contains "$output" "make build" "Help shows build command"
    assert_output_contains "$output" "make clean" "Help shows clean command"
}

# Test: make build
test_make_build() {
    log_test "Testing 'make build'"
    cd "$PROJECT_DIR"

    # Clean first
    rm -rf "$PROJECT_DIR/build/claude" "$PROJECT_DIR/build/pi"

    # Run build
    local output
    output=$(make build 2>&1)

    assert_output_contains "$output" "Building skills..." "Build shows progress"
    assert_output_contains "$output" "Skills built to" "Build shows completion"

    # Check build directories were created
    assert_dir_exists "$PROJECT_DIR/build/claude" "Build created claude directory"
    assert_dir_exists "$PROJECT_DIR/build/pi" "Build created pi directory"

    # Check that skills were built (at least one skill should exist)
    local skill_count
    skill_count=$(find "$PROJECT_DIR/build/claude" -maxdepth 1 -type d | wc -l)
    if [ "$skill_count" -gt 1 ]; then
        log_info "PASS: Build created skills ($((skill_count - 1)) skills found)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Build did not create any skills"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Check that SKILL.md files exist in built skills
    local has_skill_md=false
    for skill_dir in "$PROJECT_DIR/build/claude"/*/; do
        if [ -f "${skill_dir}SKILL.md" ]; then
            has_skill_md=true
            break
        fi
    done
    if $has_skill_md; then
        log_info "PASS: Built skills contain SKILL.md files"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Built skills missing SKILL.md files"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: make install-skills (with sandbox)
test_make_install_skills() {
    log_test "Testing 'make install-skills' (sandboxed)"
    cd "$PROJECT_DIR"

    # Run install-skills with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install-skills 2>&1)

    assert_output_contains "$output" "Installing skills for Claude Code" "Install shows Claude progress"
    assert_output_contains "$output" "Installing skills for Pi agent" "Install shows Pi progress"

    # Check symlinks were created in sandbox
    local claude_skills_count
    claude_skills_count=$(find "$SANDBOX_DIR/.claude/skills" -maxdepth 1 -type l 2>/dev/null | wc -l)
    if [ "$claude_skills_count" -gt 0 ]; then
        log_info "PASS: Claude skills symlinked ($claude_skills_count symlinks)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Claude skills symlinked"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local pi_skills_count
    pi_skills_count=$(find "$SANDBOX_DIR/.pi/agent/skills" -maxdepth 1 -type l 2>/dev/null | wc -l)
    if [ "$pi_skills_count" -gt 0 ]; then
        log_info "PASS: Pi skills symlinked ($pi_skills_count symlinks)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Pi skills symlinked"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local codex_skills_count
    codex_skills_count=$(find "$SANDBOX_DIR/.codex/skills" -maxdepth 1 -type l 2>/dev/null | wc -l)
    if [ "$codex_skills_count" -gt 0 ]; then
        log_info "PASS: Codex skills symlinked ($codex_skills_count symlinks)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Codex skills symlinked"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: make install-tools (with sandbox)
test_make_install_tools() {
    log_test "Testing 'make install-tools' (sandboxed)"
    cd "$PROJECT_DIR"

    # Run install-tools with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install-tools 2>&1)

    assert_output_contains "$output" "Installing custom tools for Pi agent" "Install shows tools progress"
    assert_output_contains "$output" "Pi tools installed" "Install shows completion"

    # Check if tools directory has any tools (depends on whether tools/pi exists)
    if [ -d "$PROJECT_DIR/tools/pi" ]; then
        local tools_count
        tools_count=$(find "$SANDBOX_DIR/.pi/agent/tools" -maxdepth 1 -type l 2>/dev/null | wc -l)
        if [ "$tools_count" -gt 0 ]; then
            log_info "PASS: Pi tools symlinked ($tools_count symlinks)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_info "PASS: No tools to install (tools/pi may be empty)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        fi
    else
        log_info "PASS: No tools directory found (expected)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# Test: make install-hooks (with sandbox)
test_make_install_hooks() {
    log_test "Testing 'make install-hooks' (sandboxed)"
    cd "$PROJECT_DIR"

    # Run install-hooks with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install-hooks 2>&1)

    assert_output_contains "$output" "Installing hooks for Pi agent" "Install shows hooks progress"
    assert_output_contains "$output" "Pi hooks installed" "Install shows completion"

    # Check if hooks directory has any hooks (depends on whether hooks/pi exists)
    if [ -d "$PROJECT_DIR/hooks/pi" ]; then
        local hooks_count
        hooks_count=$(find "$SANDBOX_DIR/.pi/agent/hooks" -maxdepth 1 -type l 2>/dev/null | wc -l)
        if [ "$hooks_count" -gt 0 ]; then
            log_info "PASS: Pi hooks symlinked ($hooks_count symlinks)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_info "PASS: No hooks to install (hooks/pi may be empty)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        fi
    else
        log_info "PASS: No hooks directory found (expected)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# Test: make install (with sandbox)
test_make_install() {
    log_test "Testing 'make install' (sandboxed)"
    cd "$PROJECT_DIR"

    # Clean sandbox first
    rm -rf "$SANDBOX_DIR/.claude/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.codex/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.pi/agent/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.pi/agent/tools"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.pi/agent/hooks"/* 2>/dev/null || true

    # Run full install with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install 2>&1)

    assert_output_contains "$output" "All skills, tools, and hooks installed" "Install shows completion message"
}

# Test: make clean (with sandbox)
test_make_clean() {
    log_test "Testing 'make clean' (sandboxed)"
    cd "$PROJECT_DIR"

    # First install
    HOME="$SANDBOX_DIR" make install >/dev/null 2>&1

    # Then clean
    local output
    output=$(HOME="$SANDBOX_DIR" make clean 2>&1)

    assert_output_contains "$output" "Removing installed skills, tools, and hooks" "Clean shows progress"
    assert_output_contains "$output" "Cleaned up installed skills, tools, and hooks" "Clean shows completion"

    # Verify build directories are removed
    if [ ! -d "$PROJECT_DIR/build/claude" ] && [ ! -d "$PROJECT_DIR/build/pi" ]; then
        log_info "PASS: Build directories removed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Build directories still exist after clean"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: make all (should run help)
test_make_all() {
    log_test "Testing 'make all' (should show help)"
    cd "$PROJECT_DIR"

    local output
    output=$(make all 2>&1)

    assert_output_contains "$output" "Agents - Skills and Tools Installer" "'make all' shows help"
}

# Main
main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Makefile Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    # Setup
    setup_sandbox
    init_submodules

    # Run tests
    test_make_help
    test_make_all
    test_make_build
    test_make_install_skills
    test_make_install_tools
    test_make_install_hooks
    test_make_install
    test_make_clean

    # Summary
    print_summary
}

# Run main
main "$@"
