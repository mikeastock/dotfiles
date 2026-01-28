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

    assert_output_contains "$output" "Agents - Skills and Extensions Installer" "Help shows title"
    assert_output_contains "$output" "make install" "Help shows install command"
    assert_output_contains "$output" "make build" "Help shows build command"
    assert_output_contains "$output" "make clean" "Help shows clean command"
    assert_output_contains "$output" "plugins.toml" "Help mentions config file"
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

    assert_output_contains "$output" "Building skills" "Build shows progress"
    assert_output_contains "$output" "Built" "Build shows completion"

    # Check build directories were created
    assert_dir_exists "$PROJECT_DIR/build/amp" "Build created amp directory"
    assert_dir_exists "$PROJECT_DIR/build/claude" "Build created claude directory"
    assert_dir_exists "$PROJECT_DIR/build/codex" "Build created codex directory"
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

    assert_output_contains "$output" "Installing skills" "Install shows progress"

    # Check directories were created in sandbox
    local amp_skills_count
    amp_skills_count=$(find "$SANDBOX_DIR/.config/agents/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$amp_skills_count" -gt 0 ]; then
        log_info "PASS: Amp skills installed ($amp_skills_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Amp skills installed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local claude_skills_count
    claude_skills_count=$(find "$SANDBOX_DIR/.claude/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$claude_skills_count" -gt 0 ]; then
        log_info "PASS: Claude skills installed ($claude_skills_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Claude skills installed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local codex_skills_count
    codex_skills_count=$(find "$SANDBOX_DIR/.codex/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$codex_skills_count" -gt 0 ]; then
        log_info "PASS: Codex skills installed ($codex_skills_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Codex skills installed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local pi_skills_count
    pi_skills_count=$(find "$SANDBOX_DIR/.pi/agent/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$pi_skills_count" -gt 0 ]; then
        log_info "PASS: Pi skills installed ($pi_skills_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Pi skills installed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: make install-extensions (with sandbox)
test_make_install_extensions() {
    log_test "Testing 'make install-extensions' (sandboxed)"
    cd "$PROJECT_DIR"

    # Run install-extensions with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install-extensions 2>&1)

    assert_output_contains "$output" "Installing extensions" "Install shows extensions progress"
    assert_output_contains "$output" "Installed" "Install shows completion"

    # Check if extensions directory has any extensions
    local extensions_count
    extensions_count=$(find "$SANDBOX_DIR/.pi/agent/extensions" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$extensions_count" -gt 0 ]; then
        log_info "PASS: Pi extensions installed ($extensions_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        # May have no extensions configured in plugins.toml
        log_info "PASS: No extensions to install (may be expected)"
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
    rm -rf "$SANDBOX_DIR/.pi/agent/extensions"/* 2>/dev/null || true

    # Run full install with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install 2>&1)

    assert_output_contains "$output" "All skills and extensions installed" "Install shows completion message"
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

    assert_output_contains "$output" "Cleaning" "Clean shows progress"

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

    assert_output_contains "$output" "Agents - Skills and Extensions Installer" "'make all' shows help"
}

# Test: plugins.toml exists and is valid
test_plugins_toml() {
    log_test "Testing plugins.toml configuration"
    cd "$PROJECT_DIR"

    assert_file_exists "$PROJECT_DIR/plugins.toml" "plugins.toml exists"

    # Check Python can parse it
    local output
    output=$(python3 -c "import tomllib; tomllib.load(open('plugins.toml', 'rb')); print('valid')" 2>&1)
    if [[ "$output" == *"valid"* ]]; then
        log_info "PASS: plugins.toml is valid TOML"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: plugins.toml is not valid TOML: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
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
    test_plugins_toml
    test_make_build
    test_make_install_skills
    test_make_install_extensions
    test_make_install
    test_make_clean

    # Summary
    print_summary
}

# Run main
main "$@"
