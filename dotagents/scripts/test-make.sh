#!/usr/bin/env bash
#
# Test script for Makefile commands
# Creates a sandbox filesystem to test installations without affecting real agent directories
#
# Usage: ./scripts/test-make.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Sandbox directory for testing
SANDBOX_DIR=""

# Cleanup function
cleanup() {
    if [ -n "$SANDBOX_DIR" ] && [ -d "$SANDBOX_DIR" ]; then
        echo -e "\n${YELLOW}Cleaning up sandbox directory...${NC}"
        rm -rf "$SANDBOX_DIR"
    fi
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
}

# Test assertion functions
assert_success() {
    local description="$1"
    shift
    if "$@"; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_file_exists() {
    local file="$1"
    local description="${2:-File exists: $file}"
    if [ -e "$file" ]; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description (file not found: $file)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_dir_exists() {
    local dir="$1"
    local description="${2:-Directory exists: $dir}"
    if [ -d "$dir" ]; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description (directory not found: $dir)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_symlink_exists() {
    local link="$1"
    local description="${2:-Symlink exists: $link}"
    if [ -L "$link" ]; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description (symlink not found: $link)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_output_contains() {
    local output="$1"
    local expected="$2"
    local description="${3:-Output contains expected text}"
    if echo "$output" | grep -q "$expected"; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description (expected: '$expected')"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Setup sandbox environment
setup_sandbox() {
    log_info "Setting up sandbox environment..."

    # Create temporary directory for sandbox HOME
    SANDBOX_DIR=$(mktemp -d)
    log_info "Sandbox HOME: $SANDBOX_DIR"

    # Create agent directories in sandbox
    mkdir -p "$SANDBOX_DIR/.claude/skills"
    mkdir -p "$SANDBOX_DIR/.codex/skills"
    mkdir -p "$SANDBOX_DIR/.pi/agent/skills"
    mkdir -p "$SANDBOX_DIR/.pi/agent/tools"

    log_info "Sandbox directories created"
}

# Initialize git submodules if needed
init_submodules() {
    log_info "Checking git submodules..."
    cd "$PROJECT_DIR"

    # Check if submodules are initialized
    if [ ! -d "$PROJECT_DIR/plugins/superpowers/skills" ]; then
        log_info "Initializing git submodules..."
        git submodule update --init --recursive
    else
        log_info "Git submodules already initialized"
    fi
}

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

# Test: make install (with sandbox)
test_make_install() {
    log_test "Testing 'make install' (sandboxed)"
    cd "$PROJECT_DIR"

    # Clean sandbox first
    rm -rf "$SANDBOX_DIR/.claude/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.codex/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.pi/agent/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.pi/agent/tools"/* 2>/dev/null || true

    # Run full install with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install 2>&1)

    assert_output_contains "$output" "All skills and tools installed" "Install shows completion message"
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

    assert_output_contains "$output" "Removing installed skills and tools" "Clean shows progress"
    assert_output_contains "$output" "Cleaned up installed skills and tools" "Clean shows completion"

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

# Print test summary
print_summary() {
    echo -e "\n${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Test Summary${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "${RED}Failed:${NC} $TESTS_FAILED"
    echo -e "${YELLOW}Total:${NC}  $((TESTS_PASSED + TESTS_FAILED))"
    echo -e "${YELLOW}========================================${NC}"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
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
    test_make_build
    test_make_install_skills
    test_make_install_tools
    test_make_install
    test_make_clean

    # Summary
    print_summary
}

# Run main
main "$@"
