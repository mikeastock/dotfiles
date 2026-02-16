#!/usr/bin/env bash
#
# Shared test helper functions for the agents test suite
#
# Source this file in your test scripts:
#   source "$(dirname "$0")/test-helpers.sh"
#

# Exit on errors, undefined variables, and pipe failures
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

# Get the directory where this file is located
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$TESTS_DIR/.." && pwd)"

# Sandbox directory for testing (set by setup_sandbox)
SANDBOX_DIR=""

# Cleanup function - call in trap or at end of tests
cleanup() {
    if [ -n "$SANDBOX_DIR" ] && [ -d "$SANDBOX_DIR" ]; then
        echo -e "\n${YELLOW}Cleaning up sandbox directory...${NC}"
        # Make all files writable before deletion (handles Go module cache read-only files)
        chmod -R u+w "$SANDBOX_DIR" 2>/dev/null || true
        rm -rf "$SANDBOX_DIR"
    fi
}

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

# Assert a command succeeds
# Usage: assert_success "description" command arg1 arg2...
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

# Assert a command fails
# Usage: assert_failure "description" command arg1 arg2...
assert_failure() {
    local description="$1"
    shift
    if "$@"; then
        log_error "FAIL: $description (expected failure but succeeded)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Assert a file exists
# Usage: assert_file_exists "/path/to/file" "optional description"
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

# Assert a file does not exist
# Usage: assert_file_not_exists "/path/to/file" "optional description"
assert_file_not_exists() {
    local file="$1"
    local description="${2:-File does not exist: $file}"
    if [ ! -e "$file" ]; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description (file exists: $file)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Assert a directory exists
# Usage: assert_dir_exists "/path/to/dir" "optional description"
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

# Assert a symlink exists
# Usage: assert_symlink_exists "/path/to/link" "optional description"
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

# Assert output contains expected text
# Usage: assert_output_contains "$output" "expected text" "optional description"
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

# Assert output does not contain text
# Usage: assert_output_not_contains "$output" "unexpected text" "optional description"
assert_output_not_contains() {
    local output="$1"
    local unexpected="$2"
    local description="${3:-Output does not contain text}"
    if ! echo "$output" | grep -q "$unexpected"; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description (found unexpected: '$unexpected')"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Assert two strings are equal
# Usage: assert_equals "actual" "expected" "optional description"
assert_equals() {
    local actual="$1"
    local expected="$2"
    local description="${3:-Values are equal}"
    if [ "$actual" = "$expected" ]; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description"
        log_error "  Expected: '$expected'"
        log_error "  Actual:   '$actual'"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Assert JSON field has expected value (requires jq)
# Usage: assert_json_field "$json" ".field.path" "expected_value" "optional description"
assert_json_field() {
    local json="$1"
    local path="$2"
    local expected="$3"
    local description="${4:-JSON field $path equals $expected}"

    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null) || {
        log_error "FAIL: $description (invalid JSON or path)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    if [ "$actual" = "$expected" ]; then
        log_info "PASS: $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAIL: $description"
        log_error "  Path:     $path"
        log_error "  Expected: '$expected'"
        log_error "  Actual:   '$actual'"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Setup sandbox environment with agent directories
# Creates a temporary HOME directory with .claude, .codex, .pi structures
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
    mkdir -p "$SANDBOX_DIR/.pi/agent/hooks"

    log_info "Sandbox directories created"
}

# Initialize git submodules if needed
init_submodules() {
    log_info "Checking git submodules..."
    cd "$PROJECT_DIR"

    # Check if any submodules are uninitialized
    if git submodule status --recursive | grep -q '^-'; then
        log_info "Initializing git submodules..."
        git submodule update --init --recursive
    else
        log_info "Git submodules already initialized"
    fi
}

# Print test summary and return appropriate exit code
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

# Export functions for use in subshells
export -f log_info
export -f log_error
export -f log_test
export -f assert_success
export -f assert_failure
export -f assert_file_exists
export -f assert_file_not_exists
export -f assert_dir_exists
export -f assert_symlink_exists
export -f assert_output_contains
export -f assert_output_not_contains
export -f assert_equals
export -f assert_json_field
