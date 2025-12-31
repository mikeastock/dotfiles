#!/usr/bin/env bash
#
# Test Pi tools by type-checking them against the latest Pi package
#
# Usage: ./tests/test-pi-tools.sh
#

source "$(dirname "$0")/test-helpers.sh"

trap cleanup EXIT

log_info "Testing Pi tools type-checking..."

# Check if there are any Pi tools to test
PI_TOOLS_DIR="$PROJECT_DIR/tools/pi"
if [ ! -d "$PI_TOOLS_DIR" ] || [ -z "$(ls -A "$PI_TOOLS_DIR" 2>/dev/null)" ]; then
    log_info "No Pi tools found in $PI_TOOLS_DIR, skipping type-check"
    print_summary
    exit 0
fi

# Check for Node.js
if ! command -v node &> /dev/null; then
    log_error "Node.js is required but not installed"
    exit 1
fi

# Check for pnpm
if ! command -v pnpm &> /dev/null; then
    log_error "pnpm is required but not installed"
    exit 1
fi

cd "$PROJECT_DIR"

# Install dependencies
log_test "Installing pnpm dependencies..."
if pnpm install --silent 2>&1; then
    log_info "PASS: pnpm install succeeded"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_error "FAIL: pnpm install failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    print_summary
    exit 1
fi

# Run type-check
log_test "Type-checking Pi tools..."
TYPECHECK_OUTPUT=$(pnpm run typecheck 2>&1) || true

if echo "$TYPECHECK_OUTPUT" | grep -q "error TS"; then
    log_error "FAIL: TypeScript errors found"
    echo "$TYPECHECK_OUTPUT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    log_info "PASS: Type-check succeeded"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

print_summary
