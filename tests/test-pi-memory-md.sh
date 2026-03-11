#!/usr/bin/env bash
#
# Validate pi-memory-md extension behavior.
#
# Usage: ./tests/test-pi-memory-md.sh
#

source "$(dirname "$0")/test-helpers.sh"

trap cleanup EXIT

log_info "Testing pi-memory-md extension..."

if ! command -v pnpm &>/dev/null; then
  log_error "pnpm is required but not installed"
  exit 1
fi

cd "$PROJECT_DIR"

run_harness() {
  pnpm exec tsx tests/pi-memory-md-harness.ts
}

test_extension_harness() {
  log_test "pi-memory-md memory helpers parse, normalize, and index files"

  local output
  output=$(run_harness)

  assert_output_contains "$output" "pi-memory-md harness passed" "harness completes successfully"
}

main() {
  setup_sandbox
  test_extension_harness
  print_summary
}

main "$@"
