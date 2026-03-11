#!/usr/bin/env bash
#
# Run extension-local test suites for any Pi extension that defines a test script.
#
# Usage: ./tests/test-pi-extension-tests.sh
#

source "$(dirname "$0")/test-helpers.sh"

trap cleanup EXIT

log_info "Testing Pi extension-local test suites..."

if ! command -v node &>/dev/null; then
  log_error "Node.js is required but not installed"
  exit 1
fi

if ! command -v pnpm &>/dev/null; then
  log_error "pnpm is required but not installed"
  exit 1
fi

cd "$PROJECT_DIR"

has_test_script() {
  local package_json="$1"
  node --input-type=module -e '
    import fs from "node:fs";

    const pkg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.exit(pkg.scripts?.test ? 0 : 1);
  ' "$package_json"
}

run_extension_test() {
  local extension_dir="$1"
  pnpm --dir "$extension_dir" test
}

test_extension_packages() {
  log_test "Pi extensions with local test scripts pass"

  local package_json
  local extension_dir
  local output
  local ran_any=0

  while IFS= read -r package_json; do
    if ! has_test_script "$package_json"; then
      continue
    fi

    ran_any=1
    extension_dir="$(dirname "$package_json")"
    log_info "Running extension tests in $extension_dir"

    if output=$(run_extension_test "$extension_dir" 2>&1); then
      log_info "PASS: $extension_dir"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    else
      log_error "FAIL: $extension_dir"
      echo "$output"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
  done < <(fd '^package\.json$' pi-extensions -d 2)

  if [ "$ran_any" -eq 0 ]; then
    log_info "PASS: no extension-local test suites found"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  fi
}

main() {
  setup_sandbox

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

  test_extension_packages
  print_summary
}

main "$@"
