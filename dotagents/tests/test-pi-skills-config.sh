#!/usr/bin/env bash
#
# Test script for pi-skills-config Makefile command
# Tests the jq-based settings.json modification
#
# Usage: ./tests/test-pi-skills-config.sh
#

# Source shared test helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

# Set trap for cleanup on exit
trap cleanup EXIT

# Test: jq is available
test_jq_available() {
    log_test "Testing that jq is available"

    if command -v jq >/dev/null 2>&1; then
        log_info "PASS: jq is installed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: jq is not installed (required for tests)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "Install jq to run these tests: apt install jq or brew install jq"
        exit 1
    fi
}

# Test: pi-skills-config with empty/new settings file
test_config_new_file() {
    log_test "Testing 'make pi-skills-config' with new settings file"
    cd "$PROJECT_DIR"

    # Ensure the settings file doesn't exist
    rm -f "$SANDBOX_DIR/.pi/agent/settings.json"

    # Run pi-skills-config with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make pi-skills-config 2>&1)

    assert_output_contains "$output" "Configuring Pi agent skills settings" "Shows progress message"
    assert_output_contains "$output" "Pi agent settings updated" "Shows completion message"

    # Verify the file was created
    assert_file_exists "$SANDBOX_DIR/.pi/agent/settings.json" "Settings file was created"

    # Verify the JSON content
    local json
    json=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    assert_json_field "$json" ".skills.enableClaudeUser" "false" "enableClaudeUser is false"
    assert_json_field "$json" ".skills.enableCodexUser" "false" "enableCodexUser is false"
}

# Test: pi-skills-config with existing settings file (should preserve other settings)
test_config_preserve_existing() {
    log_test "Testing 'make pi-skills-config' preserves existing settings"
    cd "$PROJECT_DIR"

    # Create a settings file with existing settings
    mkdir -p "$SANDBOX_DIR/.pi/agent"
    cat > "$SANDBOX_DIR/.pi/agent/settings.json" <<'EOF'
{
  "model": "claude-sonnet-4-20250514",
  "customSystemPrompt": "Be helpful",
  "skills": {
    "enableProjectSkills": true
  }
}
EOF

    # Run pi-skills-config with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make pi-skills-config 2>&1)

    assert_output_contains "$output" "Pi agent settings updated" "Shows completion message"

    # Verify the JSON content
    local json
    json=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    # Check new settings were added
    assert_json_field "$json" ".skills.enableClaudeUser" "false" "enableClaudeUser is false"
    assert_json_field "$json" ".skills.enableCodexUser" "false" "enableCodexUser is false"

    # Check existing settings were preserved
    assert_json_field "$json" ".model" "claude-sonnet-4-20250514" "model setting preserved"
    assert_json_field "$json" ".customSystemPrompt" "Be helpful" "customSystemPrompt preserved"
    assert_json_field "$json" ".skills.enableProjectSkills" "true" "enableProjectSkills preserved"
}

# Test: pi-skills-config is idempotent (running twice has same result)
test_config_idempotent() {
    log_test "Testing 'make pi-skills-config' is idempotent"
    cd "$PROJECT_DIR"

    # Ensure fresh start
    rm -f "$SANDBOX_DIR/.pi/agent/settings.json"

    # Run pi-skills-config twice
    HOME="$SANDBOX_DIR" make pi-skills-config >/dev/null 2>&1
    local first_run
    first_run=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    HOME="$SANDBOX_DIR" make pi-skills-config >/dev/null 2>&1
    local second_run
    second_run=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    # Content should be identical
    if [ "$first_run" = "$second_run" ]; then
        log_info "PASS: Running pi-skills-config twice produces identical results"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Results differ between runs"
        log_error "  First run: $first_run"
        log_error "  Second run: $second_run"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: pi-skills-config creates directory if needed
test_config_creates_directory() {
    log_test "Testing 'make pi-skills-config' creates .pi/agent directory"
    cd "$PROJECT_DIR"

    # Remove the entire .pi directory
    rm -rf "$SANDBOX_DIR/.pi"

    # Run pi-skills-config
    local output
    output=$(HOME="$SANDBOX_DIR" make pi-skills-config 2>&1)

    assert_dir_exists "$SANDBOX_DIR/.pi/agent" ".pi/agent directory was created"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/settings.json" "settings.json was created"
}

# Test: pi-skills-config help is visible
test_help_shows_config() {
    log_test "Testing 'make help' shows pi-skills-config"
    cd "$PROJECT_DIR"

    local output
    output=$(make help 2>&1)

    assert_output_contains "$output" "pi-skills-config" "Help shows pi-skills-config command"
}

# Test: JSON is valid after multiple operations
test_json_validity() {
    log_test "Testing JSON validity after modifications"
    cd "$PROJECT_DIR"

    # Start with a complex existing config
    mkdir -p "$SANDBOX_DIR/.pi/agent"
    cat > "$SANDBOX_DIR/.pi/agent/settings.json" <<'EOF'
{
  "model": "claude-sonnet-4-20250514",
  "skills": {
    "enableProjectSkills": true,
    "customPaths": ["/path/one", "/path/two"]
  },
  "nested": {
    "deep": {
      "value": 123
    }
  }
}
EOF

    # Run pi-skills-config
    HOME="$SANDBOX_DIR" make pi-skills-config >/dev/null 2>&1

    # Validate JSON with jq
    if jq '.' "$SANDBOX_DIR/.pi/agent/settings.json" >/dev/null 2>&1; then
        log_info "PASS: Output is valid JSON"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Output is not valid JSON"
        cat "$SANDBOX_DIR/.pi/agent/settings.json"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Check complex nested structure still exists
    local json
    json=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")
    assert_json_field "$json" ".nested.deep.value" "123" "Nested structure preserved"
}

# Main
main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Pi Skills Config Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    # Setup
    setup_sandbox

    # Run tests
    test_jq_available
    test_help_shows_config
    test_config_creates_directory
    test_config_new_file
    test_config_preserve_existing
    test_config_idempotent
    test_json_validity

    # Summary
    print_summary
}

# Run main
main "$@"
