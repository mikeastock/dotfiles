#!/usr/bin/env bash
#
# Test script for agents-config Makefile command
# Tests the jq-based settings modification for Amp
# (Pi settings are now managed via make install from configs/pi-settings.json)
#
# Usage: ./tests/test-agents-config.sh
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

# Test: agents-config with empty/new settings files
test_config_new_files() {
    log_test "Testing 'make agents-config' with new settings files"
    cd "$PROJECT_DIR"

    # Ensure the settings files don't exist
    rm -f "$SANDBOX_DIR/.config/amp/settings.json"

    # Run agents-config with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make agents-config 2>&1)

    assert_output_contains "$output" "Configuring agent settings" "Shows progress message"
    assert_output_contains "$output" "Configuring Amp" "Shows Amp configuration"
    assert_output_contains "$output" "All agents configured" "Shows completion message"

    # Verify Amp settings file was created
    assert_file_exists "$SANDBOX_DIR/.config/amp/settings.json" "Amp settings file was created"

    # Verify Amp JSON content
    local amp_json
    amp_json=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    assert_json_field "$amp_json" '."amp.skills.path"' "~/.config/agents/skills" "Amp: skills.path is set"
}

# Test: agents-config with existing settings files (should preserve other settings)
test_config_preserve_existing() {
    log_test "Testing 'make agents-config' preserves existing settings"
    cd "$PROJECT_DIR"

    # Create Amp settings file with existing settings
    mkdir -p "$SANDBOX_DIR/.config/amp"
    cat > "$SANDBOX_DIR/.config/amp/settings.json" <<'EOF'
{
  "amp.dangerouslyAllowAll": true,
  "amp.showCosts": false
}
EOF

    # Run agents-config with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make agents-config 2>&1)

    assert_output_contains "$output" "All agents configured" "Shows completion message"

    # Verify Amp JSON content
    local amp_json
    amp_json=$(cat "$SANDBOX_DIR/.config/amp/settings.json")

    # Check new settings were added
    assert_json_field "$amp_json" '."amp.skills.path"' "~/.config/agents/skills" "Amp: skills.path is set"

    # Check existing settings were preserved
    assert_json_field "$amp_json" '."amp.dangerouslyAllowAll"' "true" "Amp: dangerouslyAllowAll preserved"
    assert_json_field "$amp_json" '."amp.showCosts"' "false" "Amp: showCosts preserved"
}

# Test: agents-config is idempotent (running twice has same result)
test_config_idempotent() {
    log_test "Testing 'make agents-config' is idempotent"
    cd "$PROJECT_DIR"

    # Ensure fresh start
    rm -f "$SANDBOX_DIR/.config/amp/settings.json"

    # Run agents-config twice
    HOME="$SANDBOX_DIR" make agents-config >/dev/null 2>&1
    local amp_first
    amp_first=$(cat "$SANDBOX_DIR/.config/amp/settings.json")

    HOME="$SANDBOX_DIR" make agents-config >/dev/null 2>&1
    local amp_second
    amp_second=$(cat "$SANDBOX_DIR/.config/amp/settings.json")

    # Content should be identical
    if [ "$amp_first" = "$amp_second" ]; then
        log_info "PASS: Running agents-config twice produces identical results"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Results differ between runs"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: agents-config creates directories if needed
test_config_creates_directories() {
    log_test "Testing 'make agents-config' creates config directories"
    cd "$PROJECT_DIR"

    # Remove the config directories
    rm -rf "$SANDBOX_DIR/.config/amp"

    # Run agents-config
    local output
    output=$(HOME="$SANDBOX_DIR" make agents-config 2>&1)

    assert_dir_exists "$SANDBOX_DIR/.config/amp" ".config/amp directory was created"
    assert_file_exists "$SANDBOX_DIR/.config/amp/settings.json" "Amp settings.json was created"
}

# Test: agents-config help is visible
test_help_shows_config() {
    log_test "Testing 'make help' shows agents-config"
    cd "$PROJECT_DIR"

    local output
    output=$(make help 2>&1)

    assert_output_contains "$output" "agents-config" "Help shows agents-config command"
}

# Test: JSON is valid after multiple operations
test_json_validity() {
    log_test "Testing JSON validity after modifications"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.config/amp"
    cat > "$SANDBOX_DIR/.config/amp/settings.json" <<'EOF'
{
  "amp.permissions": [
    {"pattern": "bash*", "action": "allow"}
  ],
  "amp.mcpServers": {
    "test": {"command": "test"}
  }
}
EOF

    # Run agents-config
    HOME="$SANDBOX_DIR" make agents-config >/dev/null 2>&1

    # Validate Amp JSON with jq
    if jq '.' "$SANDBOX_DIR/.config/amp/settings.json" >/dev/null 2>&1; then
        log_info "PASS: Amp output is valid JSON"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Amp output is not valid JSON"
        cat "$SANDBOX_DIR/.config/amp/settings.json"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local amp_json
    amp_json=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    assert_json_field "$amp_json" '."amp.mcpServers".test.command' "test" "Amp: MCP servers preserved"
}

# Main
main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Agents Config Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    # Setup
    setup_sandbox

    # Run tests
    test_jq_available
    test_help_shows_config
    test_config_creates_directories
    test_config_new_files
    test_config_preserve_existing
    test_config_idempotent
    test_json_validity

    # Summary
    print_summary
}

# Run main
main "$@"
