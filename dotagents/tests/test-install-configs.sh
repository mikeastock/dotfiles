#!/usr/bin/env bash
#
# Test script for install-configs command
# Tests installation of all agent configurations (Amp, Codex, Pi, AGENTS.md)
#
# Usage: ./tests/test-install-configs.sh
#

# Source shared test helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

# Set trap for cleanup on exit
trap cleanup EXIT

# Test: install-configs with empty/new settings files
test_config_new_files() {
    log_test "Testing 'make install-configs' with new settings files"
    cd "$PROJECT_DIR"

    # Ensure the settings files don't exist
    rm -rf "$SANDBOX_DIR/.config/amp"
    rm -rf "$SANDBOX_DIR/.codex"
    rm -rf "$SANDBOX_DIR/.pi"

    # Run install-configs with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install-configs 2>&1)

    assert_output_contains "$output" "Installing Amp config" "Shows Amp configuration"
    assert_output_contains "$output" "Installing Codex config" "Shows Codex configuration"
    assert_output_contains "$output" "Installing Pi settings" "Shows Pi configuration"
    assert_output_contains "$output" "Installing global AGENTS.md" "Shows AGENTS.md installation"

    # Verify all files were created
    assert_file_exists "$SANDBOX_DIR/.config/amp/settings.json" "Amp settings file was created"
    assert_file_exists "$SANDBOX_DIR/.codex/config.toml" "Codex config file was created"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/settings.json" "Pi settings file was created"
    assert_file_exists "$SANDBOX_DIR/.codex/AGENTS.md" "Codex AGENTS.md was created"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/AGENTS.md" "Pi AGENTS.md was created"
}

# Test: Amp config preserves existing settings
test_amp_preserve_existing() {
    log_test "Testing 'make install-configs' preserves existing Amp settings"
    cd "$PROJECT_DIR"

    # Create Amp settings file with existing settings
    mkdir -p "$SANDBOX_DIR/.config/amp"
    cat > "$SANDBOX_DIR/.config/amp/settings.json" <<'EOF'
{
  "amp.dangerouslyAllowAll": true,
  "amp.showCosts": false
}
EOF

    # Run install-configs with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" make install-configs 2>&1)

    assert_output_contains "$output" "Installing Amp config" "Shows Amp configuration"

    # Verify Amp JSON content
    local amp_json
    amp_json=$(cat "$SANDBOX_DIR/.config/amp/settings.json")

    # Check new settings were added
    assert_json_field "$amp_json" '."amp.skills.path"' "~/.config/agents/skills" "Amp: skills.path is set"

    # Check existing settings were preserved
    assert_json_field "$amp_json" '."amp.dangerouslyAllowAll"' "true" "Amp: dangerouslyAllowAll preserved"
    assert_json_field "$amp_json" '."amp.showCosts"' "false" "Amp: showCosts preserved"
}

# Test: install-configs is idempotent (running twice has same result)
test_config_idempotent() {
    log_test "Testing 'make install-configs' is idempotent"
    cd "$PROJECT_DIR"

    # Ensure fresh start
    rm -rf "$SANDBOX_DIR/.config/amp"
    rm -rf "$SANDBOX_DIR/.codex"
    rm -rf "$SANDBOX_DIR/.pi"

    # Run install-configs twice
    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1
    local amp_first codex_first pi_first
    amp_first=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    codex_first=$(cat "$SANDBOX_DIR/.codex/config.toml")
    pi_first=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1
    local amp_second codex_second pi_second
    amp_second=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    codex_second=$(cat "$SANDBOX_DIR/.codex/config.toml")
    pi_second=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    # Content should be identical
    local all_match=true
    if [ "$amp_first" != "$amp_second" ]; then
        log_error "FAIL: Amp results differ between runs"
        all_match=false
    fi
    if [ "$codex_first" != "$codex_second" ]; then
        log_error "FAIL: Codex results differ between runs"
        all_match=false
    fi
    if [ "$pi_first" != "$pi_second" ]; then
        log_error "FAIL: Pi results differ between runs"
        all_match=false
    fi

    if [ "$all_match" = true ]; then
        log_info "PASS: Running install-configs twice produces identical results"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: install-configs creates directories if needed
test_config_creates_directories() {
    log_test "Testing 'make install-configs' creates config directories"
    cd "$PROJECT_DIR"

    # Remove the config directories
    rm -rf "$SANDBOX_DIR/.config/amp"
    rm -rf "$SANDBOX_DIR/.codex"
    rm -rf "$SANDBOX_DIR/.pi"

    # Run install-configs
    local output
    output=$(HOME="$SANDBOX_DIR" make install-configs 2>&1)

    assert_dir_exists "$SANDBOX_DIR/.config/amp" ".config/amp directory was created"
    assert_dir_exists "$SANDBOX_DIR/.codex" ".codex directory was created"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent" ".pi/agent directory was created"
}

# Test: install-configs help is visible
test_help_shows_config() {
    log_test "Testing 'make help' shows install-configs"
    cd "$PROJECT_DIR"

    local output
    output=$(make help 2>&1)

    assert_output_contains "$output" "install-configs" "Help shows install-configs command"
}

# Test: Amp JSON is valid after multiple operations
test_amp_json_validity() {
    log_test "Testing Amp JSON validity after modifications"
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

    # Run install-configs
    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    # Validate Amp JSON with jq (if available) or Python
    if command -v jq >/dev/null 2>&1; then
        if jq '.' "$SANDBOX_DIR/.config/amp/settings.json" >/dev/null 2>&1; then
            log_info "PASS: Amp output is valid JSON"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_error "FAIL: Amp output is not valid JSON"
            cat "$SANDBOX_DIR/.config/amp/settings.json"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        # Use Python to validate JSON
        if python3 -c "import json; json.load(open('$SANDBOX_DIR/.config/amp/settings.json'))" 2>/dev/null; then
            log_info "PASS: Amp output is valid JSON"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_error "FAIL: Amp output is not valid JSON"
            cat "$SANDBOX_DIR/.config/amp/settings.json"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
}

# Main
main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Install Configs Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    # Setup
    setup_sandbox

    # Run tests
    test_help_shows_config
    test_config_creates_directories
    test_config_new_files
    test_amp_preserve_existing
    test_config_idempotent
    test_amp_json_validity

    # Summary
    print_summary
}

# Run main
main "$@"
