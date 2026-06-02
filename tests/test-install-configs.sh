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
    assert_output_contains "$output" "Installing Codex rules" "Shows Codex rules installation"
    assert_output_contains "$output" "Installing Codex hooks" "Shows Codex hooks installation"
    assert_output_contains "$output" "Installing Pi settings" "Shows Pi configuration"
    assert_output_contains "$output" "Installing global AGENTS.md" "Shows AGENTS.md installation"

    # Verify all files were created
    assert_file_exists "$SANDBOX_DIR/.config/amp/settings.json" "Amp settings file was created"
    assert_file_exists "$SANDBOX_DIR/.codex/config.toml" "Codex config file was created"
    assert_file_exists "$SANDBOX_DIR/.codex/rules/default.rules" "Codex default rules file was created"
    assert_file_exists "$SANDBOX_DIR/.codex/hooks.json" "Codex hooks file was created"
    assert_file_exists "$SANDBOX_DIR/.codex/hooks/terraform_apply_gate.py" "Codex Terraform hook was created"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/settings.json" "Pi settings file was created"
    assert_file_exists "$SANDBOX_DIR/.codex/AGENTS.md" "Codex AGENTS.md was created"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/AGENTS.md" "Pi AGENTS.md was created"
}

# Test: Codex config enables prompts and installs Terraform apply rules
test_codex_terraform_apply_rules() {
    log_test "Testing Codex Terraform apply rules"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.codex"

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    local codex_config codex_rules
    codex_config=$(cat "$SANDBOX_DIR/.codex/config.toml")
    codex_rules=$(cat "$SANDBOX_DIR/.codex/rules/default.rules")

    assert_output_contains "$codex_config" 'approval_policy = "on-request"' "Codex approval policy allows prompts"
    assert_output_contains "$codex_rules" 'pattern = ["terraform", "apply"]' "Codex rules prompt for terraform apply"
    assert_output_contains "$codex_rules" 'pattern = ["tf", "apply"]' "Codex rules prompt for tf apply"
    assert_output_contains "$codex_rules" 'decision = "prompt"' "Codex Terraform rules request prompt approval"
}

run_terraform_apply_hook() {
    local command="$1"
    jq -nc --arg command "$command" '{
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: {command: $command}
    }' | python3 "$PROJECT_DIR/configs/codex/hooks/terraform_apply_gate.py"
}

# Test: Codex Terraform apply hook blocks real apply command shapes
test_codex_terraform_apply_hook() {
    log_test "Testing Codex Terraform apply hook"
    cd "$PROJECT_DIR"

    local output
    output=$(run_terraform_apply_hook "mise run terraform -- apply tmp/taildrive.tfplan" 2>&1 || true)
    assert_output_contains "$output" '"permissionDecision": "deny"' "Hook blocks mise Terraform apply"
    assert_output_contains "$output" "Terraform apply blocked" "Hook explains blocked apply"

    output=$(run_terraform_apply_hook "mise run terraform -- -chdir=regions/us-west-2-lax-devbox apply plan.tfplan" 2>&1 || true)
    assert_output_contains "$output" '"permissionDecision": "deny"' "Hook blocks mise Terraform chdir apply"

    output=$(run_terraform_apply_hook "terraform -chdir=regions/us-west-2-lax-devbox apply plan.tfplan" 2>&1 || true)
    assert_output_contains "$output" '"permissionDecision": "deny"' "Hook blocks direct Terraform chdir apply"

    output=$(run_terraform_apply_hook "mise run terraform -- plan -out=tmp/taildrive.tfplan" 2>&1 || true)
    assert_equals "$output" "" "Hook allows Terraform plan"
}

# Test: Codex hooks are installed with the expected PreToolUse wiring
test_codex_hooks_install() {
    log_test "Testing Codex hooks install"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.codex"

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    local hooks_json
    hooks_json=$(cat "$SANDBOX_DIR/.codex/hooks.json")

    assert_file_exists "$SANDBOX_DIR/.codex/hooks/terraform_apply_gate.py" "Terraform apply hook script installed"
    assert_output_contains "$hooks_json" '"PreToolUse"' "Codex hooks include PreToolUse"
    assert_output_contains "$hooks_json" '"matcher": "Bash"' "Codex hooks match Bash"
    assert_output_contains "$hooks_json" 'terraform_apply_gate.py' "Codex hooks call Terraform apply gate"
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

# Test: Pi config preserves changelog version while updating managed settings
test_pi_preserve_changelog_version() {
    log_test "Testing 'make install-configs' preserves Pi changelog version"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.pi/agent"
    cat > "$SANDBOX_DIR/.pi/agent/settings.json" <<'EOF'
{
  "lastChangelogVersion": "9.9.9",
  "defaultProvider": "openai-codex",
  "defaultModel": "old-model",
  "enabledModels": [
    "old/provider"
  ],
  "customSetting": true
}
EOF

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    local pi_json
    pi_json=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    assert_json_field "$pi_json" '.lastChangelogVersion' "9.9.9" "Pi: lastChangelogVersion preserved"
    assert_json_field "$pi_json" '.customSetting' "true" "Pi: custom unmanaged settings preserved"
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
    local amp_first codex_first codex_rules_first codex_hooks_first pi_first
    amp_first=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    codex_first=$(cat "$SANDBOX_DIR/.codex/config.toml")
    codex_rules_first=$(cat "$SANDBOX_DIR/.codex/rules/default.rules")
    codex_hooks_first=$(cat "$SANDBOX_DIR/.codex/hooks.json")
    pi_first=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1
    local amp_second codex_second codex_rules_second codex_hooks_second pi_second
    amp_second=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    codex_second=$(cat "$SANDBOX_DIR/.codex/config.toml")
    codex_rules_second=$(cat "$SANDBOX_DIR/.codex/rules/default.rules")
    codex_hooks_second=$(cat "$SANDBOX_DIR/.codex/hooks.json")
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
    if [ "$codex_rules_first" != "$codex_rules_second" ]; then
        log_error "FAIL: Codex rules differ between runs"
        all_match=false
    fi
    if [ "$codex_hooks_first" != "$codex_hooks_second" ]; then
        log_error "FAIL: Codex hooks differ between runs"
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
    assert_dir_exists "$SANDBOX_DIR/.codex/rules" ".codex/rules directory was created"
    assert_dir_exists "$SANDBOX_DIR/.codex/hooks" ".codex/hooks directory was created"
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
    test_codex_terraform_apply_rules
    test_codex_terraform_apply_hook
    test_codex_hooks_install
    test_amp_preserve_existing
    test_pi_preserve_changelog_version
    test_config_idempotent
    test_amp_json_validity

    # Summary
    print_summary
}

# Run main
main "$@"
