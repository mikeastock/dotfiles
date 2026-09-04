#!/usr/bin/env bash
#
# Test script for install-configs command
# Tests installation of all agent configurations (Amp, Codex, OpenCode, Pi, AGENTS.md)
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
    rm -rf "$SANDBOX_DIR/.config/opencode"
    rm -rf "$SANDBOX_DIR/.codex"
    rm -rf "$SANDBOX_DIR/.pi"

    HOME="$SANDBOX_DIR" make install-configs >/dev/null

    local opencode_json
    opencode_json=$(cat "$SANDBOX_DIR/.config/opencode/opencode.jsonc")
    assert_json_field "$opencode_json" '.model' "meta/muse-spark-1.2" "OpenCode: default model is Muse Spark 1.2"
    assert_json_field "$opencode_json" '.small_model' "runinfra/nemotron-3-5-lightning-30b" "OpenCode: small model is RunInfra Nemotron"
    assert_json_field "$opencode_json" '.provider.meta.options.baseURL' "https://api.meta.ai/v1" "OpenCode: Meta Model API base URL is set"
    assert_json_field "$opencode_json" '.provider.meta.options.apiKey' "{env:MODEL_API_KEY}" "OpenCode: Meta apiKey reads MODEL_API_KEY"
    assert_json_field "$opencode_json" '.provider.meta.models["muse-spark-1.3"].name' "Muse Spark 1.3" "OpenCode: Muse Spark 1.3 model is registered"
    assert_json_field "$opencode_json" '.provider.meta.models["muse-spark-1.2"].name' "Muse Spark 1.2" "OpenCode: Muse Spark 1.2 model is registered"
    assert_json_field "$opencode_json" '.provider.runinfra.options.baseURL' "https://api.runinfra.ai/v1" "OpenCode: RunInfra base URL is set"
    assert_success "Codex receives the managed AGENTS.md" cmp "$PROJECT_DIR/configs/AGENTS.md" "$SANDBOX_DIR/.codex/AGENTS.md"
    assert_success "Pi receives the managed AGENTS.md" cmp "$PROJECT_DIR/configs/AGENTS.md" "$SANDBOX_DIR/.pi/agent/AGENTS.md"

    local pi_models_json
    pi_models_json=$(cat "$SANDBOX_DIR/.pi/agent/models.json")
    assert_json_field "$pi_models_json" '.providers.meta.models[0].name' "Muse Spark 1.3" "Pi: Muse Spark 1.3 model is registered"
    assert_json_field "$pi_models_json" '.providers.google.models[0].name' "Gemini 3.8 Flash" "Pi: Gemini 3.8 Flash model is registered"
    assert_json_field "$pi_models_json" '.providers["novita-ai"].models[0].name' "Kimi K2.7 Code (Novita)" "Pi: Kimi K2.7 Code model is registered"

    local pi_settings_json
    pi_settings_json=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")
    assert_json_field "$pi_settings_json" '.enabledModels[4]' "google/gemini-3.8-flash" "Pi: Gemini 3.8 Flash is in enabledModels"

    local amp_json
    amp_json=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    assert_json_field "$amp_json" '."amp.skills.path"' "~/.config/agents/skills" "Amp: skills.path comes from amp-configs"
    assert_json_field "$amp_json" '."amp.terminal.copyOnSelect"' "false" "Amp: terminal copy-on-select comes from amp-configs"
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
    assert_output_contains "$codex_rules" 'pattern = ["mise", ["run", "exec"], "terraform", "--", "apply"]' "Codex rules prompt for mise Terraform apply"
    assert_output_contains "$codex_rules" '-chdir=regions/us-west-2-lax-devbox' "Codex rules prompt for chdir Terraform apply"
    assert_output_contains "$codex_rules" 'decision = "prompt"' "Codex Terraform rules request prompt approval"
}

# Test: Codex config preserves runtime-managed hook trust state
test_codex_preserve_hook_trust() {
    log_test "Testing Codex hook trust state is preserved"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.codex"
    mkdir -p "$SANDBOX_DIR/.codex"
    cat > "$SANDBOX_DIR/.codex/config.toml" <<'EOF'
model = "old-model"

[hooks.state]

[hooks.state."/home/test/.codex/hooks.json:pre_tool_use:0:0"]
enabled = false
trusted_hash = "sha256:trusted-hook"
EOF

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    local codex_config
    codex_config=$(cat "$SANDBOX_DIR/.codex/config.toml")
    assert_output_contains "$codex_config" 'model = "gpt-5.6-sol"' "Codex managed config is refreshed"
    assert_output_contains "$codex_config" 'trusted_hash = "sha256:trusted-hook"' "Codex hook trust hash is preserved"
    assert_output_contains "$codex_config" 'enabled = false' "Codex hook enabled state is preserved"
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

    HOME="$SANDBOX_DIR" make install-configs >/dev/null

    local amp_json
    amp_json=$(cat "$SANDBOX_DIR/.config/amp/settings.json")

    # Check new settings were added
    assert_json_field "$amp_json" '."amp.skills.path"' "~/.config/agents/skills" "Amp: skills.path is set"
    assert_json_field "$amp_json" '."amp.terminal.copyOnSelect"' "false" "Amp: managed terminal setting is set"

    # Check existing settings were preserved
    assert_json_field "$amp_json" '."amp.dangerouslyAllowAll"' "true" "Amp: dangerouslyAllowAll preserved"
    assert_json_field "$amp_json" '."amp.showCosts"' "false" "Amp: showCosts preserved"
}

# Test: Amp config accepts trailing commas from settings editors
test_amp_trailing_commas() {
    log_test "Testing 'make install-configs' accepts trailing commas in Amp settings"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.config/amp"
    cat > "$SANDBOX_DIR/.config/amp/settings.json" <<'EOF'
{
  "amp.dangerouslyAllowAll": true,
  "amp.permissions": [
    {"pattern": "bash*,}", "action": "allow"},
  ],
}
EOF

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    local amp_json
    amp_json=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    assert_json_field "$amp_json" '."amp.dangerouslyAllowAll"' "true" "Amp: trailing-comma setting is preserved"
    assert_json_field "$amp_json" '."amp.permissions"[0].pattern' "bash*,}" "Amp: commas inside strings are preserved"
    assert_json_field "$amp_json" '."amp.skills.path"' "~/.config/agents/skills" "Amp: managed setting is merged"
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

# Test: OpenCode config overlays RunInfra while preserving other providers
test_opencode_preserve_existing_providers() {
    log_test "Testing 'make install-configs' preserves existing OpenCode providers"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.config/opencode"
    cat > "$SANDBOX_DIR/.config/opencode/opencode.jsonc" <<'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "model": "modal/existing-endpoint",
  "provider": {
    "modal": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Modal",
      "options": {
        "baseURL": "https://inference.example.modal.direct/v1"
      }
    }
  }
}
EOF

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    local opencode_json
    opencode_json=$(cat "$SANDBOX_DIR/.config/opencode/opencode.jsonc")
    assert_json_field "$opencode_json" '.model' "meta/muse-spark-1.2" "OpenCode: managed default model wins"
    assert_json_field "$opencode_json" '.provider.meta.name' "Meta Model API" "OpenCode: Meta Model API provider is installed"
    assert_json_field "$opencode_json" '.provider.runinfra.name' "RunInfra" "OpenCode: RunInfra provider is installed"
    assert_json_field "$opencode_json" '.provider.modal.name' "Modal" "OpenCode: existing Modal provider is preserved"
    assert_json_field "$opencode_json" '.provider.modal.options.baseURL' "https://inference.example.modal.direct/v1" "OpenCode: existing provider options are preserved"
}

# Test: OpenCode keeps a locally hardcoded RunInfra apiKey across install
test_opencode_preserve_runinfra_api_key() {
    log_test "Testing 'make install-configs' preserves a hardcoded OpenCode RunInfra apiKey"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.config/opencode"
    cat > "$SANDBOX_DIR/.config/opencode/opencode.jsonc" <<'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "runinfra": {
      "options": {
        "apiKey": "rp_localhardcodedkey000000000000000000000"
      }
    }
  }
}
EOF

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1

    local opencode_json
    opencode_json=$(cat "$SANDBOX_DIR/.config/opencode/opencode.jsonc")
    assert_json_field "$opencode_json" '.provider.runinfra.options.apiKey' "rp_localhardcodedkey000000000000000000000" "OpenCode: hardcoded RunInfra apiKey is preserved"
    assert_json_field "$opencode_json" '.provider.runinfra.options.baseURL' "https://api.runinfra.ai/v1" "OpenCode: managed RunInfra options are still merged"
    assert_json_field "$opencode_json" '.provider.runinfra.name' "RunInfra" "OpenCode: managed RunInfra provider metadata is installed"
}

# Test: install-configs is idempotent (running twice has same result)
test_config_idempotent() {
    log_test "Testing 'make install-configs' is idempotent"
    cd "$PROJECT_DIR"

    # Ensure fresh start
    rm -rf "$SANDBOX_DIR/.config/amp"
    rm -rf "$SANDBOX_DIR/.config/opencode"
    rm -rf "$SANDBOX_DIR/.codex"
    rm -rf "$SANDBOX_DIR/.pi"

    # Run install-configs twice
    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1
    local amp_first codex_first codex_rules_first opencode_first pi_first
    amp_first=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    codex_first=$(cat "$SANDBOX_DIR/.codex/config.toml")
    codex_rules_first=$(cat "$SANDBOX_DIR/.codex/rules/default.rules")
    opencode_first=$(cat "$SANDBOX_DIR/.config/opencode/opencode.jsonc")
    pi_first=$(cat "$SANDBOX_DIR/.pi/agent/settings.json")

    HOME="$SANDBOX_DIR" make install-configs >/dev/null 2>&1
    local amp_second codex_second codex_rules_second opencode_second pi_second
    amp_second=$(cat "$SANDBOX_DIR/.config/amp/settings.json")
    codex_second=$(cat "$SANDBOX_DIR/.codex/config.toml")
    codex_rules_second=$(cat "$SANDBOX_DIR/.codex/rules/default.rules")
    opencode_second=$(cat "$SANDBOX_DIR/.config/opencode/opencode.jsonc")
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
    if [ "$opencode_first" != "$opencode_second" ]; then
        log_error "FAIL: OpenCode results differ between runs"
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

# Main
main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Install Configs Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    # Setup
    setup_sandbox

    # Run tests
    test_config_new_files
    test_codex_terraform_apply_rules
    test_codex_preserve_hook_trust
    test_amp_preserve_existing
    test_amp_trailing_commas
    test_pi_preserve_changelog_version
    test_opencode_preserve_existing_providers
    test_opencode_preserve_runinfra_api_key
    test_config_idempotent

    # Summary
    print_summary
}

# Run main
main "$@"
