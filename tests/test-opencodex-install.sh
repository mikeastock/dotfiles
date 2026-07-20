#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

setup_fake_mise() {
    local fake_bin="$SANDBOX_DIR/bin"
    mkdir -p "$fake_bin"

    cat > "$fake_bin/mise" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s|ignore=%s|allow=%s\n' "$*" "${NPM_CONFIG_IGNORE_SCRIPTS:-}" "${NPM_CONFIG_ALLOW_SCRIPTS:-}" >> "$TEST_LOG_DIR/mise.log"
install_root="$HOME/.local/share/mise/installs/npm-bitkyc08-opencodex/2.7.27"
case "$1" in
  use)
    ;;
  install)
    mkdir -p "$install_root/bin"
    cat > "$install_root/bin/ocx" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s|key_length=%s\n' "$*" "${#XAI_API_KEY}" >> "$TEST_LOG_DIR/ocx.log"
case "$1" in
  --version)
    printf 'opencodex 2.7.27\n'
    ;;
  service)
    mkdir -p "$HOME/.opencodex"
    printf '{"pid":123,"port":10100,"hostname":"127.0.0.1"}\n' > "$HOME/.opencodex/runtime-port.json"
    ;;
  health)
    printf '{"ok":true}\n'
    ;;
  *)
    exit 1
    ;;
esac
SCRIPT
    chmod +x "$install_root/bin/ocx"
    ;;
  which)
    printf '%s\n' "$install_root/bin/ocx"
    ;;
  *)
    exit 1
    ;;
esac
EOF
    chmod +x "$fake_bin/mise"
    export PATH="$fake_bin:$PATH"
}

test_installs_daemon() {
    log_test "Testing managed OpenCodex daemon installation"
    export TEST_LOG_DIR="$SANDBOX_DIR/logs"
    mkdir -p "$TEST_LOG_DIR"
    printf 'XAI_API_KEY=test-xai-key\n' > "$SANDBOX_DIR/.env"
    mkdir -p "$SANDBOX_DIR/.config/systemd/user/opencodex.service.d"
    printf '[Service]\nEnvironmentFile=%%h/.env\n' > "$SANDBOX_DIR/.config/systemd/user/opencodex.service.d/environment.conf"

    local output
    output=$(HOME="$SANDBOX_DIR" TEST_LOG_DIR="$TEST_LOG_DIR" make -C "$PROJECT_DIR" install-opencodex 2>&1)

    local mise_log ocx_log config drop_in
    mise_log=$(cat "$TEST_LOG_DIR/mise.log")
    ocx_log=$(cat "$TEST_LOG_DIR/ocx.log")
    config=$(cat "$SANDBOX_DIR/.opencodex/config.json")
    drop_in=$(cat "$SANDBOX_DIR/.config/systemd/user/opencodex-proxy.service.d/environment.conf")

    assert_output_contains "$mise_log" 'use -g npm:@bitkyc08/opencodex@2.7.27' "Installer pins the OpenCodex package"
    assert_output_contains "$mise_log" 'ignore=false|allow=bun' "Installer permits only the bundled Bun lifecycle script"
    assert_output_contains "$ocx_log" 'service install|key_length=12' "Installer configures the native OpenCodex service"
    assert_output_contains "$config" '"defaultProvider": "openai"' "Managed config keeps vanilla OpenAI as the default provider"
    assert_output_contains "$config" '"authMode": "forward"' "Managed OpenAI provider forwards the Codex login"
    assert_output_contains "$config" '"apiKey": "${XAI_API_KEY}"' "Managed config references the xAI environment variable"
    assert_output_contains "$config" '"selectedModels": ["grok-4.5"]' "Managed config exposes optional Grok 4.5 only"
    assert_output_contains "$config" '"openaiProviderTierVersion": 2' "Managed config is already on the current OpenAI tier schema"
    assert_output_contains "$config" '"websockets": true' "Managed daemon enables Codex Responses WebSockets"
    assert_output_contains "$drop_in" 'EnvironmentFile=%h/.env' "Systemd service loads the managed dotenv file"
    assert_output_contains "$drop_in" 'ExecStart=%h/.local/share/mise/installs/npm-bitkyc08-opencodex/2.7.27/bin/ocx start' "Systemd service bypasses OpenCodex's incompatible login shell"
    assert_file_not_exists "$SANDBOX_DIR/.config/systemd/user/opencodex.service.d/environment.conf" "Installer removes the obsolete unit override"
    assert_output_contains "$output" 'Installed OpenCodex 2.7.27' "Installer waits for a healthy daemon"
}

main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}OpenCodex Daemon Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    setup_sandbox
    setup_fake_mise
    test_installs_daemon
    print_summary
}

main "$@"
