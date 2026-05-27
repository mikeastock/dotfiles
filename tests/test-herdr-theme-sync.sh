#!/usr/bin/env bash

source "$(dirname "$0")/test-helpers.sh"
trap cleanup EXIT

setup_sandbox

log_info "Testing Herdr theme sync..."

SCRIPT="$PROJECT_DIR/bin/herdr-theme-sync"
LIVE_CONFIG="$SANDBOX_DIR/.config/herdr/config.toml"
REPO_CONFIG="$SANDBOX_DIR/repo-herdr-config.toml"
FAKE_BIN="$SANDBOX_DIR/bin"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/osascript" <<'EOF'
#!/usr/bin/env bash
cat "$OSASCRIPT_RESULT_FILE"
EOF
chmod +x "$FAKE_BIN/osascript"

export PATH="$FAKE_BIN:$PATH"
export OSASCRIPT_RESULT_FILE="$SANDBOX_DIR/appearance"
export HERDR_THEME_SYNC_LIVE_CONFIG="$LIVE_CONFIG"
export HERDR_THEME_SYNC_REPO_CONFIG="$REPO_CONFIG"
export HERDR_THEME_SYNC_SKIP_RELOAD=1

mkdir -p "$(dirname "$LIVE_CONFIG")"
cat > "$LIVE_CONFIG" <<'EOF'
[theme]
# keep comment
name = "terminal"

[ui]
accent = "cyan"
EOF
cat > "$REPO_CONFIG" <<'EOF'
[ui]
accent = "cyan"
EOF

echo true > "$OSASCRIPT_RESULT_FILE"
output=$("$SCRIPT" sync 2>&1)
assert_output_contains "$output" "Herdr theme set to catppuccin" "Dark mode selects catppuccin"
assert_success "Live config dark theme updated" rg -Fq 'name = "catppuccin"' "$LIVE_CONFIG"
assert_success "Repo config dark theme appended" rg -Fq 'name = "catppuccin"' "$REPO_CONFIG"
assert_success "Unrelated live config preserved" rg -Fq 'accent = "cyan"' "$LIVE_CONFIG"

echo false > "$OSASCRIPT_RESULT_FILE"
output=$("$SCRIPT" sync 2>&1)
assert_output_contains "$output" "Herdr theme set to catppuccin-latte" "Light mode selects catppuccin-latte"
assert_success "Live config light theme updated" rg -Fq 'name = "catppuccin-latte"' "$LIVE_CONFIG"
assert_success "Repo config light theme updated" rg -Fq 'name = "catppuccin-latte"' "$REPO_CONFIG"

print_summary
