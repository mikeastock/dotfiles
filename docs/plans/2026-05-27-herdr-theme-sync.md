# Herdr Theme Sync Implementation Plan

> REQUIRED SUB-SKILL: Use superpowers:executing-plans skill to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a macOS helper that keeps Herdr's explicit theme in sync with system light/dark appearance.

**Architecture:** A focused shell script owns detection, config editing, reload, and optional LaunchAgent install/uninstall. The script updates both the live Herdr config and the dotfiles repo copy so runtime behavior and source of truth stay aligned. A shell test exercises config rewriting in a temp home/repo without touching real user state.

**Tech Stack:** Bash, macOS `osascript`, Python stdlib for TOML-ish line editing, `launchctl`/LaunchAgent plist, existing shell test helpers.

---

## File Structure

- Create `bin/herdr-theme-sync`: executable CLI for one-shot sync, watch mode, LaunchAgent install/uninstall, and status.
- Create `tests/test-herdr-theme-sync.sh`: sandbox test for light/dark config rewriting and no-Herdr reload behavior.
- Modify `tests/run-all.sh`: include the new test in the full suite.
- Modify `README.md`: document the helper briefly in the command table or relevant Herdr/config section.

## Behavior Details

- Dark mode maps to Herdr theme `catppuccin`.
- Light mode maps to Herdr theme `catppuccin-latte`.
- Default config paths:
  - live: `${HERDR_THEME_SYNC_LIVE_CONFIG:-$HOME/.config/herdr/config.toml}`
  - repo: `${HERDR_THEME_SYNC_REPO_CONFIG:-$REPO_ROOT/.config/herdr/config.toml}`
- The script must preserve unrelated config lines.
- If `[theme]` exists, replace or add `name = "..."` inside that section.
- If `[theme]` is missing, append a new `[theme]` section.
- Reload Herdr with `herdr server reload-config` only when `herdr` is on `PATH`; otherwise print a skip message and exit successfully.
- `watch` mode polls every 2 seconds by default and only rewrites/reloads when the desired theme changes.
- LaunchAgent label: `com.mikeastock.herdr-theme-sync`.

### Task 1: Add the sync script

**Files:**
- Create: `bin/herdr-theme-sync`

- [ ] **Step 1: Create the executable script**

Write `bin/herdr-theme-sync` with this structure:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DARK_THEME="${HERDR_THEME_SYNC_DARK_THEME:-catppuccin}"
LIGHT_THEME="${HERDR_THEME_SYNC_LIGHT_THEME:-catppuccin-latte}"
POLL_SECONDS="${HERDR_THEME_SYNC_POLL_SECONDS:-2}"
LIVE_CONFIG="${HERDR_THEME_SYNC_LIVE_CONFIG:-$HOME/.config/herdr/config.toml}"
REPO_CONFIG="${HERDR_THEME_SYNC_REPO_CONFIG:-$REPO_ROOT/.config/herdr/config.toml}"
LAUNCH_AGENT_LABEL="com.mikeastock.herdr-theme-sync"
LAUNCH_AGENT_PATH="$HOME/Library/LaunchAgents/$LAUNCH_AGENT_LABEL.plist"

usage() {
  cat <<'USAGE'
Usage: herdr-theme-sync [sync|watch|install-launchagent|uninstall-launchagent|status]

Commands:
  sync                  Detect macOS appearance, update Herdr config, reload Herdr (default)
  watch                 Poll appearance and sync when it changes
  install-launchagent   Install and start a macOS LaunchAgent running watch mode
  uninstall-launchagent Stop and remove the LaunchAgent
  status                Print detected appearance and target config paths
USAGE
}

is_dark_mode() {
  [[ "$(osascript -e 'tell application "System Events" to tell appearance preferences to return dark mode')" == "true" ]]
}

desired_theme() {
  if is_dark_mode; then
    printf '%s\n' "$DARK_THEME"
  else
    printf '%s\n' "$LIGHT_THEME"
  fi
}

set_theme_in_config() {
  local config_path="$1"
  local theme="$2"

  mkdir -p "$(dirname "$config_path")"
  [[ -f "$config_path" ]] || : > "$config_path"

  python3 - "$config_path" "$theme" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
theme = sys.argv[2]
lines = path.read_text().splitlines()

out = []
in_theme = False
saw_theme = False
wrote_name = False

for line in lines:
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        if in_theme and not wrote_name:
            out.append(f'name = "{theme}"')
            wrote_name = True
        in_theme = stripped == "[theme]"
        saw_theme = saw_theme or in_theme
        out.append(line)
        continue

    if in_theme and stripped.startswith("name") and "=" in stripped:
        out.append(f'name = "{theme}"')
        wrote_name = True
        continue

    out.append(line)

if in_theme and not wrote_name:
    out.append(f'name = "{theme}"')

if not saw_theme:
    if out and out[-1] != "":
        out.append("")
    out.extend(["[theme]", f'name = "{theme}"'])

path.write_text("\n".join(out) + "\n")
PY
}

reload_herdr() {
  if ! command -v herdr >/dev/null 2>&1; then
    echo "herdr not found on PATH; skipped reload"
    return 0
  fi

  herdr server reload-config >/dev/null || echo "herdr reload failed; config was still updated" >&2
}

sync_once() {
  local theme
  theme="$(desired_theme)"
  set_theme_in_config "$LIVE_CONFIG" "$theme"
  if [[ "$REPO_CONFIG" != "$LIVE_CONFIG" ]]; then
    set_theme_in_config "$REPO_CONFIG" "$theme"
  fi
  reload_herdr
  echo "Herdr theme set to $theme"
}

watch_theme() {
  local last=""
  while true; do
    current="$(desired_theme)"
    if [[ "$current" != "$last" ]]; then
      set_theme_in_config "$LIVE_CONFIG" "$current"
      if [[ "$REPO_CONFIG" != "$LIVE_CONFIG" ]]; then
        set_theme_in_config "$REPO_CONFIG" "$current"
      fi
      reload_herdr
      echo "Herdr theme set to $current"
      last="$current"
    fi
    sleep "$POLL_SECONDS"
  done
}

install_launchagent() {
  mkdir -p "$(dirname "$LAUNCH_AGENT_PATH")"
  cat > "$LAUNCH_AGENT_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LAUNCH_AGENT_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$SCRIPT_DIR/herdr-theme-sync</string>
    <string>watch</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$HOME/Library/Logs/herdr-theme-sync.log</string>
  <key>StandardErrorPath</key>
  <string>$HOME/Library/Logs/herdr-theme-sync.log</string>
</dict>
</plist>
PLIST
  launchctl unload "$LAUNCH_AGENT_PATH" >/dev/null 2>&1 || true
  launchctl load "$LAUNCH_AGENT_PATH"
  echo "Installed $LAUNCH_AGENT_PATH"
}

uninstall_launchagent() {
  launchctl unload "$LAUNCH_AGENT_PATH" >/dev/null 2>&1 || true
  rm -f "$LAUNCH_AGENT_PATH"
  echo "Removed $LAUNCH_AGENT_PATH"
}

print_status() {
  echo "desired_theme=$(desired_theme)"
  echo "live_config=$LIVE_CONFIG"
  echo "repo_config=$REPO_CONFIG"
  echo "launch_agent=$LAUNCH_AGENT_PATH"
}

command="${1:-sync}"
case "$command" in
  sync) sync_once ;;
  watch) watch_theme ;;
  install-launchagent) install_launchagent ;;
  uninstall-launchagent) uninstall_launchagent ;;
  status) print_status ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
```

- [ ] **Step 2: Make it executable**

Run:

```bash
chmod +x bin/herdr-theme-sync
```

Expected: command succeeds.

### Task 2: Add tests

**Files:**
- Create: `tests/test-herdr-theme-sync.sh`
- Modify: `tests/run-all.sh`

- [ ] **Step 1: Create a sandbox test script**

Create `tests/test-herdr-theme-sync.sh` that:

```bash
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
assert_file_contains "$LIVE_CONFIG" 'name = "catppuccin"' "Live config dark theme updated"
assert_file_contains "$REPO_CONFIG" 'name = "catppuccin"' "Repo config dark theme appended"
assert_file_contains "$LIVE_CONFIG" 'accent = "cyan"' "Unrelated live config preserved"

echo false > "$OSASCRIPT_RESULT_FILE"
output=$("$SCRIPT" sync 2>&1)
assert_output_contains "$output" "Herdr theme set to catppuccin-latte" "Light mode selects catppuccin-latte"
assert_file_contains "$LIVE_CONFIG" 'name = "catppuccin-latte"' "Live config light theme updated"
assert_file_contains "$REPO_CONFIG" 'name = "catppuccin-latte"' "Repo config light theme updated"

print_summary
```

- [ ] **Step 2: Wire it into the full suite**

Modify `tests/run-all.sh` to include:

```bash
run_test "Herdr theme sync" "tests/test-herdr-theme-sync.sh"
```

Place it near other config/install tests.

### Task 3: Document usage

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add usage docs**

Add a short section or command row:

```markdown
### Herdr light/dark theme sync

Ghostty can auto-switch themes itself, but Herdr only supports one active theme. Use:

```bash
bin/herdr-theme-sync sync
```

To keep Herdr synced automatically on macOS:

```bash
bin/herdr-theme-sync install-launchagent
```

Uninstall with:

```bash
bin/herdr-theme-sync uninstall-launchagent
```
```

### Task 4: Verify and install

**Files:**
- Runtime updates: `~/.config/herdr/config.toml`
- Runtime optional: `~/Library/LaunchAgents/com.mikeastock.herdr-theme-sync.plist`

- [ ] **Step 1: Run the focused test**

Run:

```bash
./tests/test-herdr-theme-sync.sh
```

Expected: all checks pass.

- [ ] **Step 2: Run the script once for real**

Run:

```bash
bin/herdr-theme-sync sync
```

Expected: prints the selected Herdr theme and reloads Herdr if a server is running.

- [ ] **Step 3: Optionally install the LaunchAgent**

Run only if the user wants automatic background sync:

```bash
bin/herdr-theme-sync install-launchagent
```

Expected: plist is written to `~/Library/LaunchAgents/com.mikeastock.herdr-theme-sync.plist` and loaded.

- [ ] **Step 4: Commit**

Run:

```bash
git add bin/herdr-theme-sync tests/test-herdr-theme-sync.sh tests/run-all.sh README.md .config/herdr/config.toml
git commit -m "feat(herdr): sync theme with macOS appearance"
```
