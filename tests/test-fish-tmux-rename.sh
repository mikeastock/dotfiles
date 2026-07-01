#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/test-helpers.sh"

trap cleanup EXIT

setup_sandbox

fake_bin="$SANDBOX_DIR/bin"
mkdir -p "$fake_bin"

cat > "$fake_bin/tmux" <<'TMUX'
#!/usr/bin/env bash
if [ "${1:-}" = "rename-window" ]; then
  printf '%s\n' "$*" >> "$TMUX_RENAME_LOG"
  exit 0
fi

if [ "${1:-}" = "display-message" ]; then
  printf '@1\n'
  exit 0
fi

if [ "${1:-}" = "list-windows" ]; then
  printf '@1\n'
  exit 0
fi

exit 0
TMUX
chmod +x "$fake_bin/tmux"

log_test "Testing tmux window rename only runs from trw"
rename_log="$SANDBOX_DIR/tmux-renames.log"
fish_home="$SANDBOX_DIR/home"
mkdir -p "$fish_home" "$SANDBOX_DIR/xdg-config" "$SANDBOX_DIR/xdg-data" "$SANDBOX_DIR/xdg-cache"

output=$(
  env \
    HOME="$fish_home" \
    XDG_CONFIG_HOME="$SANDBOX_DIR/xdg-config" \
    XDG_DATA_HOME="$SANDBOX_DIR/xdg-data" \
    XDG_CACHE_HOME="$SANDBOX_DIR/xdg-cache" \
    PATH="$fake_bin:$PATH" \
    TMUX_RENAME_LOG="$rename_log" \
    fish --no-config --private -c '
      set start_pwd "$PWD"
      source .config/fish/config.fish
      set -gx PATH "'$fake_bin'" $PATH
      set -gx TMUX /tmp/test-tmux
      set -gx TMUX_PANE %1
      cd /tmp
      true
      test -e "$TMUX_RENAME_LOG"; and echo "renamed_after_cd_or_command"
      cd "$start_pwd"
      trw
      test -e "$TMUX_RENAME_LOG"; and echo "renamed_after_trw"
    '
)

assert_output_not_contains "$output" "renamed_after_cd_or_command" "Changing directories and running commands do not rename tmux windows"
assert_output_contains "$output" "renamed_after_trw" "trw manually renames tmux windows"

rename_output=$(cat "$rename_log")
assert_output_contains "$rename_output" "rename-window -t %1" "trw targets the current tmux pane"

print_summary
