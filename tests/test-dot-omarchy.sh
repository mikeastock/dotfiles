#!/usr/bin/env bash
#
# Tests for scripts/dot-omarchy.sh
#
# Usage: ./tests/test-dot-omarchy.sh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

INSTALLER="$PROJECT_DIR/scripts/dot-omarchy.sh"

assert_symlink() {
  local dest="$1"
  local expected="$2"
  local description="${3:-$dest -> $expected}"

  if [[ -L $dest && $(readlink "$dest") == "$expected" ]]; then
    log_info "PASS: $description"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    return 0
  fi

  log_error "FAIL: $description"
  if [[ -L $dest ]]; then
    log_error "  actual target: $(readlink "$dest")"
  elif [[ -e $dest ]]; then
    log_error "  not a symlink"
  else
    log_error "  missing"
  fi
  TESTS_FAILED=$((TESTS_FAILED + 1))
  return 1
}

reset_home() {
  rm -rf "$SANDBOX_DIR"
  SANDBOX_DIR=$(mktemp -d)
}

seed_omarchy_home() {
  reset_home
  mkdir -p \
    "$SANDBOX_DIR/.config/tmux" \
    "$SANDBOX_DIR/.config/alacritty" \
    "$SANDBOX_DIR/.config/ghostty" \
    "$SANDBOX_DIR/.config/hypr" \
    "$SANDBOX_DIR/.config/nvim" \
    "$SANDBOX_DIR/.config/fish" \
    "$SANDBOX_DIR/.config/herdr" \
    "$SANDBOX_DIR/.config/omarchy/hooks/post-update.d"

  printf '%s\n' "omarchy-tmux" >"$SANDBOX_DIR/.config/tmux/tmux.conf"
  printf '%s\n' "omarchy-alacritty" >"$SANDBOX_DIR/.config/alacritty/alacritty.toml"
  printf '%s\n' "omarchy-ghostty" >"$SANDBOX_DIR/.config/ghostty/config"
  printf '%s\n' "omarchy-starship" >"$SANDBOX_DIR/.config/starship.toml"
  printf '%s\n' "omarchy-hypr" >"$SANDBOX_DIR/.config/hypr/hyprland.lua"
  printf '%s\n' "omarchy-nvim" >"$SANDBOX_DIR/.config/nvim/init.lua"
  printf '%s\n' "omarchy-fish" >"$SANDBOX_DIR/.config/fish/config.fish"
  printf '%s\n' "omarchy-herdr" >"$SANDBOX_DIR/.config/herdr/config.toml"
  printf '%s\n' "omarchy bashrc" >"$SANDBOX_DIR/.bashrc"
}

run_installer() {
  HOME="$SANDBOX_DIR" \
    DOTFILES_BACKUP_DIR="$SANDBOX_DIR/backup" \
    DOTFILES_OMARCHY=1 \
    "$INSTALLER" --skip-packages --skip-tpm --skip-shell "$@"
}

test_refuses_non_omarchy() {
  log_test "Testing installer refuses a non-Omarchy machine"
  local output status
  set +e
  output="$(HOME="$SANDBOX_DIR" DOTFILES_OMARCHY=0 "$INSTALLER" --skip-packages --skip-tpm --skip-shell 2>&1)"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_info "PASS: installer exits on a non-Omarchy machine"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_error "FAIL: installer ran on a non-Omarchy machine"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
  assert_output_contains "$output" "for Omarchy Linux" "Refusal names the Omarchy-only target"
}

test_installs_around_omarchy_defaults() {
  log_test "Testing installer claims personal files and leaves Omarchy terminals"
  seed_omarchy_home

  run_installer >/dev/null

  assert_symlink "$SANDBOX_DIR/.tmux.conf" "$PROJECT_DIR/.tmux.conf" "Home tmux.conf is the dotfiles link"
  assert_symlink "$SANDBOX_DIR/.config/hypr" "$PROJECT_DIR/.config/hypr" "Hyprland config is claimed"
  assert_symlink "$SANDBOX_DIR/.config/nvim/init.lua" "$PROJECT_DIR/.config/nvim/init.lua" "nvim init.lua is claimed"
  assert_symlink "$SANDBOX_DIR/.config/fish/config.fish" "$PROJECT_DIR/.config/fish/config.fish" "fish config is claimed"
  assert_symlink "$SANDBOX_DIR/.config/herdr/config.toml" "$PROJECT_DIR/.config/herdr/config.toml" "herdr config is claimed"
  assert_symlink "$SANDBOX_DIR/.local/bin/clipboard-copy" "$PROJECT_DIR/bin/clipboard-copy" "local bin scripts are linked"

  assert_file_not_exists "$SANDBOX_DIR/.config/tmux/tmux.conf" "Omarchy XDG tmux.conf is removed"
  assert_symlink \
    "$SANDBOX_DIR/.config/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook" \
    "$PROJECT_DIR/configs/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook" \
    "Post-update hook is installed from the repo"

  assert_output_contains "$(<"$SANDBOX_DIR/.config/alacritty/alacritty.toml")" "omarchy-alacritty" "Alacritty stays Omarchy-owned"
  assert_output_contains "$(<"$SANDBOX_DIR/.config/ghostty/config")" "omarchy-ghostty" "Ghostty stays Omarchy-owned"
  assert_output_contains "$(<"$SANDBOX_DIR/.config/starship.toml")" "omarchy-starship" "Starship stays Omarchy-owned"
  if [[ ! -L $SANDBOX_DIR/.config/alacritty && ! -L $SANDBOX_DIR/.config/ghostty && ! -L $SANDBOX_DIR/.config/starship.toml ]]; then
    log_info "PASS: Omarchy terminal configs were not converted to symlinks"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_error "FAIL: Omarchy terminal configs were claimed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi

  assert_file_exists "$SANDBOX_DIR/backup/hypr/hyprland.lua" "Existing Hyprland dir was backed up"
  assert_file_exists "$SANDBOX_DIR/backup/nvim-init.lua" "Existing nvim init.lua was backed up"
  assert_output_contains "$(<"$SANDBOX_DIR/backup/nvim-init.lua")" "omarchy-nvim" "nvim backup keeps the Omarchy file"
  assert_output_contains "$(<"$SANDBOX_DIR/.bashrc")" "# From personal dotfiles" "bashrc receives the dotfiles snippet"
  assert_output_contains "$(<"$SANDBOX_DIR/.bashrc")" 'alias wk="work"' "bashrc gets the wk alias"
}

test_is_idempotent() {
  log_test "Testing a second install does not rewrite already-claimed links"
  seed_omarchy_home
  run_installer >/dev/null
  rm -rf "$SANDBOX_DIR/backup"
  mkdir -p "$SANDBOX_DIR/backup"

  run_installer >/dev/null

  assert_symlink "$SANDBOX_DIR/.tmux.conf" "$PROJECT_DIR/.tmux.conf" "Second run keeps the tmux.conf link"
  if [[ -z $(ls -A "$SANDBOX_DIR/backup") ]]; then
    log_info "PASS: Second run created no new backups"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_error "FAIL: Second run wrote unexpected backups"
    ls -A "$SANDBOX_DIR/backup"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi

  local marker_count
  marker_count="$(rg --fixed-strings --count -- '# From personal dotfiles' "$SANDBOX_DIR/.bashrc")"
  if [[ $marker_count == 1 ]]; then
    log_info "PASS: bashrc snippet appears once"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_error "FAIL: bashrc snippet count was $marker_count"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

test_replaces_wrong_hook_file() {
  log_test "Testing a regular Omarchy hook file is replaced with the repo symlink"
  seed_omarchy_home
  printf '%s\n' "old hook" >"$SANDBOX_DIR/.config/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook"

  run_installer >/dev/null

  assert_symlink \
    "$SANDBOX_DIR/.config/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook" \
    "$PROJECT_DIR/configs/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook" \
    "Existing hook file becomes the repo symlink"
  assert_file_exists "$SANDBOX_DIR/backup/drop-omarchy-tmux.hook" "Previous hook file was backed up"
}

main() {
  echo -e "${YELLOW}========================================${NC}"
  echo -e "${YELLOW}Omarchy Dotfiles Installer Test Suite${NC}"
  echo -e "${YELLOW}========================================${NC}"
  echo ""

  setup_sandbox
  test_refuses_non_omarchy
  test_installs_around_omarchy_defaults
  test_is_idempotent
  test_replaces_wrong_hook_file

  print_summary
}

main "$@"
