#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/pi-ghostty-tmux-image.patch"
PLACEHOLDER_SRC="$SCRIPT_DIR/kitty-unicode-placeholder-diacritics.js"
MANAGED_INSTALL_DIR="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}/install"

require_file() {
  local path="$1"
  local label="$2"

  if [[ ! -f "$path" ]]; then
    echo "$label missing: $path" >&2
    exit 1
  fi
}

resolve_pi_root() {
  local arg="${1:-}"

  if [[ -n "$arg" ]]; then
    if [[ -d "$arg" && -f "$arg/package.json" ]]; then
      echo "$arg"
      return
    fi

    echo "Could not resolve pi install from argument: $arg" >&2
    exit 1
  fi

  local current_file="$MANAGED_INSTALL_DIR/current-version"
  if [[ ! -f "$current_file" ]]; then
    echo "No managed Pi install found at: $MANAGED_INSTALL_DIR" >&2
    exit 1
  fi

  local version
  version="$(tr -d '[:space:]' < "$current_file")"
  local root="$MANAGED_INSTALL_DIR/releases/$version"
  if [[ ! -d "$root" ]]; then
    echo "Managed Pi release missing: $root" >&2
    exit 1
  fi

  echo "$root"
}

extract_version() {
  local pi_root="$1"

  if [[ "$pi_root" =~ /releases/([^/]+) ]]; then
    echo "${BASH_REMATCH[1]}"
    return
  fi

  echo "unknown"
}

verify_patch() {
  local tui_dist="$1"

  rg -q "wrapTmuxPassthrough" "$tui_dist/terminal-image.js"
  rg -q "placeholderLines" "$tui_dist/components/image.js"
  [[ -f "$tui_dist/placeholder-diacritics.js" ]]
}

backup_originals() {
  local tui_dist="$1"
  local version="$2"

  local stamp backup_dir
  stamp="$(date +%Y%m%d-%H%M%S)"
  backup_dir="$HOME/.config/tmux/pi-patches/backups/pi-tui-${version}-${stamp}"

  mkdir -p "$backup_dir/components"
  cp "$tui_dist/terminal-image.js" "$backup_dir/terminal-image.js"
  cp "$tui_dist/components/image.js" "$backup_dir/components/image.js"
  cp "$tui_dist/placeholder-diacritics.js" "$backup_dir/placeholder-diacritics.js" 2>/dev/null || true

  echo "$backup_dir"
}

main() {
  require_file "$PATCH_FILE" "Patch file"
  require_file "$PLACEHOLDER_SRC" "Placeholder diacritics file"

  local pi_root tui_dist version backup_dir
  pi_root="$(resolve_pi_root "${1:-}")"
  tui_dist="$pi_root/node_modules/@earendil-works/pi-tui/dist"
  version="$(extract_version "$pi_root")"

  if [[ ! -d "$tui_dist" ]]; then
    echo "Target pi-tui dist directory not found: $tui_dist" >&2
    exit 1
  fi

  echo "Checking patch against: $tui_dist"
  if ! (cd "$tui_dist" && patch --dry-run --forward -p1 < "$PATCH_FILE") >/dev/null 2>&1; then
    echo
    echo "Patch does not apply cleanly. Checking if already applied..."
    if verify_patch "$tui_dist" && (cd "$tui_dist" && patch --dry-run -R --force -p1 < "$PATCH_FILE") >/dev/null 2>&1; then
      echo "Patch is already applied."
      exit 0
    fi

    echo
    echo "Patch failed (may need regenerating for this pi version):" >&2
    (cd "$tui_dist" && patch --dry-run -p1 < "$PATCH_FILE") || true
    exit 1
  fi

  backup_dir="$(backup_originals "$tui_dist" "$version")"

  (cd "$tui_dist" && patch --forward -p1 < "$PATCH_FILE")
  cp "$PLACEHOLDER_SRC" "$tui_dist/placeholder-diacritics.js"

  if ! verify_patch "$tui_dist"; then
    echo "Patch verification failed." >&2
    exit 1
  fi

  echo
  echo "Patched: $tui_dist"
  echo "Backup:  $backup_dir"
  echo "Restart pi sessions to load patched code."
}

main "$@"
