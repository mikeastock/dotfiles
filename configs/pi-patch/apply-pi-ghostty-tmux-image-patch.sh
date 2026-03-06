#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/pi-ghostty-tmux-image.patch"
PLACEHOLDER_SRC="$SCRIPT_DIR/kitty-unicode-placeholder-diacritics.js"
NODE_INSTALLS_DIR="$HOME/.local/share/mise/installs/node"

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

    local by_version="$NODE_INSTALLS_DIR/$arg/lib/node_modules/@mariozechner/pi-coding-agent"
    if [[ -d "$by_version" ]]; then
      echo "$by_version"
      return
    fi

    echo "Could not resolve pi install from argument: $arg" >&2
    exit 1
  fi

  local latest_version
  latest_version="$(fd . "$NODE_INSTALLS_DIR" --max-depth 1 --type d | xargs -n1 basename | sort -V | tail -n 1)"

  if [[ -z "$latest_version" ]]; then
    echo "No Node installs found under: $NODE_INSTALLS_DIR" >&2
    exit 1
  fi

  local root="$NODE_INSTALLS_DIR/$latest_version/lib/node_modules/@mariozechner/pi-coding-agent"
  if [[ ! -d "$root" ]]; then
    echo "Install found but pi package path missing: $root" >&2
    exit 1
  fi

  echo "$root"
}

extract_version() {
  local pi_root="$1"

  if [[ "$pi_root" =~ /installs/node/([^/]+)/ ]]; then
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
  tui_dist="$pi_root/node_modules/@mariozechner/pi-tui/dist"
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
