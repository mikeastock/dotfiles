#!/usr/bin/env bash
# Apply personal machine setup via mise bootstrap.
#
# home     macOS/Ubuntu: terminals, brew packages, macOS defaults
# omarchy  Omarchy Linux: skip terminals, claim around Omarchy files, fish login
# clean    Remove mise-managed links from both profiles

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

COMMAND=""
SKIP_PACKAGES=0
SKIP_SHELL=0
FORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/dotfiles.sh <home|omarchy|clean> [options]

  home       Install macOS/Ubuntu dotfiles (`mise -E home`)
  omarchy    Install Omarchy Linux dotfiles (`mise -E omarchy`)
  clean      Unapply home and omarchy dotfiles

  --skip-packages   Skip brew / omarchy package install
  --skip-shell      Do not change the login shell (omarchy)
  --force           Run omarchy even when this machine does not look like Omarchy
  -h, --help        Show this help
USAGE
}

is_omarchy() {
  if [[ -n ${DOTFILES_OMARCHY:-} ]]; then
    [[ $DOTFILES_OMARCHY == 1 ]]
    return
  fi

  if ((FORCE)); then
    return 0
  fi

  [[ -d ${OMARCHY_PATH:-/usr/share/omarchy} ]] || command -v omarchy >/dev/null 2>&1
}

require_omarchy() {
  if is_omarchy; then
    return
  fi

  echo "✗ This target is for Omarchy Linux. Use make dot-all elsewhere, or pass --force." >&2
  exit 1
}

require_mise() {
  if ! command -v mise >/dev/null 2>&1; then
    echo "✗ mise 2026.9.2+ is required. Install: curl https://mise.run | sh" >&2
    exit 1
  fi
}

join_csv() {
  local IFS=,
  printf '%s\n' "$*"
}

bootstrap() {
  local profile="$1"
  local parts=()
  local extra=()

  if ((SKIP_PACKAGES == 0)); then
    parts+=(packages)
  fi
  parts+=(dotfiles)
  if [[ $profile == home && $(uname -s) == Darwin ]]; then
    parts+=(macos-defaults)
  fi
  if [[ $profile == omarchy ]] && ((SKIP_SHELL == 0)); then
    parts+=(user)
  fi
  if [[ $profile == omarchy ]]; then
    extra+=(--force-dotfiles)
  fi

  mise -C "$REPO_ROOT" trust --yes
  mise -C "$REPO_ROOT" -E "$profile" bootstrap --only "$(join_csv "${parts[@]}")" --yes "${extra[@]}"
}

unapply() {
  mise -C "$REPO_ROOT" trust --yes
  mise -C "$REPO_ROOT" -E home dot unapply --yes
  mise -C "$REPO_ROOT" -E omarchy dot unapply --yes
}

while (($#)); do
  case "$1" in
    home | omarchy | clean)
      if [[ -n $COMMAND ]]; then
        echo "Unknown option: $1" >&2
        usage >&2
        exit 1
      fi
      COMMAND="$1"
      ;;
    --skip-packages) SKIP_PACKAGES=1 ;;
    --skip-shell) SKIP_SHELL=1 ;;
    --force) FORCE=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ -z $COMMAND ]]; then
  usage >&2
  exit 1
fi

require_mise

case "$COMMAND" in
  home)
    bootstrap home
    echo "✓ Home dotfiles installed"
    ;;
  omarchy)
    require_omarchy
    bootstrap omarchy
    echo "✓ Omarchy dotfiles installed"
    ;;
  clean)
    unapply
    echo "✓ Dotfile links removed"
    ;;
esac
