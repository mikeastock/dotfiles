#!/usr/bin/env bash
# Install personal dotfiles on Omarchy Linux.
#
# Claims home/config links around existing Omarchy files, leaves Ghostty,
# Alacritty, and Starship alone, and drops Omarchy's XDG tmux config so
# ~/.tmux.conf wins. Installs fish and atuin without Homebrew.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SKIP_PACKAGES=0
SKIP_TPM=0
SKIP_SHELL=0
FORCE=0

HOME_LINKS=(.gitconfig .ideavimrc .psqlrc .tmux.conf .tmuxinator .vscode)
CONFIG_DIRS=(stylua lvim zellij direnv atuin hypr)
OMARCHY_PACKAGES=(fish atuin)

usage() {
  cat <<'USAGE'
Usage: scripts/dot-omarchy.sh [options]

Install dotfiles on Omarchy Linux.

  --skip-packages   Do not install Arch packages
  --skip-tpm        Do not clone TPM or install tmux plugins
  --skip-shell      Do not change the login shell
  --force           Run even when this machine does not look like Omarchy
  -h, --help        Show this help
USAGE
}

while (($#)); do
  case "$1" in
    --skip-packages) SKIP_PACKAGES=1 ;;
    --skip-tpm) SKIP_TPM=1 ;;
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

BACKUP_DIR="${DOTFILES_BACKUP_DIR:-$HOME/.config/dotfiles-setup-backup-$(date +%Y%m%dT%H%M%S)}"

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

backup_name() {
  local dest="$1"
  local name parent

  name="$(basename "$dest")"
  parent="$(basename "$(dirname "$dest")")"

  case "$parent" in
    nvim | fish | herdr) printf '%s-%s\n' "$parent" "$name" ;;
    *) printf '%s\n' "$name" ;;
  esac
}

replace_with_symlink() {
  local src="$1"
  local dest="$2"

  if [[ ! -e "$src" ]]; then
    echo "✗ missing source: $src" >&2
    exit 1
  fi

  if [[ -L "$dest" && $(readlink "$dest") == "$src" ]]; then
    return 0
  fi

  if [[ -L "$dest" ]]; then
    rm "$dest"
  elif [[ -e "$dest" ]]; then
    mkdir -p "$BACKUP_DIR"
    mv "$dest" "$BACKUP_DIR/$(backup_name "$dest")"
    echo "  backed up $dest"
  fi

  mkdir -p "$(dirname "$dest")"
  ln -s "$src" "$dest"
}

require_omarchy() {
  if is_omarchy; then
    return
  fi

  echo "✗ This target is for Omarchy Linux. Use make dot-all elsewhere, or pass --force." >&2
  exit 1
}

install_packages() {
  if ((SKIP_PACKAGES)); then
    echo "✓ Skipping package install"
    return
  fi

  if ! command -v omarchy >/dev/null 2>&1; then
    echo "✗ omarchy is not on PATH; cannot install packages" >&2
    exit 1
  fi

  omarchy pkg add "${OMARCHY_PACKAGES[@]}"
  echo "✓ Packages present: ${OMARCHY_PACKAGES[*]}"
}

link_home() {
  local link

  for link in "${HOME_LINKS[@]}"; do
    replace_with_symlink "$REPO_ROOT/$link" "$HOME/$link"
  done

  mkdir -p "$HOME/.local/bin"
  local script name
  for script in "$REPO_ROOT"/bin/*; do
    [[ -f $script ]] || continue
    name="$(basename "$script")"
    replace_with_symlink "$script" "$HOME/.local/bin/$name"
  done

  mkdir -p "$HOME/.grok/workflows"
  if [[ -d $REPO_ROOT/configs/grok/workflows ]]; then
    local workflow
    for workflow in "$REPO_ROOT"/configs/grok/workflows/*; do
      [[ -f $workflow ]] || continue
      cp -f "$workflow" "$HOME/.grok/workflows/$(basename "$workflow")"
    done
  fi
  rm -f "$HOME/.grok/workflows/review-gauntlet.rhai"
  if [[ -L $HOME/.local/bin/code-review-loop ]]; then
    rm "$HOME/.local/bin/code-review-loop"
  fi

  echo "✓ Home links created"
}

link_config() {
  local dir

  mkdir -p "$HOME/.config" "$HOME/.config/nvim" "$HOME/.config/fish" "$HOME/.config/herdr"

  for dir in "${CONFIG_DIRS[@]}"; do
    replace_with_symlink "$REPO_ROOT/.config/$dir" "$HOME/.config/$dir"
  done

  replace_with_symlink "$REPO_ROOT/.config/nvim/init.lua" "$HOME/.config/nvim/init.lua"
  replace_with_symlink "$REPO_ROOT/.config/fish/config.fish" "$HOME/.config/fish/config.fish"
  replace_with_symlink "$REPO_ROOT/.config/fish/functions" "$HOME/.config/fish/functions"
  replace_with_symlink "$REPO_ROOT/.config/herdr/config.toml" "$HOME/.config/herdr/config.toml"

  echo "✓ Config links created"
  echo "  left Omarchy-owned: ghostty, alacritty, starship.toml"
}

patch_bashrc() {
  local bashrc="$HOME/.bashrc"
  local marker="# From personal dotfiles"

  if [[ -f $bashrc ]] && rg --fixed-strings --quiet -- "$marker" "$bashrc"; then
    echo "✓ bashrc already patched"
    return
  fi

  if [[ ! -f $bashrc ]]; then
    : >"$bashrc"
  fi

  cat >>"$bashrc" <<EOF

$marker
export PATH="\$HOME/.local/bin:\$PATH"
alias wk="work"
alias wokr="work"
if [ -f "\$HOME/.env" ]; then
  set -a
  . "\$HOME/.env"
  set +a
fi
EOF

  echo "✓ bashrc patched"
}

drop_omarchy_tmux() {
  rm -f "$HOME/.config/tmux/tmux.conf" "$HOME/.config/tmux"/tmux.conf.bak.*
  rmdir "$HOME/.config/tmux" 2>/dev/null || true

  local hook_src="$REPO_ROOT/configs/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook"
  local hook_dest="$HOME/.config/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook"

  replace_with_symlink "$hook_src" "$hook_dest"

  echo "✓ Omarchy tmux config dropped; post-update hook installed"
}

install_tpm() {
  if ((SKIP_TPM)); then
    echo "✓ Skipping tmux plugin install"
    return
  fi

  mkdir -p "$HOME/.tmux/plugins"
  if [[ -d $HOME/.tmux/plugins/tpm/.git ]]; then
    git -C "$HOME/.tmux/plugins/tpm" pull --ff-only
  elif [[ -e $HOME/.tmux/plugins/tpm ]]; then
    echo "✗ Error: $HOME/.tmux/plugins/tpm exists and is not a git checkout" >&2
    exit 1
  else
    git clone https://github.com/tmux-plugins/tpm "$HOME/.tmux/plugins/tpm"
  fi

  tmux start-server \; set-environment -g TMUX_PLUGIN_MANAGER_PATH "$HOME/.tmux/plugins/" \; source-file "$REPO_ROOT/.tmux.conf"
  "$HOME/.tmux/plugins/tpm/bin/install_plugins"
  echo "✓ tmux plugins installed"
}

set_login_shell() {
  if ((SKIP_SHELL)); then
    echo "✓ Skipping login shell change"
    return
  fi

  local fish_path current_shell
  fish_path="$(command -v fish)"
  if [[ -z $fish_path ]]; then
    echo "✗ fish is not installed" >&2
    exit 1
  fi

  current_shell="$(getent passwd "${USER:-$(id -un)}" | cut -d: -f7)"
  if [[ $current_shell == "$fish_path" ]]; then
    echo "✓ Login shell is already $fish_path"
    return
  fi

  if chsh -s "$fish_path"; then
    echo "✓ Login shell set to $fish_path (log out for it to apply)"
  else
    echo "✗ Could not change login shell. Run: chsh -s $fish_path" >&2
    exit 1
  fi
}

main() {
  require_omarchy
  install_packages
  link_home
  link_config
  patch_bashrc
  drop_omarchy_tmux
  install_tpm
  set_login_shell
  echo "✓ Omarchy dotfiles installed"
}

main
