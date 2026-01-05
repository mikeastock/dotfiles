#!/bin/bash
set -e

# OrbStack VM Setup Script
# Sets up fish shell config and /code mount for consistent dev environment
#
# This script is IDEMPOTENT - safe to run multiple times.
# All config files are overwritten (not appended) on each run.
#
# Usage: ./setup-orb-vm.sh [machine-name]
# Default machine: ubuntu

MACHINE="${1:-ubuntu}"

echo "Setting up OrbStack VM: $MACHINE"

# Check if machine exists and is running
if ! orb list | grep -q "^$MACHINE.*running"; then
    echo "Error: Machine '$MACHINE' is not running"
    echo "Available machines:"
    orb list
    exit 1
fi

# ===========================================
# Fetch secrets from 1Password
# ===========================================
echo "Fetching secrets from 1Password..."
if ! command -v op &> /dev/null; then
    echo "Error: 1Password CLI (op) is not installed"
    echo "Install with: brew install 1password-cli"
    exit 1
fi

# Fetch secrets (will prompt for authentication if needed)
ANTHROPIC_OAUTH_TOKEN=$(op read "op://Private/Anthropic OAuth Token/credential")
CEREBRAS_API_KEY=$(op read "op://Private/Cerebras API Key/credential")
BUILDKITE_API_TOKEN=$(op read "op://Private/Buildkite API Token/credential")

echo "Secrets fetched successfully"

# Helper function to run commands in VM
run_in_vm() {
    orb run -m "$MACHINE" -s "$1"
}

# Helper function to write file in VM (creates parent dirs)
# Usage: write_file '~/.config/path' << 'EOF' ... EOF
# Note: Path should use ~ or be absolute, $HOME won't work properly
write_file() {
    local path="$1"
    local dir=$(dirname "$path")
    # Read stdin first before any orb commands (they consume stdin)
    local content
    content=$(cat)
    # Create parent directory (~ is expanded by bash in VM)
    orb run -m "$MACHINE" -s "bash -c 'mkdir -p $dir'" < /dev/null
    # Write content to file
    printf '%s\n' "$content" | orb run -m "$MACHINE" -s "bash -c 'cat > $path'"
}

# Helper function to write file with sudo
# Usage: write_file_sudo '/etc/path' << 'EOF' ... EOF
write_file_sudo() {
    local path="$1"
    local dir=$(dirname "$path")
    run_in_vm "sudo mkdir -p $dir"
    local content
    content=$(cat)
    echo "$content" | orb run -m "$MACHINE" -s "sudo tee $path > /dev/null"
}

# ===========================================
# Fish shell configuration
# ===========================================
echo "Writing fish config..."
write_file '~/.config/fish/config.fish' << FISH_CONFIG
if status is-interactive
    # ===========================================
    # Auto-cd based on MAC_PWD from orb function
    # ===========================================
    set -l MAC_CODE_BASE "/Users/mikeastock/code"
    set -l TARGET_MOUNT "/code"

    if set -q MAC_PWD
        if string match -q "\$MAC_CODE_BASE/*" \$MAC_PWD
            set -l RELATIVE_PATH (string replace "\$MAC_CODE_BASE/" "" \$MAC_PWD)
            set -l TARGET_DIR "\$TARGET_MOUNT/\$RELATIVE_PATH"
            if test -d "\$TARGET_DIR"
                cd "\$TARGET_DIR"
            else
                cd "\$TARGET_MOUNT" 2>/dev/null; or true
            end
        else if test "\$MAC_PWD" = "\$MAC_CODE_BASE"
            cd "\$TARGET_MOUNT"
        else
            cd "\$TARGET_MOUNT" 2>/dev/null; or true
        end
    else
        cd "\$TARGET_MOUNT" 2>/dev/null; or true
    end

    # ===========================================
    # API Keys (from 1Password)
    # ===========================================
    set -gx ANTHROPIC_OAUTH_TOKEN "$ANTHROPIC_OAUTH_TOKEN"
    set -gx CEREBRAS_API_KEY "$CEREBRAS_API_KEY"
    set -gx BUILDKITE_API_TOKEN "$BUILDKITE_API_TOKEN"
    set -gx BUILDKITE_ORGANIZATION_SLUG buildr

    # ===========================================
    # OrbStack service discovery
    # ===========================================
    set -gx PGHOST docker.orb.internal
    set -gx REDIS_URL redis://docker.orb.internal:6379
    set -gx DOLT_HOST docker.orb.internal
    set -gx MLFLOW_TRACKING_URI http://host.orb.internal:5500

    # ===========================================
    # Python/UV
    # ===========================================
    set -gx UV_PROJECT_ENVIRONMENT ".venv-linux"

    # ===========================================
    # Editor
    # ===========================================
    set -gx EDITOR nvim

    # ===========================================
    # pnpm
    # ===========================================
    set -gx PNPM_HOME "/home/mikeastock/.local/share/pnpm"
    fish_add_path \$PNPM_HOME

    # ===========================================
    # bun
    # ===========================================
    set -gx BUN_INSTALL "\$HOME/.bun"
    fish_add_path \$BUN_INSTALL/bin

    # ===========================================
    # Mise activation
    # ===========================================
    if test -f \$HOME/.local/bin/mise
        \$HOME/.local/bin/mise activate fish | source
    end

    # ===========================================
    # Linuxbrew
    # ===========================================
    if test -d /home/linuxbrew/.linuxbrew
        eval (/home/linuxbrew/.linuxbrew/bin/brew shellenv)
    end

    # ===========================================
    # Aliases (matching Mac config)
    # ===========================================

    # CLI tools with special flags
    alias claude="claude --dangerously-skip-permissions"
    alias codex="codex --yolo"

    # Package managers
    alias n="pnpm"
    alias b="bundle"
    alias be="bundle exec"

    # Rails
    alias r="bin/rails"
    alias migrate="bin/rails db:migrate"
    alias m="migrate"
    alias rk="rake"

    # Git
    alias g="git"
    alias gad="git add -p"
    alias gap="git add -p"
    alias gc="git commit -v"
    alias gcd="git checkout develop"
    alias gcm="git checkout main"
    alias co="git checkout"
    alias br="git branch --sort=-committerdate"
    alias gp="git push -u"
    alias gpl="git pull"
    alias gpoh="git push -u origin HEAD"
    alias gpull="git pull"
    alias gpush="git push -u"
    alias grm="git pull --rebase origin main"
    alias gmm="git pull --no-rebase origin main"
    alias gs="git status"
    alias gst="git status"
    alias s="git status"

    # Unix enhancements
    alias ...="../.."
    alias l="ls -lah"
    alias lh="ls -Alh"
    alias ll="ls -lh"
    alias ln="ln -v"
    alias mkdir="mkdir -p"
    alias cp="cp -r"
    alias grep="grep --color=auto"
    alias vim="nvim"
end
FISH_CONFIG

# ===========================================
# Profile.d scripts (system-wide)
# ===========================================
echo "Ensuring /code directory exists..."
run_in_vm 'sudo mkdir -p /code'

echo "Writing profile.d script for /code mount..."
write_file_sudo '/etc/profile.d/z-restrict-mac-access.sh' << 'PROFILE_SCRIPT'
#!/bin/sh

# Configuration  
MAC_CODE_BASE="/Users/mikeastock/code"
TARGET_MOUNT="/code"

# First, bind mount /code from the Mac's ~/code BEFORE blocking other paths
if [ -d "$MAC_CODE_BASE" ] && [ -d "$TARGET_MOUNT" ]; then
    if ! mountpoint -q "$TARGET_MOUNT" 2>/dev/null; then
        sudo mount --bind "$MAC_CODE_BASE" "$TARGET_MOUNT" 2>/dev/null
    fi
fi

# Block the "Leak" Paths (Deny-list) - unmount Mac filesystem access except /code
BLOCK_LIST="/mnt/mac /Users /Volumes /private /Applications /Library"

for MOUNT_PATH in $BLOCK_LIST; do
    if mountpoint -q "$MOUNT_PATH" 2>/dev/null; then
        sudo umount -l "$MOUNT_PATH" 2>/dev/null
    fi
done

# Only continue with cd for interactive shells
[ -z "$PS1" ] && return

# Change to relative directory if MAC_PWD is set and within code directory
if [ -n "$MAC_PWD" ]; then
    case "$MAC_PWD" in
        "$MAC_CODE_BASE"/*)
            RELATIVE_PATH="${MAC_PWD#$MAC_CODE_BASE/}"
            TARGET_DIR="$TARGET_MOUNT/$RELATIVE_PATH"
            if [ -d "$TARGET_DIR" ]; then
                cd "$TARGET_DIR"
            fi
            ;;
        "$MAC_CODE_BASE")
            cd "$TARGET_MOUNT"
            ;;
    esac
fi
PROFILE_SCRIPT
run_in_vm 'sudo chmod +x /etc/profile.d/z-restrict-mac-access.sh'

echo "Writing bundler.sh profile.d script..."
write_file_sudo '/etc/profile.d/bundler.sh' << 'BUNDLER_SCRIPT'
#!/bin/sh
export BUNDLE_PATH="../vendor/bundle"
BUNDLER_SCRIPT

echo "Writing locale fix profile.d script..."
write_file_sudo '/etc/profile.d/01-locale-fix.sh' << 'LOCALE_SCRIPT'
# Make sure the locale variables are set to valid values.
eval $(/usr/bin/locale-check C.UTF-8)
LOCALE_SCRIPT

# ===========================================
# Bash configuration
# ===========================================
echo "Writing bash config..."
write_file '~/.bashrc.orb-setup' << 'BASHRC_APPEND'

# ===========================================
# OrbStack Setup (added by setup-orb-vm.sh)
# ===========================================

# Auto-cd based on MAC_PWD from orbsh function (uses OrbStack native /code mount)
MAC_CODE_BASE="/Users/mikeastock/code"
TARGET_MOUNT="/code"

if [ -n "$MAC_PWD" ]; then
    case "$MAC_PWD" in
        "$MAC_CODE_BASE"/*)
            RELATIVE_PATH="${MAC_PWD#$MAC_CODE_BASE/}"
            TARGET_DIR="$TARGET_MOUNT/$RELATIVE_PATH"
            if [ -d "$TARGET_DIR" ]; then
                cd "$TARGET_DIR"
            else
                cd "$TARGET_MOUNT" 2>/dev/null || true
            fi
            ;;
        "$MAC_CODE_BASE")
            cd "$TARGET_MOUNT"
            ;;
        *)
            cd "$TARGET_MOUNT" 2>/dev/null || true
            ;;
    esac
else
    cd "$TARGET_MOUNT" 2>/dev/null || true
fi

# OrbStack service discovery
export PGHOST=docker.orb.internal
export REDIS_URL=redis://docker.orb.internal:6379
export DOLT_HOST=docker.orb.internal
export MLFLOW_TRACKING_URI=http://host.orb.internal:5500

# Python/UV
export UV_PROJECT_ENVIRONMENT=".venv-linux"

# Editor
export EDITOR=nvim

# pnpm
export PNPM_HOME="/home/mikeastock/.local/share/pnpm"
case ":$PATH:" in
  *":$PNPM_HOME:"*) ;;
  *) export PATH="$PNPM_HOME:$PATH" ;;
esac

# Mise activation
if [ -f "$HOME/.local/bin/mise" ]; then
    eval "$($HOME/.local/bin/mise activate --shims bash)"
fi

# Linuxbrew
if [ -d /home/linuxbrew/.linuxbrew ]; then
    eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
fi

# bun
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"

# Aliases
alias claude="claude --dangerously-skip-permissions"
alias codex="codex --yolo"
alias n="pnpm"
alias b="bundle"
alias be="bundle exec"
alias g="git"
alias s="git status"
alias r="bin/rails"
alias migrate="bin/rails db:migrate"
alias m="migrate"
BASHRC_APPEND

# Idempotently add source line to .bashrc (only if not already present)
orb run -m "$MACHINE" -s 'bash -c '\''
if ! grep -q "bashrc.orb-setup" ~/.bashrc 2>/dev/null; then
    echo "" >> ~/.bashrc
    echo "# Source OrbStack setup" >> ~/.bashrc
    echo "[ -f ~/.bashrc.orb-setup ] && source ~/.bashrc.orb-setup" >> ~/.bashrc
    echo "  Added source line to ~/.bashrc"
else
    echo "  Source line already in ~/.bashrc (skipped)"
fi
'\'''

# ===========================================
# Git configuration
# ===========================================
echo "Writing .gitconfig..."
write_file '~/.gitconfig' << 'GITCONFIG'
[user]
  name = Michael Stock
  email = mikeastock@gmail.com
[alias]
  co = checkout
  oc = checkout
  com = checkout main
  ci = commit
  cm = commit -v
  t = status
  s = status
  st = status
  br = branch --sort=-committerdate
  df = diff --color
  dfom = diff origin/main --color
  pl = pull
  p = push
  ad = add --patch
  hist = log --pretty=format:'%h %ad | %s%d [%an]' --graph --date=short
  lg = log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit
  su = submodule update --init --recursive
  pim = pull --no-rebase origin main
  d = diff
  lc = log -n 1
  wt = worktree
[push]
  default = current
[core]
  editor = nvim
[color]
  ui = auto
[color "status"]
  added = yellow
  changed = green
  untracked = cyan
[color "branch"]
  current = yellow reverse
  local = yellow
  remote = green
[branch "master"]
  remote = origin
  merge = refs/heads/master
[difftool]
  prompt = false
[filter "lfs"]
  clean = git-lfs clean -- %f
  smudge = git-lfs smudge -- %f
  process = git-lfs filter-process
  required = true
[pull]
  rebase = true
[rerere]
  enabled = true
[init]
  defaultBranch = main
[merge]
  conflictstyle = zdiff3
GITCONFIG

# ===========================================
# SSH configuration (uses OrbStack's host SSH agent)
# ===========================================
echo "Writing SSH config..."
run_in_vm 'mkdir -p ~/.ssh && chmod 700 ~/.ssh'
write_file '~/.ssh/config' << 'SSHCONFIG'
Host *
    IdentityAgent /opt/orbstack-guest/run/host-ssh-agent.sock
SSHCONFIG
run_in_vm 'chmod 600 ~/.ssh/config'

# ===========================================
# pnpm configuration (isolated node_modules for Linux)
# ===========================================
echo "Writing pnpm config..."
write_file '~/.config/pnpm/rc' << 'PNPMRC'
virtual-store-dir=node_modules/.pnpm.linux
PNPMRC

# ===========================================
# Mise configuration
# ===========================================
echo "Writing mise config..."
write_file '~/.config/mise/config.toml' << 'MISECONFIG'
[tools]
node = "latest"
ruby = "3.4"
python = "3.13"
go = "latest"
deno = "latest"
"npm:@mariozechner/pi-coding-agent" = "latest"
rust = "stable"
MISECONFIG

# ===========================================
# Claude Code configuration
# ===========================================
echo "Writing Claude Code config..."
write_file '~/.claude/settings.json' << 'CLAUDECONFIG'
{
  "enabledPlugins": {
    "dev-browser@dev-browser-marketplace": true
  },
  "statusLine": {
    "type": "command",
    "command": "bash /home/mikeastock/.claude/statusline-git.sh"
  }
}
CLAUDECONFIG

write_file '~/.claude/statusline-git.sh' << 'STATUSLINE'
#!/bin/bash

# Read JSON input from stdin
input=$(cat)

# Extract information from JSON
model_name=$(echo "$input" | jq -r '.model.display_name')
current_dir=$(echo "$input" | jq -r '.workspace.current_dir')

# Extract context window information
context_size=$(echo "$input" | jq -r '.context_window.context_window_size // 200000')
current_usage=$(echo "$input" | jq '.context_window.current_usage')

# Calculate context percentage
if [ "$current_usage" != "null" ]; then
    current_tokens=$(echo "$current_usage" | jq '.input_tokens + .cache_creation_input_tokens + .cache_read_input_tokens')
    context_percent=$((current_tokens * 100 / context_size))
else
    context_percent=0
fi

# Build context progress bar (20 chars wide)
bar_width=15
filled=$((context_percent * bar_width / 100))
empty=$((bar_width - filled))
bar=""
for ((i=0; i<filled; i++)); do bar+="█"; done
for ((i=0; i<empty; i++)); do bar+="░"; done

# Extract cost information
session_cost=$(echo "$input" | jq -r '.cost.total_cost_usd // empty')
[ "$session_cost" != "empty" ] && session_cost=$(printf "%.4f" "$session_cost") || session_cost=""

# Get directory name (basename)
dir_name=$(basename "$current_dir")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Change to the current directory to get git info
cd "$current_dir" 2>/dev/null || cd /

# Get git branch
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    branch=$(git branch --show-current 2>/dev/null || echo "detached")

    # Get git status with file counts
    status_output=$(git status --porcelain 2>/dev/null)

    if [ -n "$status_output" ]; then
        # Count files and get basic line stats
        total_files=$(echo "$status_output" | wc -l | xargs)
        line_stats=$(git diff --numstat HEAD 2>/dev/null | awk '{added+=$1; removed+=$2} END {print added+0, removed+0}')

        added=$(echo $line_stats | cut -d' ' -f1)
        removed=$(echo $line_stats | cut -d' ' -f2)

        # Build status display
        git_info=" ${YELLOW}($branch${NC} ${YELLOW}|${NC} ${GRAY}${total_files} files${NC}"

        [ "$added" -gt 0 ] && git_info="${git_info} ${GREEN}+${added}${NC}"
        [ "$removed" -gt 0 ] && git_info="${git_info} ${RED}-${removed}${NC}"

        git_info="${git_info} ${YELLOW})${NC}"
    else
        git_info=" ${YELLOW}($branch)${NC}"
    fi
else
    git_info=""
fi

# Add session cost if available
cost_info=""
if [ -n "$session_cost" ] && [ "$session_cost" != "null" ] && [ "$session_cost" != "empty" ]; then
    cost_info=" ${GRAY}[\$$session_cost]${NC}"
fi

# Build context bar display
context_info="${GRAY}${bar}${NC} ${context_percent}%"

# Output the status line
echo -e "${BLUE}${dir_name}${NC} ${GRAY}|${NC} ${CYAN}${model_name}${NC} ${GRAY}|${NC} ${context_info}${git_info:+ ${GRAY}|${NC}}${git_info}${cost_info}"
STATUSLINE
run_in_vm 'chmod +x ~/.claude/statusline-git.sh'

# ===========================================
# Pi (coding agent) configuration
# ===========================================
echo "Writing pi agent config..."
write_file '~/.pi/agent/settings.json' << 'PICONFIG'
{
  "lastChangelogVersion": "0.34.2",
  "defaultProvider": "anthropic",
  "defaultModel": "claude-opus-4-5",
  "defaultThinkingLevel": "high",
  "skills": {
    "enableCodexUser": false,
    "enableClaudeUser": false
  }
}
PICONFIG

echo ""
echo "✅ Setup complete for VM: $MACHINE"
echo ""
echo "This script is idempotent - safe to run again to update configs."
echo ""
echo "The following has been configured:"
echo ""
echo "  Shell configs:"
echo "    - ~/.config/fish/config.fish (fish shell)"
echo "    - ~/.bashrc.orb-setup (bash shell)"
echo ""
echo "  Profile.d scripts:"
echo "    - /etc/profile.d/z-restrict-mac-access.sh (mounts /code, blocks Mac paths)"
echo "    - /etc/profile.d/bundler.sh (BUNDLE_PATH=../vendor/bundle)"
echo "    - /etc/profile.d/01-locale-fix.sh (UTF-8 locale)"
echo ""
echo "  Tool configs:"
echo "    - ~/.gitconfig (git aliases, colors)"
echo "    - ~/.ssh/config (OrbStack host SSH agent)"
echo "    - ~/.config/pnpm/rc (pnpm virtual-store-dir-suffix=.linux)"
echo "    - ~/.config/mise/config.toml (node, ruby, python, go, deno, rust)"
echo "    - ~/.claude/settings.json + statusline-git.sh (Claude Code)"
echo "    - ~/.pi/agent/settings.json (pi coding agent)"
echo ""
echo "  Environment:"
echo "    - OrbStack service discovery (docker.orb.internal)"
echo "    - Common aliases and environment variables"
echo ""
echo "To use, run 'orb' from your Mac in any ~/code subdirectory."
echo "The VM shell will automatically cd to the equivalent /code path."
