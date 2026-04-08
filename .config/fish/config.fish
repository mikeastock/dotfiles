####### MISC CONFIG

set -U fish_greeting
set -gx EDITOR nvim
set -gx ELM_WATCH_OPEN_EDITOR 'idea --line "$line" "$file"'

# https://github.com/rails/rails/issues/38560
set -gx OBJC_DISABLE_INITIALIZE_FORK_SAFETY 'YES'

set -gx MINIO_ROOT_USER access_key_id
set -gx MINIO_ROOT_PASSWORD secret_access_key

function __load_env_file --argument-names env_file
  test -f "$env_file"
  or return

  while read -l line
    set line (string trim -- "$line")

    if test -z "$line"
      continue
    end

    if string match -qr '^#' -- "$line"
      continue
    end

    if not string match -qr '^[A-Za-z_][A-Za-z0-9_]*=' -- "$line"
      continue
    end

    set -l parts (string split -m 1 '=' -- "$line")
    set -gx "$parts[1]" "$parts[2]"
  end < "$env_file"
end

# Load ~/.env
__load_env_file ~/.env

####### ALIASES

# Unix
alias ...="../.."
alias cat="bat --theme base16"
alias cp="cp -r"
alias grep="grep --color=auto"
alias l="ls -lah"
alias lh="ls -Alh"
alias ll="ls -lh"
alias ln="ln -v"
alias mkdir="mkdir -p"
alias vim="nvim"

alias h="heroku"
alias hc="heroku run env CONSOLE_USER=mike bin/rails console"

# tmux / zellij
alias mux="tmuxinator"
alias tma="tmux att -t"
alias zj="zellij"

# Bundler
alias b="bundle"
alias be="bundle exec"

# Rails
alias r="bin/rails"
alias migrate="bin/rails db:migrate"
alias m="migrate"
alias rk="rake"
alias reset_elm="rm -f app/assets/javascripts/elm.js && rm -rf public/dist/assets && npm run build && rails assets:precompile"

# Git
alias g="git"
alias gad="git add -p"
alias gap="git add -p"
alias gc="git commit -v"
alias gcd="git checkout develop"
alias gcm="git checkout main"
alias co="git checkout"
alias br="git branch --sort=-committerdate"
alias gf="git-flow"
alias gp="git push -u"
alias gpl="git pull"
alias gpoh="git push -u origin HEAD"
alias gpr="git pull-request"
alias gprd="git pull-request -b develop"
alias gpull="git pull"
alias gpush="git push -u"
alias grm="git pull --rebase origin main"
alias gmm="git pull --no-rebase origin main"
alias gs="git status"
alias gst="git status"
alias gsu="git submodule update"
alias s="git status"
alias ci="git ci-status -v"
alias glist="git for-each-ref --sort=-committerdate refs/heads/ --format='%(committerdate:short) %(refname:short)' | head -n 10"

alias tf="mise exec terraform -- terraform"
alias n="corepack pnpm"
alias piu="npm install -g @mariozechner/pi-coding-agent"

# app checkouts
alias a1="cd ~/code/buildr/app"
alias a2="cd ~/code/buildr/app2"
alias a3="cd ~/code/buildr/app3"
alias a4="cd ~/code/buildr/app4"
alias a5="cd ~/code/buildr/app5"

function fco -d "Fuzzy-find and checkout a branch"
  git branch --all --sort=-committerdate | grep -v HEAD | string trim | fzf --header='[fuzzy:branch-checkout]' | xargs git checkout
end

function ssm-connect
  if test (count $argv) -lt 1
    echo "Usage: ssm-connect INSTANCE_ID [PROFILE]"
    echo "Default profile is buildr-app-prod"
    return 1
  end

  set instance_id $argv[1]
  set profile "buildr-app-prod"

  if test (count $argv) -gt 1
    set profile $argv[2]
  end

  aws --profile $profile ssm start-session --region us-east-1 --target $instance_id
end

function aic -d "Use pi with a fast model to commit"
  # codex exec --yolo -m gpt-5.3-codex-spark "use the semantic commit skill"
  pi --no-session --models "fireworks/accounts/fireworks/routers/kimi-k2p5-turbo" -p "use the semantic commit skill to commit"
end

####### PATH SETUP

####### Homebrew (macOS) / Linuxbrew (Linux)
if test -x /opt/homebrew/bin/brew
  eval (/opt/homebrew/bin/brew shellenv)
else if test -x /home/linuxbrew/.linuxbrew/bin/brew
  eval (/home/linuxbrew/.linuxbrew/bin/brew shellenv)
else if type -q brew
  eval (brew shellenv)
end

####### Tailscale
if test -d "/Applications/Tailscale.app/Contents/MacOS"
  alias tailscale="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
end

####### Mise
if type -q mise
  set -g MISE_FISH_AUTO_ACTIVATE 0
  mise activate fish | source
end

# Local bin dirs - Added after Mise so that these take precedence
fish_add_path ~/.local/bin
alias claude="claude --allow-dangerously-skip-permissions"

####### Bun
fish_add_path ~/.bun/bin

####### Amp
fish_add_path $HOME/.amp/bin

####### Postgres 17 (macOS only)
if test -d /opt/homebrew/opt/postgresql@17/bin
  fish_add_path /opt/homebrew/opt/postgresql@17/bin/
end

####### GNU sed (macOS only)
if test -d /opt/homebrew/opt/gnu-sed/libexec/gnubin
  fish_add_path /opt/homebrew/opt/gnu-sed/libexec/gnubin/
end

####### Z Alt (zoxide)
if type -q zoxide
  zoxide init fish | source
end

####### LM Studio CLI
if test -d ~/.lmstudio
  fish_add_path ~/.lmstudio/bin
end

###### Orbstack
source ~/.orbstack/shell/init2.fish 2>/dev/null || :

###### History Search (atuin)
if type -q atuin
  atuin init fish --disable-up-arrow | source
end

####### Workspace title helpers
function __workspace_git_branch
  command git rev-parse --is-inside-work-tree >/dev/null 2>&1
  or return

  set -l branch (command git symbolic-ref --short HEAD 2>/dev/null)
  if test -z "$branch"
    set branch (command git rev-parse --short HEAD 2>/dev/null)
  end

  if test -n "$branch"; and test (string length "$branch") -gt 20
    set branch (string sub -l 19 "$branch")…
  end

  if test -n "$branch"
    echo $branch
  end
end

function __workspace_repo_name --argument-names dir
  switch "$dir"
    case bizops
      echo biz
    case bizops-infra
      echo b-inf
    case infrastructure
      echo m-inf
    case dotfiles
      echo dot
    case marketing
      echo mkt
    case release-notes
      echo rel
    case app
      echo a1
    case app2
      echo a2
    case app3
      echo a3
    case app4
      echo a4
    case app5
      echo a5
    case '*'
      echo "$dir"
  end
end

function __workspace_title
  set -l dir (__workspace_repo_name (basename "$PWD"))
  set -l branch (__workspace_git_branch)

  if test -n "$branch"
    echo "$dir $branch"
  else
    echo "$dir"
  end
end

####### tmux window auto-rename
function _update_sibling_tmux_windows --argument-names repo_root branch
  set -l my_window (command tmux display-message -p '#{window_id}')

  for win_id in (command tmux list-windows -F '#{window_id}')
    if test "$win_id" = "$my_window"
      continue
    end

    set -l pane_path (command tmux display-message -t "$win_id" -p '#{pane_current_path}')
    set -l pane_repo (command git -C "$pane_path" rev-parse --show-toplevel 2>/dev/null)
    if test "$pane_repo" = "$repo_root"
      set -l dir (__workspace_repo_name (basename "$pane_path"))
      set -l branch (__workspace_git_branch)
      if test -n "$branch"
        command tmux rename-window -t "$win_id" "$dir $branch"
      else
        command tmux rename-window -t "$win_id" "$dir"
      end
    end
  end
end

function _tmux_window_name --on-variable PWD --on-event fish_postexec
  if not set -q TMUX; or not set -q TMUX_PANE
    return
  end

  set -l title (__workspace_title)
  command tmux rename-window -t "$TMUX_PANE" "$title"

  # When the branch changes within the same repo, update sibling windows
  set -l repo_root (command git rev-parse --show-toplevel 2>/dev/null)
  set -l branch (__workspace_git_branch)

  if test -n "$repo_root" -a -n "$branch"
    if test "$repo_root" = "$__tmux_last_repo" -a "$branch" != "$__tmux_last_branch"
      _update_sibling_tmux_windows "$repo_root" "$branch"
    end
    set -g __tmux_last_repo "$repo_root"
    set -g __tmux_last_branch "$branch"
  else
    set -e __tmux_last_repo
    set -e __tmux_last_branch
  end
end

_tmux_window_name

####### PROMPT CONFIG (starship)
if type -q starship
  starship init fish | source
end

functions -c fish_prompt _original_fish_prompt 2>/dev/null
function fish_prompt --description 'Write out the prompt'
  if set -q ZMX_SESSION
    echo -n "[$ZMX_SESSION] "
  end
  _original_fish_prompt
end
