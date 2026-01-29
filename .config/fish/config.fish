####### MISC CONFIG

set -U fish_greeting
set -gx EDITOR nvim
set -gx ELM_WATCH_OPEN_EDITOR 'idea --line "$line" "$file"'

# https://github.com/rails/rails/issues/38560
set -gx OBJC_DISABLE_INITIALIZE_FORK_SAFETY 'YES'

set -gx MINIO_ROOT_USER access_key_id
set -gx MINIO_ROOT_PASSWORD secret_access_key

# Load ~/.env
export (grep "^[^#]" ~/.env | xargs -L 1)

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

# tmux
alias mux="tmuxinator"
alias tma="tmux att -t"

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

alias tf="terraform"
alias n="corepack pnpm"
alias gt="gtree"

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

# function orb -d "OrbStack wrapper with auto-cd to relative path in ~/code"
#   if test (count $argv) -eq 0; or test "$argv[1]" = "shell"
#     set mac_pwd (pwd)
#     command orb run -s "MAC_PWD='$mac_pwd' bash -li"
#   else
#     command orb $argv
#   end
# end
#
# function orb-codex -d "Run codex --yolo in OrbStack at current directory"
#   set mac_pwd (pwd)
#   command orb run -s "MAC_PWD='$mac_pwd' fish -lc 'codex --yolo'"
# end
#
# function orb-pi -d "Run pi in OrbStack at current directory"
#   set mac_pwd (pwd)
#   command orb run -s "MAC_PWD='$mac_pwd' fish -lc 'pi'"
# end
#
# function orb-claude -d "Run claude in OrbStack at current directory"
#   set mac_pwd (pwd)
#   command orb run -s "MAC_PWD='$mac_pwd' fish -lc 'claude --allow-dangerously-skip-permissions'"
# end

####### PATH SETUP

####### Homebrew (macOS) / Linuxbrew (Linux)
if test -d /opt/homebrew
    fish_add_path /opt/homebrew/bin
else if test -d /home/linuxbrew/.linuxbrew
    eval (/home/linuxbrew/.linuxbrew/bin/brew shellenv)
end

####### Tailscale
if test -d "/Applications/Tailscale.app/Contents/MacOS"
  alias tailscale="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
end

####### Mise
set -g MISE_FISH_AUTO_ACTIVATE 0
mise activate fish | source

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

###### Orbstack
source ~/.orbstack/shell/init2.fish 2>/dev/null || :

###### History Search (atuin)
if type -q atuin
    atuin init fish --disable-up-arrow | source
end

####### PROMPT CONFIG (starship)
if type -q starship
    starship init fish | source
end
