# set PATH /usr/local/bin /usr/sbin $PATH

theme_gruvbox "dark"

# Node
status --is-interactive; and source (nodenv init -|psub)

# Ruby

# Aliases

# Unix
alias ...="../.."
alias cat="bat --theme base16"
alias cp="cp -r"
alias grep="grep --color=auto"
alias h="heroku"
alias l="ls -lah"
alias lh="ls -Alh"
alias ll="ls -lh"
alias ln="ln -v"
alias mkdir="mkdir -p"
alias vim="nvim"

# tmux
alias mux="tmuxinator"
alias tma="tmux att -t"

# Bundler
alias b="bundle"
alias be="bundle exec"

# Rails
alias migrate="bin/rails db:migrate"
alias m="migrate"
alias rk="rake"

alias g="git"
alias gap="git add -p"
alias gc="git commit -v"
alias gcd="git checkout develop"
alias gcm="git checkout master"
alias gf="git-flow"
alias gp="git push -u"
alias gpl="git pull"
alias gpoh="git push -u origin HEAD"
alias gpr="git pull-request"
alias gprd="git pull-request -b develop"
alias gpull="git pull"
alias gpush="git push -u"
alias grm="git pull --rebase origin master"
alias gs="git status"
alias gst="git status"
alias gsu="git submodule update"
alias s="git status"
alias ci="git ci-status -v"
