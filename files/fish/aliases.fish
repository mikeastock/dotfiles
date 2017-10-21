# Random
alias aliases="nvim ~/.zsh/aliases"

# Unix
alias tlf="tail -f"
alias ln='ln -v'
alias mkdir='mkdir -p'
alias grep='grep --color=auto'
alias cp='cp -r'
alias l='ls -lah'
alias ll='ls -lh'
alias lh='ls -Alh'
alias vim="nvim"

# tmux
alias tma='tmux att -t'
alias tmls='tmux ls'
alias grabssh="$HOME/bin/grabssh"
alias updatessh="$HOME/bin/updatessh"
alias mux="tmuxinator"

# Bundler
alias b="bundle"
alias be="bundle exec"

# Tests and Specs
alias cuc="bundle exec cucumber"

# Rubygems
alias gi="gem install"
alias giv="gem install -v"

# Rails
alias migrate="bin/rake db:migrate db:test:prepare"
alias m="migrate"
alias rk="rake"
alias fdoc_scaf="FDOC_SCAFFOLD=true spring rspec spec/controllers/api/v1/"
alias sc="spring cucumber"
alias sr="spring rspec spec/"

alias co="git checkout"
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

alias reset_db="bin/rake db:drop db:create db:structure:load db:migrate db:seed"
