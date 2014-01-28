#####################
# oh-my-zsh configs #
#####################

ZSH=$HOME/.oh-my-zsh
ZSH_THEME="afowler"

COMPLETION_WAITING_DOTS="true"

plugins=(ruby cp autojump command-not-found lol sprunge git gitfast git_remote_branch rails bundler rbenv rake capistrano colored-man colorize dirpersist history profiles vundle rand-quote)

source $ZSH/oh-my-zsh.sh

######################
# custom zsh configs #
######################

# use vim as the visual editor
export VISUAL=vim
export EDITOR=$VISUAL

# load rbenv if available
if which rbenv &>/dev/null ; then
  eval "$(rbenv init - --no-rehash)"
fi

# aliases
[[ -f ~/.aliases ]] && source ~/.aliases

# paths
export PATH=/usr/local/rbenv/shims:/usr/local/rbenv/bin:/user/local/redis/bin:$PATH
export RBENV_ROOT="/usr/local/rbenv"
