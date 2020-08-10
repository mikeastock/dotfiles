# Set custom prompt
setopt PROMPT_SUBST
autoload -U promptinit
promptinit
prompt pure
prompt_newline='%666v'
PROMPT=" $PROMPT"

# Initialize completion
autoload -Uz compinit
if [ $(date +'%j') != $(stat -f '%Sm' -t '%j' ~/.zcompdump) ]; then
  compinit
else
  compinit -C
fi

# GNU Screen sets -o vi if EDITOR=vi, so we have to force it back.
set -o emacs

# Allow [ or ] whereever you want
unsetopt nomatch

# By default, zsh considers many characters part of a word (e.g., _ and -).
# Narrow that down to allow easier skipping through words via M-f and M-b.
export WORDCHARS='*?[]~&;!$%^<>'

# Set ls colors
export CLICOLOR=1

# History options
HISTFILE=$HOME/.history
HISTSIZE=10000
SAVEHIST=10000

setopt append_history
setopt extended_history
setopt hist_expire_dups_first
setopt hist_ignore_dups # ignore duplication command history list
setopt hist_ignore_space
setopt hist_verify
setopt inc_append_history
setopt share_history # share command history data

# By default, ^S freezes terminal output and ^Q resumes it. Disable that so
# that those keys can be used for other things.
unsetopt flowcontrol

 # Handle dup path in tmux for Mac OS X
 # http://superuser.com/questions/544989/does-tmux-sort-the-path-variable/583502#583502
 if [[ `uname` == "Darwin" ]]; then
   if [ -f /etc/profile ]; then
     PATH=""
     source /etc/profile
   fi
 fi

if [[ -n $SSH_CONNECTION ]]; then
  export EDITOR='vim'
else
  export EDITOR='nvim'
fi

# PATH setup
export PATH="$PATH:$HOME/.bin:$HOME/bin:$HOME/.fzf/bin:/usr/local/heroku/bin:$HOME/.git-semantic-commits:$HOME/.yarn/bin:$HOME/.config/yarn/global/node_modules/.bin"

# Load FZF
[ -f ~/.fzf/shell/key-bindings.zsh ] && source ~/.fzf/shell/key-bindings.zsh
[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh

# Setup Cargo (Rust)
[ -f ~/.cargo/env ] && source ~/.cargo/env

source /usr/local/share/chruby/chruby.sh
source /usr/local/share/chruby/auto.sh

# Setup Nodenv (Node)
export PATH="$HOME/.nodenv/bin:$PATH"
eval "$(nodenv init -)"

# Setup pyenv (Pyrthon)
export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init -)"

# Setup Kiex (Elixir)
test -s "$HOME/.kiex/scripts/kiex" && source "$HOME/.kiex/scripts/kiex"

export ERL_AFLAGS="-kernel shell_history enabled"

# Sourcing of other zsh files
source $HOME/.zsh/aliases
source $HOME/.zsh/z
source /usr/local/share/zsh/site-functions

if [[ `uname` == "Darwin" ]]; then
  source ~/.zshrc.mac
fi

if [[ `uname` == "Linux" ]]; then
  source ~/.zshrc.linux
fi

[ -f ~/.cargo/env ] && source ~/.cargo/env
export RUST_SRC_PATH="$(rustc --print sysroot)/lib/rustlib/src/rust/src"

BASE16_SHELL=$HOME/.config/base16-shell/
[ -n "$PS1" ] && [ -s $BASE16_SHELL/profile_helper.sh ] && eval "$($BASE16_SHELL/profile_helper.sh)"

[ -f /usr/local/share/zsh-autosuggestions/zsh-autosuggestions.zsh ] && source /usr/local/share/zsh-autosuggestions/zsh-autosuggestions.zsh
[ -f /usr/local/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && source /usr/local/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

autoload -Uz pcurl

[ -f $HOME/.env ] && source $HOME/.env

# Add local bin to front of PATH
export PATH="./bin:$PATH"
