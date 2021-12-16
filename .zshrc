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

# Load FZF
[ -f ~/.fzf/shell/key-bindings.zsh ] && source ~/.fzf/shell/key-bindings.zsh
[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh

# Setup Cargo (Rust)
[ -f ~/.cargo/env ] && source ~/.cargo/env

# asdf
. $(brew --prefix asdf)/libexec/asdf.sh

# Sourcing of other zsh files
source $HOME/.zsh/aliases
source $HOME/.zsh/z
[ -f /usr/local/share/zsh/site-functions ] && source /usr/local/share/zsh/site-functions
[ -f /opt/homebrew/share/zsh/site-functions ] && source /opt/homebrew/share/zsh/site-functions

HISTDB_TABULATE_CMD=(sed -e $'s/\x1f/\t/g')
source $HOME/.zsh/plugins/zsh-histdb/sqlite-history.zsh
autoload -Uz add-zsh-hook

if [[ `uname` == "Linux" ]]; then
  source ~/.zshrc.linux
fi

[ -f ~/.cargo/env ] && source ~/.cargo/env
export RUST_SRC_PATH="$(rustc --print sysroot)/lib/rustlib/src/rust/src"

BASE16_SHELL=$HOME/.config/base16-shell/
[ -n "$PS1" ] && [ -s $BASE16_SHELL/profile_helper.sh ] && eval "$($BASE16_SHELL/profile_helper.sh)"

[ -f /usr/local/share/zsh-autosuggestions/zsh-autosuggestions.zsh ] && source /usr/local/share/zsh-autosuggestions/zsh-autosuggestions.zsh
[ -f /usr/local/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && source /usr/local/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

[ -f /opt/homebrew/share/zsh-autosuggestions/zsh-autosuggestions.zsh ] && source /opt/homebrew/share/zsh-autosuggestions/zsh-autosuggestions.zsh
[ -f /opt/homebrew/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && source /opt/homebrew/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

# _zsh_autosuggest_strategy_histdb_top_here() {
#     local query="select commands.argv from
# history left join commands on history.command_id = commands.rowid
# left join places on history.place_id = places.rowid
# where places.dir LIKE '$(sql_escape $PWD)%'
# and commands.argv LIKE '$(sql_escape $1)%'
# group by commands.argv order by count(*) desc limit 1"
#     suggestion=$(_histdb_query "$query")
# }

# ZSH_AUTOSUGGEST_STRATEGY=histdb_top_here

[ -f $HOME/.env ] && source $HOME/.env

export MINIO_ROOT_USER=access_key_id
export MINIO_ROOT_PASSWORD=secret_access_key

autoload -U +X bashcompinit && bashcompinit

##############
# PATH setup #
##############

# Add homebrew to front of path
export PATH="/opt/homebrew/bin:$PATH"
# Add local bin to front of PATH
export PATH="./bin:$PATH"
# Add postgresql 13 to path
export PATH="/opt/homebrew/opt/postgresql@13/bin:$PATH"
# Add home bins to path
export PATH="$PATH:$HOME/.bin:$HOME/bin:$HOME/.fzf/bin"

################
# Setup prompt #
################

eval "$(starship init zsh)"
