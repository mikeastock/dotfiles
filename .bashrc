
#Prompt settigns
export PS1="\u@\[\e[36m\]\h\[\e[0m\] :: \w >> "

#ls color
if [ -f "$HOME/.dircolors" ]
  then
    eval $(dircolors -b $HOME/.dircolors)
fi


#Aliases in .bash_aliases
if [ -f ~/.bash_aliases ]; then
   . ~/.bash_aliases
fi

# added by travis gem
[ -f /Users/mikeastock/.travis/travis.sh ] && source /Users/mikeastock/.travis/travis.sh

export NVM_DIR="/Users/mikeastock/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"  # This loads nvm
[[ -s "/home/mikeastock/.gvm/scripts/gvm" ]] && source "/home/mikeastock/.gvm/scripts/gvm"
[ -f ~/.fzf.bash ] && source ~/.fzf.bash

source $HOME/.asdf/asdf.sh
source $HOME/.asdf/completions/asdf.bash
