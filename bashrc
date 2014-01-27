
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
