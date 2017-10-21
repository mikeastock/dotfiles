source $HOME/.config/fish/aliases.fish
source $HOME/.kiex/scripts/kiex.fish

if status --is-interactive
  # Base16 Shell
  source $HOME/.config/base16-shell/profile_helper.fish
  # Rbenv
  source (rbenv init -|psub)
end

set -xg PATH ./bin $PATH
