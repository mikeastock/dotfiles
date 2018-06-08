#!/bin/zsh

# Bootstrap a development environment for Matt Casper
# usage: ./bootstrap.zsh

set -eo pipefail

# "${VAR-}" takes the value of the variable, or empty string if it doesn't exist
if [ -n "${TMUX-}" ]; then
  echo "I can't be run from inside a tmux session, please exit the session and run me in a bare terminal."
  exit 1
fi

# Install essentials when necessary
if [[ $(/usr/bin/gcc 2>&1) =~ "no developer tools were found" ]] || [[ ! -x /usr/bin/gcc ]]; then
  echo "Installing Xcode"
  xcode-select --install
fi

# Dotfiles
rcup -f -d "$HOME/code/dotfiles/files"
. "$HOME/.zshrc"

SERVICES=("postgresql" "memcached" "redis")
for service in "${SERVICES[@]}"; do brew services start "$service"; done

# Rehash so zsh can find all its commands
rehash

# Setup neovim
mkdir -p $HOME/.config
ln -sf ~/code/dotfiles/files/nvim ~/.config/

# Setup z
touch ~/.z

# Elixir - kiex (version manager)
if ! type kiex > /dev/null 2>&1; then
  curl -sSL https://raw.githubusercontent.com/taylor/kiex/master/install | bash -s
  . "$HOME/.zshrc"
fi

latest_elixir=$(kiex list known | tail -n 1 | xargs)
if ! [[ -n $(kiex list | grep "$latest_elixir") ]]; then
  kiex install "$latest_elixir"
fi

kiex use "$latest_elixir"
kiex default "$latest_elixir"
mix archive.install https://github.com/phoenixframework/archives/raw/master/phoenix_new.ez --force

# Rust
curl https://sh.rustup.rs -sSf | bash -s -- -y
rustup update

if ! [[ -n $(cargo install --list | grep ripgrep) ]]; then
  cargo install ripgrep
fi
