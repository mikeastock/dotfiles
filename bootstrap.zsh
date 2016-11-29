#!/bin/zsh

# Bootstrap a development environment for Matt Casper
# usage: ./bootstrap.zsh

set -eo pipefail

# "${VAR-}" takes the value of the variable, or empty string if it doesn't exist
if [ -n "${TMUX-}" ]; then
  echo "I can't be run from inside a tmux session, please exit the session and run me in a bare terminal."
  exit 1
fi

# Setup code directory
mkdir -p ~/code

# Install essentials when necessary
if [[ $(/usr/bin/gcc 2>&1) =~ "no developer tools were found" ]] || [[ ! -x /usr/bin/gcc ]]; then
  echo "Installing Xcode"
  xcode-select --install
fi

# Download and install Homebrew
if [[ ! -x /usr/local/bin/brew ]]; then
  echo "Installing Homebrew"
  /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

# Install homebrew bundle
echo "Updating brew, running 'brew bundle', and upgrading packages"
brew update
brew tap Homebrew/bundle
brew bundle --verbose
brew upgrade

# Git setup
mkdir -p "$HOME/.git_template/hooks"
cp git/ctags "$HOME/.git_template/hooks/ctags"
cp git/ctags_hook "$HOME/.git_template/hooks/post-commit"
cp git/ctags_hook "$HOME/.git_template/hooks/post-merge"
cp git/ctags_hook "$HOME/.git_template/hooks/post-checkout"

# Dotfiles
# rcup -f -d "$HOME/code/dotfiles/files"
# . "$HOME/.zshrc"

SERVICES=("postgresql" "elasticsearch" "memcached" "redis")
for service in "${SERVICES[@]}"; do brew services start "$service"; done

# Set default shell
if ! [ "$SHELL" = "/bin/zsh" ]; then
  chsh -s /bin/zsh
fi

# Rehash so zsh can find all its commands
rehash

# Setup neovim
mkdir -p $HOME/.config
ln -sf ~/code/dotfiles/files/nvim ~/.config/

## Language specific installations

## Install asdf
if [[ ! -x ~/.asdf ]]; then
  echo "Installing asdf"
  git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch v0.2.0
fi

function add_asdf_plugin() {
  if ! [[ -n $(asdf plugin-list | grep $1) ]]; then
    asdf plugin-add $1 $2
  fi
}

function install_latest_version() {
  local latest_version=$(asdf list-all $1 | grep "\d+.\d+.\d+" | grep "rc\|beta\|preview" | tail -n 1 | xargs)
  echo "Latest version of ${$1} is ${$latest_version}"
  asdf install $1 $latest_version
  asdf global $1 $latest_version
}

add_asdf_plugin erlang https://github.com/asdf-vm/asdf-erlang.git
add_asdf_plugin elixir https://github.com/asdf-vm/asdf-elixir.git
add_asdf_plugin ruby https://github.com/asdf-vm/asdf-ruby.git
add_asdf_plugin rust https://github.com/code-lever/asdf-rust.git
add_asdf_plugin golang https://github.com/kennyp/asdf-golang.git
add_asdf_plugin elm https://github.com/vic/asdf-elm.git
add_asdf_plugin python https://github.com/tuvistavie/asdf-python.git
add_asdf_plugin nodejs https://github.com/asdf-vm/asdf-nodejs.git

install_latest_version "erlang"
install_latest_version "elixir"
install_latest_version "rust"
install_latest_version "ruby"
install_latest_version "golang"
install_latest_version "elm"
install_latest_version "python"
install_latest_version "nodejs"

mix archive.install https://github.com/phoenixframework/archives/raw/master/phoenix_new.ez --force

if ! [[ -n $(cargo install --list | grep ripgrep) ]]; then
  cargo install ripgrep
fi
