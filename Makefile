.PHONY: all
all: icloud-link home-symlinks config-symlinks brew macos-defaults

ICLOUD_DOTFILES := $(HOME)/icloud-drive/dotfiles

# Home directory symlinks
HOME_LINKS := .bin .gitconfig .ideavimrc .psqlrc .tmux.conf .tmuxinator .vscode

# .config directories to symlink entirely
CONFIG_DIRS := alacritty stylua lvim zellij direnv atuin ghostty

# Create iCloud drive symlink
.PHONY: icloud-link
icloud-link:
	@test -L $(HOME)/icloud-drive || ln -s "$(HOME)/Library/Mobile Documents/com~apple~CloudDocs" $(HOME)/icloud-drive
	@echo "✓ iCloud drive linked"

# Symlink dotfiles to home directory
.PHONY: home-symlinks
home-symlinks: icloud-link
	@for link in $(HOME_LINKS); do \
		test -L $(HOME)/$$link || ln -s $(ICLOUD_DOTFILES)/$$link $(HOME)/$$link; \
	done
	@echo "✓ Home symlinks created"

# Symlink .config files and directories
.PHONY: config-symlinks
config-symlinks: icloud-link
	@mkdir -p $(HOME)/.config
	@mkdir -p $(HOME)/.config/nvim
	@mkdir -p $(HOME)/.config/fish
	@# Config directories (link entire dir)
	@for dir in $(CONFIG_DIRS); do \
		test -L $(HOME)/.config/$$dir || ln -s $(ICLOUD_DOTFILES)/.config/$$dir $(HOME)/.config/$$dir; \
	done
	@# nvim (individual files)
	@test -L $(HOME)/.config/nvim/init.lua || ln -s $(ICLOUD_DOTFILES)/.config/nvim/init.lua $(HOME)/.config/nvim/init.lua
	@test -d $(HOME)/.config/nvim/autoload || ln -s $(ICLOUD_DOTFILES)/.config/nvim/autoload $(HOME)/.config/nvim/autoload
	@# fish (config.fish and functions/)
	@test -L $(HOME)/.config/fish/config.fish || ln -s $(ICLOUD_DOTFILES)/.config/fish/config.fish $(HOME)/.config/fish/config.fish
	@test -L $(HOME)/.config/fish/functions || ln -s $(ICLOUD_DOTFILES)/.config/fish/functions $(HOME)/.config/fish/functions
	@# starship.toml (single file)
	@test -L $(HOME)/.config/starship.toml || ln -s $(ICLOUD_DOTFILES)/.config/starship.toml $(HOME)/.config/starship.toml
	@echo "✓ Config symlinks created"

# Install Homebrew and packages
.PHONY: brew
brew:
	@command -v brew >/dev/null || /bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	@brew update
	@brew tap Homebrew/bundle
	@brew bundle --file=$(ICLOUD_DOTFILES)/Brewfile --verbose
	@brew upgrade
	@echo "✓ Homebrew packages installed"

# Set macOS defaults
.PHONY: macos-defaults
macos-defaults:
	@# Disable shadows on window screenshots
	@defaults write com.apple.screencapture disable-shadow -bool true
	@echo "✓ macOS defaults set"
