.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all             Run all setup tasks (symlinks, brew, macos-defaults)"
	@echo "  icloud-link     Create iCloud drive symlink"
	@echo "  home-symlinks   Symlink dotfiles to home directory"
	@echo "  config-symlinks Symlink .config files and directories"
	@echo "  brew            Install Homebrew and packages"
	@echo "  macos-defaults  Set macOS defaults"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DOTFILES_DIR    Override dotfiles source directory"
	@echo "                  Default: ~/icloud-drive/dotfiles"
	@echo "                  Example: make all DOTFILES_DIR=~/code/dotfiles"

.PHONY: all
all: icloud-link home-symlinks config-symlinks brew macos-defaults

# DOTFILES_DIR can be overridden: make DOTFILES_DIR=~/code/personal/dotfiles
DOTFILES_DIR ?= $(HOME)/icloud-drive/dotfiles

# Home directory symlinks
HOME_LINKS := .bin .gitconfig .ideavimrc .psqlrc .tmux.conf .tmuxinator .vscode

# .config directories to symlink entirely
CONFIG_DIRS := alacritty stylua lvim zellij direnv atuin ghostty

# Create iCloud drive symlink (skip if using custom DOTFILES_DIR)
.PHONY: icloud-link
icloud-link:
ifeq ($(DOTFILES_DIR),$(HOME)/icloud-drive/dotfiles)
	@test -L $(HOME)/icloud-drive || ln -s "$(HOME)/Library/Mobile Documents/com~apple~CloudDocs" $(HOME)/icloud-drive
	@echo "✓ iCloud drive linked"
else
	@echo "✓ Using custom DOTFILES_DIR: $(DOTFILES_DIR)"
endif

# Symlink dotfiles to home directory
.PHONY: home-symlinks
home-symlinks: icloud-link
	@for link in $(HOME_LINKS); do \
		test -L $(HOME)/$$link || ln -s $(DOTFILES_DIR)/$$link $(HOME)/$$link; \
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
		test -L $(HOME)/.config/$$dir || ln -s $(DOTFILES_DIR)/.config/$$dir $(HOME)/.config/$$dir; \
	done
	@# nvim (individual files)
	@test -L $(HOME)/.config/nvim/init.lua || ln -s $(DOTFILES_DIR)/.config/nvim/init.lua $(HOME)/.config/nvim/init.lua
	@test -d $(HOME)/.config/nvim/autoload || ln -s $(DOTFILES_DIR)/.config/nvim/autoload $(HOME)/.config/nvim/autoload
	@# fish (config.fish and functions/)
	@test -L $(HOME)/.config/fish/config.fish || ln -s $(DOTFILES_DIR)/.config/fish/config.fish $(HOME)/.config/fish/config.fish
	@test -L $(HOME)/.config/fish/functions || ln -s $(DOTFILES_DIR)/.config/fish/functions $(HOME)/.config/fish/functions
	@# starship.toml (single file)
	@test -L $(HOME)/.config/starship.toml || ln -s $(DOTFILES_DIR)/.config/starship.toml $(HOME)/.config/starship.toml
	@echo "✓ Config symlinks created"

# Install Homebrew and packages
.PHONY: brew
brew:
	@command -v brew >/dev/null || /bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	@brew update
	@brew tap Homebrew/bundle
	@brew bundle --file=$(DOTFILES_DIR)/Brewfile --verbose
	@brew upgrade
	@echo "✓ Homebrew packages installed"

# Set macOS defaults
.PHONY: macos-defaults
macos-defaults:
	@# Disable shadows on window screenshots
	@defaults write com.apple.screencapture disable-shadow -bool true
	@echo "✓ macOS defaults set"
