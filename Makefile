.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all             Run all setup tasks (symlinks, macos-defaults)"
	@echo "  icloud-link     Create iCloud drive symlink"
	@echo "  home-symlinks   Symlink dotfiles to home directory"
	@echo "  config-symlinks Symlink .config files and directories"
	@echo "  macos-defaults  Set macOS defaults"
	@echo "  clean           Remove all managed symlinks"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DOTFILES_DIR    Override dotfiles source directory"
	@echo "                  Default: ~/icloud-drive/dotfiles"
	@echo "                  Example: make all DOTFILES_DIR=~/code/dotfiles"
	@echo ""
	@echo "Agent Targets:"
	@echo "  install                  Install agent skills/prompts/extensions"
	@echo "  install-non-interactive  Non-interactive install for CI/headless runs"
	@echo "  install-skills           Install agent skills"
	@echo "  install-prompts          Install agent prompts"
	@echo "  install-extensions       Install Pi extensions"
	@echo "  install-configs          Install agent config files"
	@echo "  build                    Build agent artifacts only"
	@echo "  agents-clean             Clean agent build/install artifacts"
	@echo "  plugin-update            Update plugin submodules"

.PHONY: all
all: icloud-link home-symlinks config-symlinks macos-defaults

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

# Helper: create symlink or error if non-symlink exists
# Usage: $(call safe_symlink,source,target)
define safe_symlink
	@if [ -L $(2) ]; then \
		:; \
	elif [ -e $(2) ]; then \
		echo "✗ Error: $(2) exists and is not a symlink"; \
		echo "  Run 'make clean' first or remove it manually"; \
		exit 1; \
	else \
		ln -s $(1) $(2); \
	fi
endef

# Symlink dotfiles to home directory
.PHONY: home-symlinks
home-symlinks: icloud-link
	@for link in $(HOME_LINKS); do \
		if [ -L $(HOME)/$$link ]; then \
			:; \
		elif [ -e $(HOME)/$$link ]; then \
			echo "✗ Error: $(HOME)/$$link exists and is not a symlink"; \
			echo "  Run 'make clean' first or remove it manually"; \
			exit 1; \
		else \
			ln -s $(DOTFILES_DIR)/$$link $(HOME)/$$link; \
		fi; \
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
		if [ -L $(HOME)/.config/$$dir ]; then \
			:; \
		elif [ -e $(HOME)/.config/$$dir ]; then \
			echo "✗ Error: $(HOME)/.config/$$dir exists and is not a symlink"; \
			echo "  Run 'make clean' first or remove it manually"; \
			exit 1; \
		else \
			ln -s $(DOTFILES_DIR)/.config/$$dir $(HOME)/.config/$$dir; \
		fi; \
	done
	@# nvim (individual files - only if nvim dir is not already a symlink)
	@if [ ! -L $(HOME)/.config/nvim ]; then \
		if [ -L $(HOME)/.config/nvim/init.lua ]; then :; \
		elif [ -e $(HOME)/.config/nvim/init.lua ]; then \
			echo "✗ Error: $(HOME)/.config/nvim/init.lua exists and is not a symlink"; \
			echo "  Run 'make clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(DOTFILES_DIR)/.config/nvim/init.lua $(HOME)/.config/nvim/init.lua; fi; \
		if [ -L $(HOME)/.config/nvim/autoload ]; then :; \
		elif [ -e $(HOME)/.config/nvim/autoload ]; then \
			echo "✗ Error: $(HOME)/.config/nvim/autoload exists and is not a symlink"; \
			echo "  Run 'make clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(DOTFILES_DIR)/.config/nvim/autoload $(HOME)/.config/nvim/autoload; fi; \
	fi
	@# fish (config.fish and functions/ - only if fish dir is not already a symlink)
	@if [ ! -L $(HOME)/.config/fish ]; then \
		if [ -L $(HOME)/.config/fish/config.fish ]; then :; \
		elif [ -e $(HOME)/.config/fish/config.fish ]; then \
			echo "✗ Error: $(HOME)/.config/fish/config.fish exists and is not a symlink"; \
			echo "  Run 'make clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(DOTFILES_DIR)/.config/fish/config.fish $(HOME)/.config/fish/config.fish; fi; \
		if [ -L $(HOME)/.config/fish/functions ]; then :; \
		elif [ -e $(HOME)/.config/fish/functions ]; then \
			echo "✗ Error: $(HOME)/.config/fish/functions exists and is not a symlink"; \
			echo "  Run 'make clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(DOTFILES_DIR)/.config/fish/functions $(HOME)/.config/fish/functions; fi; \
	fi
	@# starship.toml (single file)
	$(call safe_symlink,$(DOTFILES_DIR)/.config/starship.toml,$(HOME)/.config/starship.toml)
	@echo "✓ Config symlinks created"

# Remove all managed symlinks (only removes if target is a symlink)
.PHONY: clean
clean:
	@echo "Removing managed symlinks..."
	@# Home symlinks
	@for link in $(HOME_LINKS); do \
		[ -L $(HOME)/$$link ] && rm $(HOME)/$$link || true; \
	done
	@# Config directories
	@for dir in $(CONFIG_DIRS); do \
		[ -L $(HOME)/.config/$$dir ] && rm $(HOME)/.config/$$dir || true; \
	done
	@# nvim
	@[ -L $(HOME)/.config/nvim/init.lua ] && rm $(HOME)/.config/nvim/init.lua || true
	@[ -L $(HOME)/.config/nvim/autoload ] && rm $(HOME)/.config/nvim/autoload || true
	@# fish
	@[ -L $(HOME)/.config/fish/config.fish ] && rm $(HOME)/.config/fish/config.fish || true
	@[ -L $(HOME)/.config/fish/functions ] && rm $(HOME)/.config/fish/functions || true
	@# starship
	@[ -L $(HOME)/.config/starship.toml ] && rm $(HOME)/.config/starship.toml || true
	@echo "✓ Symlinks removed"

# Set macOS defaults
.PHONY: macos-defaults
macos-defaults:
	@# Disable shadows on window screenshots
	@defaults write com.apple.screencapture disable-shadow -bool true
	@echo "✓ macOS defaults set"

# Agent tooling
AGENTS_PYTHON ?= python3
AGENTS_BUILD_SCRIPT := $(CURDIR)/scripts/build.py

.PHONY: agents-check-python agents-install agents-install-non-interactive agents-submodule-init agents-build agents-install-skills agents-install-extensions agents-install-prompts agents-install-configs agents-clean install install-non-interactive install-skills install-extensions install-prompts install-configs build submodule-init plugin-update

agents-check-python:
	@$(AGENTS_PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null || \
		(echo "Error: Python 3.11+ required (for tomllib)"; exit 1)

agents-install: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) install
	@echo "Agent skills, prompt templates, and extensions installed"

agents-install-non-interactive: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) install --non-interactive
	@echo "Agent skills, prompt templates, and extensions installed (non-interactive mode)"

agents-submodule-init:
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) submodule-init

agents-build: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) build

agents-install-skills: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) install-skills

agents-install-extensions: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) install-extensions

agents-install-prompts: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) install-prompts

agents-install-configs: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) install-configs

agents-clean: agents-check-python
	@$(AGENTS_PYTHON) $(AGENTS_BUILD_SCRIPT) clean

install: agents-install
install-non-interactive: agents-install-non-interactive
install-skills: agents-install-skills
install-extensions: agents-install-extensions
install-prompts: agents-install-prompts
install-configs: agents-install-configs
build: agents-build
submodule-init: agents-submodule-init

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"
