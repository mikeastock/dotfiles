# Agents Makefile
# Installs skills, prompt templates, themes, and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

# Home directory symlinks
HOME_LINKS := .bin .gitconfig .ideavimrc .psqlrc .tmux.conf .tmuxinator .vscode

# .config directories to symlink entirely
CONFIG_DIRS := alacritty stylua lvim zellij direnv atuin ghostty

.PHONY: all install install-non-interactive install-skills install-extensions install-prompts install-themes install-configs build clean help submodule-init plugin-update check-python \
	dot-all dot-install dot-home-symlinks dot-config-symlinks dot-macos-defaults dot-clean

all: help

help:
	@echo "Agents - Skills, Prompt Templates, and Extensions Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install                 Initialize submodules and install skills and extensions"
	@echo "  make install-non-interactive Install for headless/automated environments (skips interactive extensions)"
	@echo "  make install-skills          Install skills only (Amp, Claude Code, Codex, Pi agent)"
	@echo "  make install-extensions      Install extensions only (Pi agent)"
	@echo "  make install-prompts         Install prompt templates only (Pi agent)"
	@echo "  make install-themes          Install themes only (Pi agent)"
	@echo "  make install-configs         Install all agent configs (Amp, Codex, Pi)"
	@echo "  make build                   Build skills/prompts/themes (without installing)"
	@echo "  make plugin-update           Update all plugin submodules to latest"
	@echo "  make clean                   Remove all installed skills, extensions, and build artifacts"
	@echo ""
	@echo "Dotfiles:"
	@echo "  make dot-all                Run all dotfile setup tasks"
	@echo "  make dot-install            Install required Homebrew packages"
	@echo "  make dot-home-symlinks      Symlink dotfiles to home directory"
	@echo "  make dot-config-symlinks    Symlink .config files and directories"
	@echo "  make dot-macos-defaults     Set macOS defaults"
	@echo "  make dot-clean              Remove all managed dotfile symlinks"
	@echo ""
	@echo "  make help                    Show this help message"
	@echo ""
	@echo "Configuration: plugins.toml"

check-python:
	@$(PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null || \
		(echo "Error: Python 3.11+ required (for tomllib)"; exit 1)

install: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install
	@echo "All skills, prompt templates, themes, and extensions installed"

install-non-interactive: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install --non-interactive
	@echo "All skills, prompt templates, themes, and extensions installed (non-interactive mode)"

submodule-init:
	@$(PYTHON) "$(BUILD_SCRIPT)" submodule-init

build: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" build

install-skills: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-skills

install-extensions: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-extensions

install-prompts: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-prompts

install-themes: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-themes

install-configs: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-configs

clean: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" clean

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"

# Helper: create symlink or error if non-symlink exists
# Usage: $(call safe_symlink,source,target)
define safe_symlink
	@if [ -L $(2) ]; then \
		:; \
	elif [ -e $(2) ]; then \
		echo "✗ Error: $(2) exists and is not a symlink"; \
		echo "  Run 'make dot-clean' first or remove it manually"; \
		exit 1; \
	else \
		ln -s $(1) $(2); \
	fi
endef

# Dotfiles targets

dot-all: dot-install dot-home-symlinks dot-config-symlinks dot-macos-defaults

# Install required Homebrew packages from Brewfile
dot-install:
	@which brew >/dev/null 2>&1 || (echo "✗ Error: Homebrew not installed"; exit 1)
	@brew bundle --file=$(CURDIR)/Brewfile
	@echo "✓ Brew packages installed"

# Symlink dotfiles to home directory
dot-home-symlinks:
	@for link in $(HOME_LINKS); do \
		if [ -L $(HOME)/$$link ]; then \
			:; \
		elif [ -e $(HOME)/$$link ]; then \
			echo "✗ Error: $(HOME)/$$link exists and is not a symlink"; \
			echo "  Run 'make dot-clean' first or remove it manually"; \
			exit 1; \
		else \
			ln -s $(CURDIR)/$$link $(HOME)/$$link; \
		fi; \
	done
	@echo "✓ Home symlinks created"

# Symlink .config files and directories
dot-config-symlinks:
	@mkdir -p $(HOME)/.config
	@mkdir -p $(HOME)/.config/nvim
	@mkdir -p $(HOME)/.config/fish
	@# Config directories (link entire dir)
	@for dir in $(CONFIG_DIRS); do \
		if [ -L $(HOME)/.config/$$dir ]; then \
			:; \
		elif [ -e $(HOME)/.config/$$dir ]; then \
			echo "✗ Error: $(HOME)/.config/$$dir exists and is not a symlink"; \
			echo "  Run 'make dot-clean' first or remove it manually"; \
			exit 1; \
		else \
			ln -s $(CURDIR)/.config/$$dir $(HOME)/.config/$$dir; \
		fi; \
	done
	@# nvim (individual files - only if nvim dir is not already a symlink)
	@if [ ! -L $(HOME)/.config/nvim ]; then \
		if [ -L $(HOME)/.config/nvim/init.lua ]; then :; \
		elif [ -e $(HOME)/.config/nvim/init.lua ]; then \
			echo "✗ Error: $(HOME)/.config/nvim/init.lua exists and is not a symlink"; \
			echo "  Run 'make dot-clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(CURDIR)/.config/nvim/init.lua $(HOME)/.config/nvim/init.lua; fi; \
		if [ -L $(HOME)/.config/nvim/autoload ]; then :; \
		elif [ -e $(HOME)/.config/nvim/autoload ]; then \
			echo "✗ Error: $(HOME)/.config/nvim/autoload exists and is not a symlink"; \
			echo "  Run 'make dot-clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(CURDIR)/.config/nvim/autoload $(HOME)/.config/nvim/autoload; fi; \
	fi
	@# fish (config.fish and functions/ - only if fish dir is not already a symlink)
	@if [ ! -L $(HOME)/.config/fish ]; then \
		if [ -L $(HOME)/.config/fish/config.fish ]; then :; \
		elif [ -e $(HOME)/.config/fish/config.fish ]; then \
			echo "✗ Error: $(HOME)/.config/fish/config.fish exists and is not a symlink"; \
			echo "  Run 'make dot-clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(CURDIR)/.config/fish/config.fish $(HOME)/.config/fish/config.fish; fi; \
		if [ -L $(HOME)/.config/fish/functions ]; then :; \
		elif [ -e $(HOME)/.config/fish/functions ]; then \
			echo "✗ Error: $(HOME)/.config/fish/functions exists and is not a symlink"; \
			echo "  Run 'make dot-clean' first or remove it manually"; \
			exit 1; \
		else ln -s $(CURDIR)/.config/fish/functions $(HOME)/.config/fish/functions; fi; \
	fi
	@# starship.toml (single file)
	$(call safe_symlink,$(CURDIR)/.config/starship.toml,$(HOME)/.config/starship.toml)
	@echo "✓ Config symlinks created"

# Remove all managed dotfile symlinks (only removes if target is a symlink)
dot-clean:
	@echo "Removing managed dotfile symlinks..."
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
	@echo "✓ Dotfile symlinks removed"

# Set macOS defaults
dot-macos-defaults:
	@# Disable shadows on window screenshots
	@defaults write com.apple.screencapture disable-shadow -bool true
	@echo "✓ macOS defaults set"
