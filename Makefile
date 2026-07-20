# Agents Makefile
# Installs skills, prompt templates, themes, and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py
FORCE_FLAG := $(if $(FORCE),--force,)
UNAME_S := $(shell uname -s)

# Home directory symlinks
HOME_LINKS := .gitconfig .ideavimrc .psqlrc .tmux.conf .tmuxinator .vscode

# .config directories to symlink entirely
CONFIG_DIRS := alacritty stylua lvim zellij direnv atuin ghostty

.PHONY: all install install-non-interactive install-tools install-skills install-amp-plugins install-extensions install-prompts install-subagents install-themes install-configs install-codex-config install-opencodex amp-plugin-types amp-plugin-check package-manager-security-config build clean help submodule-init plugin-update check-python \
	dot-all dot-install dot-home-symlinks dot-config-symlinks dot-platform-defaults dot-macos-defaults dot-clean

all: help

help:
	@echo "Agents - Skills, Prompt Templates, and Extensions Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install                 Initialize submodules and install all agent artifacts"
	@echo "  make install FORCE=1         Claim existing unmanaged paths that match managed artifacts"
	@echo "  make install-non-interactive Install for headless/automated environments (skips interactive extensions)"
	@echo "  make install-tools           Install pinned external agent tools"
	@echo "  make install-skills          Install skills only (Amp, Claude Code, Pi agent)"
	@echo "  make install-amp-plugins     Install Amp plugins from amp-plugins/"
	@echo "  make install-extensions      Install extensions only (Pi agent)"
	@echo "  make install-prompts         Install prompt templates only (Pi agent)"
	@echo "  make install-subagents       Install subagent definitions only (Pi agent)"
	@echo "  make install-themes          Install themes only (Pi agent)"
	@echo "  make install-configs         Install all agent configs (Amp, Codex, Pi)"
	@echo "  make install-codex-config    Install the managed Codex config and profiles only"
	@echo "  make install-opencodex       Install the pinned OpenCodex package through mise"
	@echo "  make amp-plugin-types        Refresh local Amp plugin TypeScript declarations"
	@echo "  make amp-plugin-check        Refresh Amp plugin declarations and typecheck plugins"
	@echo "  make package-manager-security-config Configure global npm/pnpm/bun/uv package security settings"
	@echo "  make build                   Build skills/prompts/themes (without installing)"
	@echo "  make plugin-update           Update all plugin submodules to latest"
	@echo "  make clean                   Remove all installed skills, extensions, and build artifacts"
	@echo ""
	@echo "Dotfiles:"
	@echo "  make dot-all                Run all dotfile setup tasks"
	@echo "  make dot-install            Install required Homebrew/Linuxbrew packages and tmux plugins"
	@echo "  make dot-home-symlinks      Symlink dotfiles to home directory"
	@echo "  make dot-config-symlinks    Symlink .config files and directories"
	@echo "  make dot-platform-defaults  Apply supported platform defaults"
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
	@$(PYTHON) "$(BUILD_SCRIPT)" install $(FORCE_FLAG)
	@echo "All skills, prompt templates, themes, extensions, and Amp plugins installed"

install-non-interactive: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install --non-interactive $(FORCE_FLAG)
	@echo "All skills, prompt templates, themes, extensions, and Amp plugins installed (non-interactive mode)"

install-tools: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-tools

submodule-init:
	@$(PYTHON) "$(BUILD_SCRIPT)" submodule-init

build: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" build

install-skills: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-skills $(FORCE_FLAG)

install-amp-plugins: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-amp-plugins $(FORCE_FLAG)

install-extensions: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-extensions $(FORCE_FLAG)

install-prompts: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-prompts $(FORCE_FLAG)

install-subagents: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-subagents $(FORCE_FLAG)

install-themes: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-themes $(FORCE_FLAG)

install-configs: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-configs

install-codex-config: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-codex-config

install-opencodex:
	@$(PYTHON) "$(BUILD_SCRIPT)" install-opencodex

amp-plugin-types: check-python
	@$(PYTHON) $(CURDIR)/scripts/update_amp_plugin_types.py

amp-plugin-check: amp-plugin-types
	@pnpm exec tsc --noEmit --pretty false

package-manager-security-config:
	@$(PYTHON) $(CURDIR)/scripts/package_manager_security_config.py

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

dot-all: dot-install dot-home-symlinks dot-config-symlinks dot-platform-defaults

# Install required Homebrew/Linuxbrew packages from Brewfile and tmux plugins
dot-install:
	@which brew >/dev/null 2>&1 || (echo "✗ Error: Homebrew/Linuxbrew not installed"; exit 1)
	@brew bundle --file=$(CURDIR)/Brewfile
	@echo "✓ Brew packages installed"
	@mkdir -p $(HOME)/.tmux/plugins
	@if [ -d $(HOME)/.tmux/plugins/tpm/.git ]; then \
		git -C $(HOME)/.tmux/plugins/tpm pull --ff-only; \
	elif [ -e $(HOME)/.tmux/plugins/tpm ]; then \
		echo "✗ Error: $(HOME)/.tmux/plugins/tpm exists and is not a git checkout"; \
		exit 1; \
	else \
		git clone https://github.com/tmux-plugins/tpm $(HOME)/.tmux/plugins/tpm; \
	fi
	@tmux start-server \; set-environment -g TMUX_PLUGIN_MANAGER_PATH $(HOME)/.tmux/plugins/ \; source-file $(CURDIR)/.tmux.conf
	@$(HOME)/.tmux/plugins/tpm/bin/install_plugins
	@echo "✓ tmux plugins installed"

# Apply platform-specific defaults when supported
dot-platform-defaults:
ifeq ($(UNAME_S),Darwin)
	@$(MAKE) dot-macos-defaults
else
	@echo "✓ No platform defaults to apply for $(UNAME_S)"
endif

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
	@# Symlink bin/ scripts into ~/.local/bin/
	@mkdir -p $(HOME)/.local/bin
	@for script in $(CURDIR)/bin/*; do \
		name=$$(basename $$script); \
		if [ -L $(HOME)/.local/bin/$$name ]; then \
			:; \
		elif [ -e $(HOME)/.local/bin/$$name ]; then \
			echo "✗ Error: $(HOME)/.local/bin/$$name exists and is not a symlink"; \
			echo "  Remove it manually to proceed"; \
			exit 1; \
		else \
			ln -s $$script $(HOME)/.local/bin/$$name; \
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
	@# Single-file configs
	$(call safe_symlink,$(CURDIR)/.config/starship.toml,$(HOME)/.config/starship.toml)
	@mkdir -p $(HOME)/.config/herdr
	$(call safe_symlink,$(CURDIR)/.config/herdr/config.toml,$(HOME)/.config/herdr/config.toml)
	@echo "✓ Config symlinks created"

# Remove all managed dotfile symlinks (only removes if target is a symlink)
dot-clean:
	@echo "Removing managed dotfile symlinks..."
	@# Home symlinks
	@for link in $(HOME_LINKS); do \
		[ -L $(HOME)/$$link ] && rm $(HOME)/$$link || true; \
	done
	@# ~/.local/bin scripts
	@for script in $(CURDIR)/bin/*; do \
		name=$$(basename $$script); \
		[ -L $(HOME)/.local/bin/$$name ] && rm $(HOME)/.local/bin/$$name || true; \
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
	@# Single-file configs
	@[ -L $(HOME)/.config/starship.toml ] && rm $(HOME)/.config/starship.toml || true
	@[ -L $(HOME)/.config/herdr/config.toml ] && rm $(HOME)/.config/herdr/config.toml || true
	@echo "✓ Dotfile symlinks removed"

# Set macOS defaults
dot-macos-defaults:
	@if [ "$(UNAME_S)" != "Darwin" ]; then \
		echo "✗ Error: dot-macos-defaults is only supported on macOS"; \
		exit 1; \
	fi
	@# Disable shadows on window screenshots
	@defaults write com.apple.screencapture disable-shadow -bool true
	@echo "✓ macOS defaults set"
