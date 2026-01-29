# Agents Makefile
# Installs skills and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

# Agent settings directories
PI_SETTINGS_DIR := $(HOME)/.pi/agent
PI_SETTINGS_FILE := $(PI_SETTINGS_DIR)/settings.json
AMP_SETTINGS_DIR := $(HOME)/.config/amp
AMP_SETTINGS_FILE := $(AMP_SETTINGS_DIR)/settings.json
CODEX_SETTINGS_DIR := $(HOME)/.codex
CODEX_SETTINGS_FILE := $(CODEX_SETTINGS_DIR)/config.toml
LOCAL_BIN_DIR := $(HOME)/.local/bin
AGENTS_CONFIG_DIR := $(HOME)/.config/agents
TMUX_BIN_DIR := $(CURDIR)/tmux/bin
TMUX_CONFIG_DIR := $(CURDIR)/tmux/config

.PHONY: all install install-non-interactive install-skills install-extensions install-tmux build clean help submodule-init plugin-update agents-config check-python

all: help

help:
	@echo "Agents - Skills and Extensions Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install                 Initialize submodules and install skills and extensions"
	@echo "  make install-non-interactive Install for headless/automated environments (skips interactive extensions)"
	@echo "  make install-skills          Install skills only (Amp, Claude Code, Codex, Pi agent)"
	@echo "  make install-extensions      Install extensions only (Pi agent)"
	@echo "  make install-tmux            Install tmux agent integration scripts"
	@echo "  make build                   Build skills with overrides (without installing)"
	@echo "  make plugin-update           Update all plugin submodules to latest"
	@echo "  make clean                   Remove all installed skills, extensions, and build artifacts"
	@echo "  make agents-config           Configure all agents to use their own skills directories"
	@echo "  make help                    Show this help message"
	@echo ""
	@echo "Configuration: plugins.toml"

check-python:
	@$(PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null || \
		(echo "Error: Python 3.11+ required (for tomllib)"; exit 1)

install: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install
	@$(MAKE) install-tmux
	@echo "All skills and extensions installed"

install-non-interactive: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install --non-interactive
	@echo "All skills and extensions installed (non-interactive mode)"

submodule-init:
	@$(PYTHON) $(BUILD_SCRIPT) submodule-init

build: check-python
	@$(PYTHON) $(BUILD_SCRIPT) build

install-skills: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-skills

install-extensions: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-extensions

install-tmux:
	@echo "Installing tmux agent integration..."
	@mkdir -p $(LOCAL_BIN_DIR)
	@mkdir -p $(AGENTS_CONFIG_DIR)
	@ln -sf $(TMUX_BIN_DIR)/codex-notify $(LOCAL_BIN_DIR)/codex-notify
	@ln -sf $(TMUX_BIN_DIR)/agent-status $(LOCAL_BIN_DIR)/agent-status
	@if [ ! -f "$(AGENTS_CONFIG_DIR)/state.json" ]; then \
		cp "$(TMUX_CONFIG_DIR)/state.json" "$(AGENTS_CONFIG_DIR)/state.json"; \
		echo "  Installed $(AGENTS_CONFIG_DIR)/state.json"; \
	else \
		echo "  $(AGENTS_CONFIG_DIR)/state.json already exists; leaving as-is"; \
	fi
	@echo "  Linked codex-notify + agent-status into $(LOCAL_BIN_DIR)"

clean: check-python
	@$(PYTHON) $(BUILD_SCRIPT) clean

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"

agents-config:
	@echo "Configuring agent settings..."
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "Error: jq is required but not installed."; \
		echo "Install with: brew install jq (macOS) or apt install jq (Linux)"; \
		exit 1; \
	fi
	@echo ""
	@echo "Configuring Amp..."
	@mkdir -p $(AMP_SETTINGS_DIR)
	@if [ ! -f "$(AMP_SETTINGS_FILE)" ]; then \
		echo '{}' > "$(AMP_SETTINGS_FILE)"; \
	fi
	@jq '."amp.skills.path" = "~/.config/agents/skills"' \
		"$(AMP_SETTINGS_FILE)" > "$(AMP_SETTINGS_FILE).tmp" && \
		mv "$(AMP_SETTINGS_FILE).tmp" "$(AMP_SETTINGS_FILE)"
	@echo "  $(AMP_SETTINGS_FILE)"
	@echo "    amp.skills.path = ~/.config/agents/skills"
	@echo ""
	@echo "Configuring Pi..."
	@mkdir -p $(PI_SETTINGS_DIR)
	@if [ ! -f "$(PI_SETTINGS_FILE)" ]; then \
		echo '{}' > "$(PI_SETTINGS_FILE)"; \
	fi
	@jq '.skills.enableClaudeUser = false | .skills.enableCodexUser = false' \
		"$(PI_SETTINGS_FILE)" > "$(PI_SETTINGS_FILE).tmp" && \
		mv "$(PI_SETTINGS_FILE).tmp" "$(PI_SETTINGS_FILE)"
	@echo "  $(PI_SETTINGS_FILE)"
	@echo "    skills.enableClaudeUser = false"
	@echo "    skills.enableCodexUser = false"
	@echo ""
	@echo "Claude Code: No configuration needed (uses ~/.claude/skills/)"
	@echo "Codex CLI: No configuration needed (uses ~/.codex/skills/)"
	@echo ""
	@echo "All agents configured!"
