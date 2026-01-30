# Agents Makefile
# Installs skills and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

# Agent settings directories
AMP_SETTINGS_DIR := $(HOME)/.config/amp
AMP_SETTINGS_FILE := $(AMP_SETTINGS_DIR)/settings.json
CODEX_SETTINGS_DIR := $(HOME)/.codex
CODEX_SETTINGS_FILE := $(CODEX_SETTINGS_DIR)/config.toml
LOCAL_BIN_DIR := $(HOME)/.local/bin
AGENTS_CONFIG_DIR := $(HOME)/.config/agents
TMUX_BIN_DIR := $(CURDIR)/tmux-agent-status/bin
TMUX_CONFIG_DIR := $(CURDIR)/tmux-agent-status/config
AGENT_STATUS_GO := tmux-agent-status/agent-status-go

.PHONY: all install install-non-interactive install-skills install-extensions install-tmux build build-agent-status clean clean-tmux help submodule-init plugin-update agents-config check-python

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

# Go daemon build
$(AGENT_STATUS_GO): tmux-agent-status/main.go tmux-agent-status/cmd/*.go tmux-agent-status/internal/**/*.go
	cd tmux-agent-status && go build -o agent-status-go .

build-agent-status: $(AGENT_STATUS_GO)

install-tmux: build-agent-status
	@mkdir -p ~/.local/bin
	@ln -sf $(abspath $(AGENT_STATUS_GO)) ~/.local/bin/agent-status
	@echo "Installed agent-status to ~/.local/bin/"

clean-tmux:
	rm -f $(AGENT_STATUS_GO)
	rm -f ~/.local/bin/agent-status

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
	@echo "Pi: Configured via 'make install' (agent-configs/pi-settings.json)"
	@echo "Claude Code: No configuration needed (uses ~/.claude/skills/)"
	@echo "Codex CLI: No configuration needed (uses ~/.codex/skills/)"
	@echo ""
	@echo "All agents configured!"
