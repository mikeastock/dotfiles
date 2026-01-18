# Agents Makefile
# Installs skills and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

# Pi settings for pi-skills-config target
PI_SETTINGS_DIR := $(HOME)/.pi/agent
PI_SETTINGS_FILE := $(PI_SETTINGS_DIR)/settings.json

.PHONY: all install install-non-interactive install-skills install-extensions build clean help submodule-init plugin-update pi-skills-config check-python

all: help

help:
	@echo "Agents - Skills and Extensions Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install                 Initialize submodules and install skills and extensions"
	@echo "  make install-non-interactive Install for headless/automated environments (skips interactive extensions)"
	@echo "  make install-skills          Install skills only (Claude Code, Codex, Pi agent)"
	@echo "  make install-extensions      Install extensions only (Pi agent)"
	@echo "  make build                   Build skills with overrides (without installing)"
	@echo "  make plugin-update           Update all plugin submodules to latest"
	@echo "  make clean                   Remove all installed skills, extensions, and build artifacts"
	@echo "  make pi-skills-config        Configure Pi agent to use only Pi-specific skills"
	@echo "  make help                    Show this help message"
	@echo ""
	@echo "Configuration: plugins.toml"

check-python:
	@$(PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null || \
		(echo "Error: Python 3.11+ required (for tomllib)"; exit 1)

install: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install
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

clean: check-python
	@$(PYTHON) $(BUILD_SCRIPT) clean

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"

pi-skills-config:
	@echo "Configuring Pi agent skills settings..."
	@mkdir -p $(PI_SETTINGS_DIR)
	@if [ ! -f "$(PI_SETTINGS_FILE)" ]; then \
		echo '{}' > "$(PI_SETTINGS_FILE)"; \
	fi
	@if command -v jq >/dev/null 2>&1; then \
		jq '.skills.enableClaudeUser = false | .skills.enableCodexUser = false' \
			"$(PI_SETTINGS_FILE)" > "$(PI_SETTINGS_FILE).tmp" && \
			mv "$(PI_SETTINGS_FILE).tmp" "$(PI_SETTINGS_FILE)"; \
		echo "Pi agent settings updated: $(PI_SETTINGS_FILE)"; \
		echo "  skills.enableClaudeUser = false"; \
		echo "  skills.enableCodexUser = false"; \
	else \
		echo "Error: jq is required but not installed."; \
		echo "Install with: brew install jq (macOS) or apt install jq (Linux)"; \
		exit 1; \
	fi
