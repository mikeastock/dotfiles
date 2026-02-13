# Agents Makefile
# Installs skills and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

.PHONY: all install install-non-interactive install-skills install-extensions install-prompts install-configs build clean help submodule-init plugin-update check-python

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
	@echo "  make install-configs         Install all agent configs (Amp, Codex, Pi)"
	@echo "  make build                   Build skills with overrides (without installing)"
	@echo "  make plugin-update           Update all plugin submodules to latest"
	@echo "  make clean                   Remove all installed skills, extensions, and build artifacts"

	@echo "  make help                    Show this help message"
	@echo ""
	@echo "Configuration: plugins.toml"

check-python:
	@$(PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null || \
		(echo "Error: Python 3.11+ required (for tomllib)"; exit 1)

install: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install
	@echo "All skills, prompt templates, and extensions installed"

install-non-interactive: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install --non-interactive
	@echo "All skills, prompt templates, and extensions installed (non-interactive mode)"

submodule-init:
	@$(PYTHON) $(BUILD_SCRIPT) submodule-init

build: check-python
	@$(PYTHON) $(BUILD_SCRIPT) build

install-skills: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-skills

install-extensions: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-extensions

install-prompts: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-prompts

install-configs: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-configs

clean: check-python
	@$(PYTHON) $(BUILD_SCRIPT) clean

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"
