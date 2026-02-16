# dotagents Makefile
# Installs skills for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

.PHONY: all install install-skills build clean help submodule-init plugin-update check-python

all: help

help:
	@echo "dotagents - Skills Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install            Initialize submodules and install skills"
	@echo "  make install-skills     Install skills only"
	@echo "  make build              Build skills (without installing)"
	@echo "  make plugin-update      Update all plugin submodules to latest"
	@echo "  make clean              Remove all installed skills and build artifacts"
	@echo "  make help               Show this help message"
	@echo ""
	@echo "Configuration: plugins.toml"
	@echo ""
	@echo "Install paths:"
	@echo "  Claude Code:           ~/.claude/skills/"
	@echo "  OpenCode/Pi/Codex:     ~/.agents/skills/"

check-python:
	@$(PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null || \
		(echo "Error: Python 3.11+ required (for tomllib)"; exit 1)

install: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install
	@echo "All skills installed"

submodule-init:
	@$(PYTHON) $(BUILD_SCRIPT) submodule-init

build: check-python
	@$(PYTHON) $(BUILD_SCRIPT) build

install-skills: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-skills

clean: check-python
	@$(PYTHON) $(BUILD_SCRIPT) clean

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"
