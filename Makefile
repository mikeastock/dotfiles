# Agents Makefile
# Installs skills, prompt templates, themes, and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py
FORCE_FLAG := $(if $(FORCE),--force,)

.PHONY: all install install-non-interactive install-skills install-amp-plugins install-extensions install-prompts install-themes amp-plugin-types amp-plugin-check package-manager-security-config build clean help submodule-init plugin-update check-python

all: help

help:
	@echo "Agents - Skills, Prompt Templates, and Extensions Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install                 Install agent artifacts and machine dotfiles"
	@echo "  make install FORCE=1         Claim existing unmanaged paths that match managed artifacts"
	@echo "  make install-non-interactive Install for headless/automated environments (skips interactive extensions)"
	@echo "  make install-skills          Install skills only (Amp, Claude Code, Pi agent)"
	@echo "  make install-amp-plugins     Install Amp plugins from amp-plugins/"
	@echo "  make install-extensions      Install extensions only (Pi agent)"
	@echo "  make install-prompts         Install prompt templates only (Pi agent)"
	@echo "  make install-themes          Install themes only (Pi agent)"
	@echo "  make amp-plugin-types        Refresh local Amp plugin TypeScript declarations"
	@echo "  make amp-plugin-check        Refresh Amp plugin declarations and typecheck plugins"
	@echo "  make package-manager-security-config Configure global npm/pnpm/bun/uv package security settings"
	@echo "  make build                   Build skills/prompts/themes (without installing)"
	@echo "  make plugin-update           Update all plugin submodules to latest"
	@echo "  make clean                   Remove all installed skills, extensions, and build artifacts"
	@echo ""
	@echo "  make help                    Show this help message"
	@echo ""
	@echo "Configuration: plugins.toml"

check-python:
	@$(PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null || \
		(echo "Error: Python 3.11+ required (for tomllib)"; exit 1)

install: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install $(FORCE_FLAG)
	@$(CURDIR)/scripts/dotfiles.sh auto
	@echo "All skills, prompt templates, themes, extensions, Amp plugins, and machine dotfiles installed"

install-non-interactive: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install --non-interactive $(FORCE_FLAG)
	@$(CURDIR)/scripts/dotfiles.sh auto --skip-packages --skip-shell
	@echo "All skills, prompt templates, themes, extensions, Amp plugins, and machine dotfiles installed (non-interactive mode)"

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

install-themes: check-python
	@$(PYTHON) "$(BUILD_SCRIPT)" install-themes $(FORCE_FLAG)

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
