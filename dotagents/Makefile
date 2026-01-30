# Agents Makefile
# Installs skills and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

# Paths
LOCAL_BIN_DIR := $(HOME)/.local/bin
AGENT_STATUS_BIN := tmux-agent-status/agent-status
AGENT_STATUS_PLIST_SRC := tmux-agent-status/com.agents.agent-status.plist
AGENT_STATUS_PLIST_DST := $(HOME)/Library/LaunchAgents/com.agents.agent-status.plist
AGENT_STATUS_LABEL := com.agents.agent-status

.PHONY: all install install-non-interactive install-skills install-extensions install-configs install-tmux build build-agent-status clean clean-tmux help submodule-init plugin-update check-python

all: help

help:
	@echo "Agents - Skills and Extensions Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install                 Initialize submodules and install skills and extensions"
	@echo "  make install-non-interactive Install for headless/automated environments (skips interactive extensions)"
	@echo "  make install-skills          Install skills only (Amp, Claude Code, Codex, Pi agent)"
	@echo "  make install-extensions      Install extensions only (Pi agent)"
	@echo "  make install-configs         Install all agent configs (Amp, Codex, Pi)"
	@echo "  make install-tmux            Install tmux agent integration scripts"
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

install-configs: check-python
	@$(PYTHON) $(BUILD_SCRIPT) install-configs

# Go daemon build
$(AGENT_STATUS_BIN): tmux-agent-status/main.go tmux-agent-status/cmd/*.go tmux-agent-status/internal/**/*.go
	cd tmux-agent-status && go build -o agent-status .

build-agent-status: $(AGENT_STATUS_BIN)

install-tmux: build-agent-status
	@mkdir -p ~/.local/bin
	@ln -sf $(abspath $(AGENT_STATUS_BIN)) ~/.local/bin/agent-status
	@echo "Installed agent-status to ~/.local/bin/"
ifeq ($(shell uname),Darwin)
	@mkdir -p ~/Library/LaunchAgents
	@sed 's|__HOME__|$(HOME)|g' $(AGENT_STATUS_PLIST_SRC) > $(AGENT_STATUS_PLIST_DST)
	@launchctl bootout gui/$$(id -u) $(AGENT_STATUS_PLIST_DST) 2>/dev/null || true
	@launchctl bootstrap gui/$$(id -u) $(AGENT_STATUS_PLIST_DST)
	@echo "Installed and started launchd service: $(AGENT_STATUS_LABEL)"
endif

clean-tmux:
ifeq ($(shell uname),Darwin)
	@launchctl bootout gui/$$(id -u) $(AGENT_STATUS_PLIST_DST) 2>/dev/null || true
	@rm -f $(AGENT_STATUS_PLIST_DST)
	@echo "Removed launchd service"
endif
	rm -f $(AGENT_STATUS_BIN)
	rm -f ~/.local/bin/agent-status

clean: check-python
	@$(PYTHON) $(BUILD_SCRIPT) clean

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"


