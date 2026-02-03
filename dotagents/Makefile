# Agents Makefile
# Installs skills and extensions for AI coding agents
#
# Configuration is in plugins.toml. Run `make install` to build and install.
# Requires Python 3.11+ (uses tomllib from stdlib).

PYTHON := python3
BUILD_SCRIPT := $(CURDIR)/scripts/build.py

# Paths
LOCAL_BIN_DIR := $(HOME)/.local/bin
HOST_GOOS := $(shell go env GOOS)
HOST_GOARCH := $(shell go env GOARCH)
HOST_TARGET := $(HOST_GOOS)/$(HOST_GOARCH)
AGENT_STATUS_BUILD_DIR := build/agent-status
AGENT_STATUS_HOST_BIN := $(AGENT_STATUS_BUILD_DIR)/$(HOST_GOOS)-$(HOST_GOARCH)/agent-status
AGENT_STATUS_STAMP := $(AGENT_STATUS_BUILD_DIR)/.stamp
AGENT_STATUS_PLIST_SRC := tmux-agent-status/com.agents.agent-status.plist
AGENT_STATUS_PLIST_DST := $(HOME)/Library/LaunchAgents/com.agents.agent-status.plist
AGENT_STATUS_LABEL := com.agents.agent-status

ifeq ($(HOST_GOOS),darwin)
AGENT_STATUS_TARGETS ?= linux/amd64 $(HOST_TARGET)
else
AGENT_STATUS_TARGETS ?= $(HOST_TARGET)
endif
AGENT_STATUS_TARGETS := $(sort $(AGENT_STATUS_TARGETS))

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
AGENT_STATUS_SOURCES := tmux-agent-status/main.go tmux-agent-status/go.mod \
	tmux-agent-status/cmd/*.go tmux-agent-status/internal/**/*.go

$(AGENT_STATUS_STAMP): $(AGENT_STATUS_SOURCES)
	@mkdir -p $(AGENT_STATUS_BUILD_DIR)
	@set -e; \
	for target in $(AGENT_STATUS_TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		out_dir="$(AGENT_STATUS_BUILD_DIR)/$$os-$$arch"; \
		mkdir -p "$$out_dir"; \
		cgo=0; \
		if [ "$$target" = "$(HOST_TARGET)" ]; then cgo=1; fi; \
		(cd tmux-agent-status && \
			CGO_ENABLED=$$cgo GOOS=$$os GOARCH=$$arch \
			go build -o "../$$out_dir/agent-status" .); \
	done
	@touch $@

build-agent-status: $(AGENT_STATUS_STAMP)

install-tmux: build-agent-status
	@mkdir -p ~/.local/bin
	@test -x $(AGENT_STATUS_HOST_BIN) || \
		(echo "Error: $(AGENT_STATUS_HOST_BIN) missing. Run 'make build-agent-status'."; exit 1)
	@ln -sf $(abspath $(AGENT_STATUS_HOST_BIN)) ~/.local/bin/agent-status
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
	rm -rf $(AGENT_STATUS_BUILD_DIR)
	rm -f ~/.local/bin/agent-status

clean: check-python
	@$(PYTHON) $(BUILD_SCRIPT) clean

plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "Plugins updated"

