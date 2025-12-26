# Agents Makefile
# Installs skills and custom tools for AI coding agents
#
# Note: Pi Coding Agent automatically reads Codex skills from ~/.codex/skills,
# so we only install skills there. Tools are Pi-specific.

# Installation directories
PI_TOOLS_DIR := ~/.pi/agent/tools
CLAUDE_SKILLS_DIR := ~/.claude/skills
CODEX_SKILLS_DIR := ~/.codex/skills

# Source directories
SKILLS_SRC := $(CURDIR)/skills
TOOLS_SRC := $(CURDIR)/tools

.PHONY: all install install-skills install-tools install-claude install-codex clean help

all: install

help:
	@echo "Agents - Skills and Tools Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install         Install skills and tools for all agents"
	@echo "  make install-skills  Install skills only (Claude Code, Codex CLI, Pi via Codex)"
	@echo "  make install-tools   Install custom tools only (Pi agent)"
	@echo "  make install-claude  Install skills for Claude Code"
	@echo "  make install-codex   Install skills for Codex CLI (also used by Pi agent)"
	@echo "  make clean           Remove all installed skills and tools"
	@echo "  make help            Show this help message"

install: install-skills install-tools
	@echo "✓ All skills and tools installed"

install-skills: install-claude install-codex
	@echo "✓ Skills installed for all agents"

install-tools:
	@echo "Installing custom tools for Pi agent..."
	@mkdir -p $(PI_TOOLS_DIR)
	@for tool in $(TOOLS_SRC)/*/; do \
		tool_name=$$(basename "$$tool"); \
		echo "  → $$tool_name"; \
		rm -rf "$(PI_TOOLS_DIR)/$$tool_name"; \
		cp -r "$$tool" "$(PI_TOOLS_DIR)/$$tool_name"; \
	done
	@echo "✓ Pi tools installed to $(PI_TOOLS_DIR)"

# Claude Code
install-claude:
	@echo "Installing skills for Claude Code..."
	@mkdir -p $(CLAUDE_SKILLS_DIR)
	@for skill in $(SKILLS_SRC)/*/; do \
		skill_name=$$(basename "$$skill"); \
		echo "  → $$skill_name"; \
		rm -rf "$(CLAUDE_SKILLS_DIR)/$$skill_name"; \
		cp -r "$$skill" "$(CLAUDE_SKILLS_DIR)/$$skill_name"; \
	done
	@echo "✓ Claude Code skills installed to $(CLAUDE_SKILLS_DIR)"

# Codex CLI (also used by Pi Coding Agent)
install-codex:
	@echo "Installing skills for Codex CLI (also used by Pi agent)..."
	@mkdir -p $(CODEX_SKILLS_DIR)
	@for skill in $(SKILLS_SRC)/*/; do \
		skill_name=$$(basename "$$skill"); \
		echo "  → $$skill_name"; \
		rm -rf "$(CODEX_SKILLS_DIR)/$$skill_name"; \
		cp -r "$$skill" "$(CODEX_SKILLS_DIR)/$$skill_name"; \
	done
	@echo "✓ Codex CLI skills installed to $(CODEX_SKILLS_DIR)"

# Clean up
clean:
	@echo "Removing installed skills and tools..."
	@for skill in $(SKILLS_SRC)/*/; do \
		skill_name=$$(basename "$$skill"); \
		rm -rf "$(CLAUDE_SKILLS_DIR)/$$skill_name"; \
		rm -rf "$(CODEX_SKILLS_DIR)/$$skill_name"; \
	done
	@for tool in $(TOOLS_SRC)/*/; do \
		tool_name=$$(basename "$$tool"); \
		rm -rf "$(PI_TOOLS_DIR)/$$tool_name"; \
	done
	@echo "✓ Cleaned up installed skills and tools"
