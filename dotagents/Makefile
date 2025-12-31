# Agents Makefile
# Installs skills and custom tools for AI coding agents
#
# Skills are built from:
#   1. plugins/<name>/skills/ (git submodules, filtered by <name>-enabled.txt if present)
#   2. skills/ (your custom skills)
#
# Overrides in skill-overrides/<skill>-<agent>.md are prepended during build.

# Installation directories
PI_TOOLS_DIR := $(HOME)/.pi/agent/tools
PI_HOOKS_DIR := $(HOME)/.pi/agent/hooks
CLAUDE_SKILLS_DIR := $(HOME)/.claude/skills
CODEX_SKILLS_DIR := $(HOME)/.codex/skills
PI_SKILLS_DIR := $(HOME)/.pi/agent/skills

# Source directories
SKILLS_SRC := $(CURDIR)/skills
PLUGINS_DIR := $(CURDIR)/plugins
OVERRIDES_DIR := $(CURDIR)/skill-overrides
TOOLS_SRC := $(CURDIR)/tools
HOOKS_SRC := $(CURDIR)/hooks
BUILD_DIR := $(CURDIR)/build

# Agents that get skills installed
AGENTS := claude pi

.PHONY: all install install-skills install-tools install-hooks clean help build submodule-init plugin-update pi-skills-config

all: help

help:
	@echo "Agents - Skills and Tools Installer"
	@echo ""
	@echo "Usage:"
	@echo "  make install         Initialize submodules and install skills, tools, and hooks"
	@echo "  make install-skills  Install skills only (Claude Code, Pi agent)"
	@echo "  make install-tools   Install custom tools only (Pi agent)"
	@echo "  make install-hooks   Install hooks only (Pi agent)"
	@echo "  make build           Build skills with overrides (without installing)"
	@echo "  make plugin-update   Update all plugin submodules to latest"
	@echo "  make clean           Remove all installed skills, tools, hooks, and build artifacts"
	@echo "  make pi-skills-config  Configure Pi agent to use only Pi-specific skills"
	@echo "  make help            Show this help message"

install: submodule-init install-skills install-tools install-hooks
	@echo "✓ All skills, tools, and hooks installed"

# Initialize git submodules
submodule-init:
	@echo "Initializing git submodules..."
	@git submodule update --init --recursive
	@echo "✓ Submodules initialized"

install-skills: build
	@echo "Installing skills for Claude Code..."
	@mkdir -p $(CLAUDE_SKILLS_DIR)
	@for skill in $(BUILD_DIR)/claude/*/; do \
		if [ -d "$$skill" ]; then \
			skill_name=$$(basename "$$skill"); \
			echo "  → $$skill_name"; \
			rm -rf "$(CLAUDE_SKILLS_DIR)/$$skill_name"; \
			cp -r "$$skill" "$(CLAUDE_SKILLS_DIR)/$$skill_name"; \
		fi \
	done
	@echo "✓ Claude Code skills installed to $(CLAUDE_SKILLS_DIR)"
	@echo ""
	@echo "Installing skills for Codex CLI..."
	@mkdir -p $(CODEX_SKILLS_DIR)
	@for skill in $(BUILD_DIR)/pi/*/; do \
		if [ -d "$$skill" ]; then \
			skill_name=$$(basename "$$skill"); \
			echo "  → $$skill_name"; \
			rm -rf "$(CODEX_SKILLS_DIR)/$$skill_name"; \
			cp -r "$$skill" "$(CODEX_SKILLS_DIR)/$$skill_name"; \
		fi \
	done
	@echo "✓ Codex CLI skills installed to $(CODEX_SKILLS_DIR)"
	@echo ""
	@echo "Installing skills for Pi agent..."
	@mkdir -p $(PI_SKILLS_DIR)
	@for skill in $(BUILD_DIR)/pi/*/; do \
		if [ -d "$$skill" ]; then \
			skill_name=$$(basename "$$skill"); \
			echo "  → $$skill_name"; \
			rm -rf "$(PI_SKILLS_DIR)/$$skill_name"; \
			cp -r "$$skill" "$(PI_SKILLS_DIR)/$$skill_name"; \
		fi \
	done
	@echo "✓ Pi agent skills installed to $(PI_SKILLS_DIR)"

install-tools:
	@echo "Installing custom tools for Pi agent..."
	@mkdir -p $(PI_TOOLS_DIR)
	@if [ -d "$(TOOLS_SRC)/pi" ]; then \
		for tool in $(TOOLS_SRC)/pi/*/; do \
			if [ -d "$$tool" ]; then \
				tool_name=$$(basename "$$tool"); \
				echo "  → $$tool_name"; \
				rm -rf "$(PI_TOOLS_DIR)/$$tool_name"; \
				cp -r "$$tool" "$(PI_TOOLS_DIR)/$$tool_name"; \
			fi \
		done; \
	fi
	@echo "✓ Pi tools installed to $(PI_TOOLS_DIR)"

install-hooks:
	@echo "Installing hooks for Pi agent..."
	@mkdir -p $(PI_HOOKS_DIR)
	@if [ -d "$(HOOKS_SRC)/pi" ]; then \
		for hook in $(HOOKS_SRC)/pi/*/; do \
			if [ -d "$$hook" ]; then \
				hook_name=$$(basename "$$hook"); \
				echo "  → $$hook_name"; \
				rm -rf "$(PI_HOOKS_DIR)/$$hook_name"; \
				cp -r "$$hook" "$(PI_HOOKS_DIR)/$$hook_name"; \
			fi \
		done; \
	fi
	@echo "✓ Pi hooks installed to $(PI_HOOKS_DIR)"

# Build skills with overrides applied
build:
	@echo "Building skills..."
	@rm -rf $(BUILD_DIR)/claude $(BUILD_DIR)/pi
	@mkdir -p $(BUILD_DIR)/claude $(BUILD_DIR)/pi
	@# Process each plugin
	@for plugin_dir in $(PLUGINS_DIR)/*/; do \
		if [ -d "$$plugin_dir/skills" ]; then \
			plugin_name=$$(basename "$$plugin_dir"); \
			enabled_file="$(PLUGINS_DIR)/$${plugin_name}-enabled.txt"; \
			for skill_dir in $$plugin_dir/skills/*/; do \
				if [ -d "$$skill_dir" ]; then \
					skill_name=$$(basename "$$skill_dir"); \
					if [ -f "$$enabled_file" ]; then \
						if ! grep -q "^$$skill_name$$" "$$enabled_file"; then \
							continue; \
						fi; \
					fi; \
					for agent in $(AGENTS); do \
						mkdir -p "$(BUILD_DIR)/$$agent/$$skill_name"; \
						override_file="$(OVERRIDES_DIR)/$${skill_name}-$${agent}.md"; \
						if [ -f "$$override_file" ]; then \
							cat "$$skill_dir/SKILL.md" "$$override_file" > "$(BUILD_DIR)/$$agent/$$skill_name/SKILL.md"; \
						else \
							cp "$$skill_dir/SKILL.md" "$(BUILD_DIR)/$$agent/$$skill_name/SKILL.md"; \
						fi; \
						for extra in $$skill_dir/*; do \
							if [ "$$(basename $$extra)" != "SKILL.md" ] && [ -e "$$extra" ]; then \
								cp -r "$$extra" "$(BUILD_DIR)/$$agent/$$skill_name/"; \
							fi; \
						done; \
					done; \
					echo "  → $$skill_name (from $$plugin_name)"; \
				fi; \
			done; \
		fi; \
	done
	@# Process custom skills
	@if [ -d "$(SKILLS_SRC)" ]; then \
		for skill_dir in $(SKILLS_SRC)/*/; do \
			if [ -d "$$skill_dir" ]; then \
				skill_name=$$(basename "$$skill_dir"); \
				for agent in $(AGENTS); do \
					mkdir -p "$(BUILD_DIR)/$$agent/$$skill_name"; \
					override_file="$(OVERRIDES_DIR)/$${skill_name}-$${agent}.md"; \
					if [ -f "$$override_file" ]; then \
						cat "$$skill_dir/SKILL.md" "$$override_file" > "$(BUILD_DIR)/$$agent/$$skill_name/SKILL.md"; \
					else \
						cp "$$skill_dir/SKILL.md" "$(BUILD_DIR)/$$agent/$$skill_name/SKILL.md"; \
					fi; \
					for extra in $$skill_dir/*; do \
						if [ "$$(basename $$extra)" != "SKILL.md" ] && [ -e "$$extra" ]; then \
							cp -r "$$extra" "$(BUILD_DIR)/$$agent/$$skill_name/"; \
						fi; \
					done; \
				done; \
				echo "  → $$skill_name (custom)"; \
			fi; \
		done; \
	fi
	@echo "✓ Skills built to $(BUILD_DIR)"

# Clean up
clean:
	@echo "Removing installed skills, tools, and hooks..."
	@# Clean Claude skills (copied from build/claude)
	@if [ -d "$(BUILD_DIR)/claude" ]; then \
		for skill in $(BUILD_DIR)/claude/*/; do \
			if [ -d "$$skill" ]; then \
				skill_name=$$(basename "$$skill"); \
				rm -rf "$(CLAUDE_SKILLS_DIR)/$$skill_name"; \
			fi \
		done; \
	fi
	@# Clean Codex skills (copied from build/pi)
	@if [ -d "$(BUILD_DIR)/pi" ]; then \
		for skill in $(BUILD_DIR)/pi/*/; do \
			if [ -d "$$skill" ]; then \
				skill_name=$$(basename "$$skill"); \
				rm -rf "$(CODEX_SKILLS_DIR)/$$skill_name"; \
			fi \
		done; \
	fi
	@# Clean Pi skills (copied from build/pi)
	@if [ -d "$(BUILD_DIR)/pi" ]; then \
		for skill in $(BUILD_DIR)/pi/*/; do \
			if [ -d "$$skill" ]; then \
				skill_name=$$(basename "$$skill"); \
				rm -rf "$(PI_SKILLS_DIR)/$$skill_name"; \
			fi \
		done; \
	fi
	@# Clean Pi tools
	@if [ -d "$(TOOLS_SRC)/pi" ]; then \
		for tool in $(TOOLS_SRC)/pi/*/; do \
			if [ -d "$$tool" ]; then \
				tool_name=$$(basename "$$tool"); \
				rm -rf "$(PI_TOOLS_DIR)/$$tool_name"; \
			fi \
		done; \
	fi
	@# Clean Pi hooks
	@if [ -d "$(HOOKS_SRC)/pi" ]; then \
		for hook in $(HOOKS_SRC)/pi/*/; do \
			if [ -d "$$hook" ]; then \
				hook_name=$$(basename "$$hook"); \
				rm -rf "$(PI_HOOKS_DIR)/$$hook_name"; \
			fi \
		done; \
	fi
	@# Remove build directory
	@rm -rf $(BUILD_DIR)/claude $(BUILD_DIR)/pi
	@echo "✓ Cleaned up installed skills, tools, and hooks"

# Update all plugin submodules
plugin-update:
	@echo "Updating plugin submodules..."
	@git submodule update --remote --merge
	@echo "✓ Plugins updated"

# Pi skills configuration directory
PI_SETTINGS_DIR := $(HOME)/.pi/agent
PI_SETTINGS_FILE := $(PI_SETTINGS_DIR)/settings.json

# Configure Pi agent skills settings
# Disables Claude and Codex skill sources to avoid duplicates when using this repo
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
		echo "✓ Pi agent settings updated: $(PI_SETTINGS_FILE)"; \
		echo "  skills.enableClaudeUser = false"; \
		echo "  skills.enableCodexUser = false"; \
	else \
		echo "Error: jq is required but not installed."; \
		echo "Install with: brew install jq (macOS) or apt install jq (Linux)"; \
		exit 1; \
	fi
