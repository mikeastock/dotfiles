#!/bin/bash

# Development installation script for dev-browser plugin
# This script removes any existing installation and reinstalls from the current directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARKETPLACE_NAME="dev-browser-marketplace"
PLUGIN_NAME="dev-browser"

# Find claude command - check common locations
if command -v claude &> /dev/null; then
    CLAUDE="claude"
elif [ -x "$HOME/.claude/local/claude" ]; then
    CLAUDE="$HOME/.claude/local/claude"
elif [ -x "/usr/local/bin/claude" ]; then
    CLAUDE="/usr/local/bin/claude"
else
    echo "Error: claude command not found"
    echo "Please install Claude Code or add it to your PATH"
    exit 1
fi

echo "Dev Browser - Development Installation"
echo "======================================="
echo ""

# Step 1: Remove existing plugin if installed
echo "Checking for existing plugin installation..."
if $CLAUDE plugin uninstall "${PLUGIN_NAME}@${MARKETPLACE_NAME}" 2>/dev/null; then
    echo "  Removed existing plugin: ${PLUGIN_NAME}@${MARKETPLACE_NAME}"
else
    echo "  No existing plugin found (skipping)"
fi

# Also try to remove from the GitHub marketplace if it exists
if $CLAUDE plugin uninstall "${PLUGIN_NAME}@sawyerhood/dev-browser" 2>/dev/null; then
    echo "  Removed plugin from GitHub marketplace: ${PLUGIN_NAME}@sawyerhood/dev-browser"
else
    echo "  No GitHub marketplace plugin found (skipping)"
fi

echo ""

# Step 2: Remove existing marketplaces
echo "Checking for existing marketplace..."
if $CLAUDE plugin marketplace remove "${MARKETPLACE_NAME}" 2>/dev/null; then
    echo "  Removed marketplace: ${MARKETPLACE_NAME}"
else
    echo "  Local marketplace not found (skipping)"
fi

if $CLAUDE plugin marketplace remove "sawyerhood/dev-browser" 2>/dev/null; then
    echo "  Removed GitHub marketplace: sawyerhood/dev-browser"
else
    echo "  GitHub marketplace not found (skipping)"
fi

echo ""

# Step 3: Add the local marketplace
echo "Adding local marketplace from: ${SCRIPT_DIR}"
$CLAUDE plugin marketplace add "${SCRIPT_DIR}"
echo "  Added marketplace: ${MARKETPLACE_NAME}"

echo ""

# Step 4: Install the plugin
echo "Installing plugin: ${PLUGIN_NAME}@${MARKETPLACE_NAME}"
$CLAUDE plugin install "${PLUGIN_NAME}@${MARKETPLACE_NAME}"
echo "  Installed plugin successfully"

echo ""
echo "======================================="
echo "Installation complete!"
echo ""
echo "Restart Claude Code to activate the plugin."
