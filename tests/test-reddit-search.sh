#!/usr/bin/env bash
# Offline Reddit search contracts; a live Gemini query is a separate manual check.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"
setup_sandbox
trap cleanup EXIT

assert_success "Reddit search input, source, redirect, and install contracts" \
    env TMPDIR="$SANDBOX_DIR" PYTHONDONTWRITEBYTECODE=1 python3 "$SCRIPT_DIR/test_reddit_search.py"
print_summary
