#!/usr/bin/env bash
#
# Validate tab-status extension behavior.
#
# Usage: ./tests/test-tab-status.sh
#

source "$(dirname "$0")/test-helpers.sh"

trap cleanup EXIT

log_info "Testing tab-status extension..."

if ! command -v pnpm &>/dev/null; then
	log_error "pnpm is required but not installed"
	exit 1
fi

cd "$PROJECT_DIR"

run_harness() {
	TERM_PROGRAM=ghostty PI_TAB_STATUS_USE_FISH_HELPER=0 pnpm exec tsx tests/tab-status-harness.ts
}

test_titles_and_ghostty_signals() {
	log_test "tab-status updates title and emits ghostty OSC progress/notifications"

	local output
	output=$(run_harness)

	assert_output_contains "$output" "TITLE pi - dotfiles 󱞩" "new title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "running title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "waiting for user input title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "failed title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "completion title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles" "session shutdown restores base title"

	assert_output_contains "$output" "OSC <ESC>]9;4;3<BEL>" "running emits indeterminate progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;4<BEL>" "waiting emits paused progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;2;100<BEL>" "failed emits error progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;1;100<BEL>" "done emits completed progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;0<BEL>" "shutdown clears progress"
	assert_output_contains "$output" "OSC <ESC>]777;notify;Pi · dotfiles;Needs input<BEL>" "waiting emits ghostty notification"
}

main() {
	setup_sandbox
	test_titles_and_ghostty_signals
	print_summary
}

main "$@"
