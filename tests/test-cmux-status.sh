#!/usr/bin/env bash
#
# Validate cmux-status extension behavior.
#
# Usage: ./tests/test-cmux-status.sh
#

source "$(dirname "$0")/test-helpers.sh"

trap cleanup EXIT

log_info "Testing cmux-status extension..."

if ! command -v pnpm &>/dev/null; then
	log_error "pnpm is required but not installed"
	exit 1
fi

if ! command -v rg &>/dev/null; then
	log_error "rg (ripgrep) is required but not installed"
	exit 1
fi

cd "$PROJECT_DIR"

make_fake_cmux() {
	local bin_dir
	bin_dir=$(mktemp -d)
	local cmux_log
	cmux_log=$(mktemp)

	cat >"$bin_dir/cmux" <<'EOF'
#!/usr/bin/env bash
for arg in "$@"; do
	printf '%s\n' "$arg" >> "$CMUX_LOG"
done
printf '%s\n' '---' >> "$CMUX_LOG"
EOF
	chmod +x "$bin_dir/cmux"
	echo "$bin_dir" "$cmux_log"
}

run_harness() {
	TERM_PROGRAM=ghostty PI_CMUX_STATUS_USE_FISH_HELPER=0 \
		pnpm exec tsx tests/cmux-status-harness.ts
}

run_stall_harness() {
	pnpm exec tsx tests/cmux-status-stall-harness.ts >/dev/null
}

test_cmux_status_lifecycle() {
	log_test "cmux set-status reflects agent lifecycle states"

	read -r bin_dir cmux_log < <(make_fake_cmux)

	PATH="$bin_dir:$PATH" \
	CMUX_LOG="$cmux_log" \
	run_harness >/dev/null

	assert_file_exists "$cmux_log" "cmux was invoked"

	# Expected transitions:
	#   session_start: new (clear)
	#   Scenario 1 (answered AskUserQuestion): running → waiting-input → running → complete
	#   Scenario 2 (cancelled AskUserQuestion): running → waiting-input → failed (agent_end deduped)
	#   Scenario 3 (direct error): running → failed
	#   Scenario 4 (shutdown): clear-status
	local set_status_count
	set_status_count=$(rg -c "^set-status$" "$cmux_log")
	assert_equals "$set_status_count" "9" "set-status called for each lifecycle transition"

	local clear_status_count
	clear_status_count=$(rg -c "^clear-status$" "$cmux_log")
	assert_equals "$clear_status_count" "1" "clear-status called on session_shutdown"

	# Verify the full transition sequence
	local values
	values=$(rg -A2 "^set-status$" "$cmux_log" | rg -v "^set-status$|^pi$|^--|^---$" | tr '\n' ',')
	assert_equals "$values" "running,waiting-input,running,complete,running,waiting-input,failed,running,failed," \
		"status transitions match expected lifecycle"

	rm -rf "$bin_dir"
	rm -f "$cmux_log"
}

test_titles_and_ghostty_signals() {
	log_test "updates terminal title and emits ghostty OSC progress/notifications"

	read -r bin_dir cmux_log < <(make_fake_cmux)

	local output
	output=$(PATH="$bin_dir:$PATH" CMUX_LOG="$cmux_log" run_harness)

	# Titles
	assert_output_contains "$output" "TITLE pi - dotfiles 󱞩" "new title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "running title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "waiting for user input title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "failed title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles " "completion title is set"
	assert_output_contains "$output" "TITLE pi - dotfiles" "session shutdown restores base title"

	# Ghostty OSC progress
	assert_output_contains "$output" "OSC <ESC>]9;4;0<BEL>" "new/shutdown emits clear progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;3<BEL>" "running emits indeterminate progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;4<BEL>" "waiting emits paused progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;2;100<BEL>" "failed emits error progress"
	assert_output_contains "$output" "OSC <ESC>]9;4;1;100<BEL>" "done emits completed progress"

	# Ghostty notification
	assert_output_contains "$output" "OSC <ESC>]777;notify;Pi · dotfiles;Needs input<BEL>" "waiting emits ghostty notification"

	rm -rf "$bin_dir"
	rm -f "$cmux_log"
}

test_ask_user_question_resume() {
	log_test "resumes running after AskUserQuestion is answered"

	read -r bin_dir cmux_log < <(make_fake_cmux)

	PATH="$bin_dir:$PATH" \
	CMUX_LOG="$cmux_log" \
	run_harness >/dev/null

	# After a non-cancelled AskUserQuestion, the status should go back to running.
	local values
	values=$(rg -A2 "^set-status$" "$cmux_log" | rg -v "^set-status$|^pi$|^--|^---$" | tr '\n' ',')

	# The first three transitions should be: running → waiting-input → running
	local first_three
	first_three=$(echo "$values" | cut -d, -f1-3)
	assert_equals "$first_three" "running,waiting-input,running" \
		"answered AskUserQuestion resumes to running"

	rm -rf "$bin_dir"
	rm -f "$cmux_log"
}

test_stall_detection() {
	log_test "agent goes stalled after inactivity and recovers on activity"

	read -r bin_dir cmux_log < <(make_fake_cmux)

	PATH="$bin_dir:$PATH" \
	CMUX_LOG="$cmux_log" \
	PI_CMUX_STATUS_STALL_TIMEOUT_MS=50 \
	run_stall_harness

	assert_file_exists "$cmux_log" "cmux was invoked"

	# Expected: running → stalled → running → complete, then clear-status
	local values
	values=$(rg -A2 "^set-status$" "$cmux_log" | rg -v "^set-status$|^pi$|^--|^---$" | tr '\n' ',')
	assert_equals "$values" "running,stalled,running,complete," \
		"stall detection fires and recovers on activity"

	local clear_status_count
	clear_status_count=$(rg -c "^clear-status$" "$cmux_log")
	assert_equals "$clear_status_count" "1" "clear-status called on session_shutdown"

	rm -rf "$bin_dir"
	rm -f "$cmux_log"
}

test_no_routing_flags() {
	log_test "no explicit routing flags (cmux auto-routes via env vars)"

	read -r bin_dir cmux_log < <(make_fake_cmux)

	PATH="$bin_dir:$PATH" \
	CMUX_LOG="$cmux_log" \
	CMUX_WORKSPACE_ID="workspace:123" \
	CMUX_SURFACE_ID="surface:456" \
	run_harness >/dev/null

	if ! rg -q "^--workspace$\|^--surface$\|^--tab$\|^--panel$" "$cmux_log"; then
		log_info "PASS: no explicit routing flags in cmux calls"
		TESTS_PASSED=$((TESTS_PASSED + 1))
	else
		log_error "FAIL: unexpected routing flags found in cmux calls"
		TESTS_FAILED=$((TESTS_FAILED + 1))
	fi

	rm -rf "$bin_dir"
	rm -f "$cmux_log"
}

main() {
	setup_sandbox

	test_cmux_status_lifecycle
	test_titles_and_ghostty_signals
	test_ask_user_question_resume
	test_stall_detection
	test_no_routing_flags

	print_summary
}

main "$@"
