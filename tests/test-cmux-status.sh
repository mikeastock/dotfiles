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

cd "$PROJECT_DIR"

run_harness() {
	pnpm exec tsx tests/cmux-status-harness.ts >/dev/null
}

test_cmux_notifications_and_dedupe() {
	log_test "cmux notifications route to tab/panel and dedupe repeats"

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

	PATH="$bin_dir:$PATH" \
	CMUX_LOG="$cmux_log" \
	CMUX_TAB_ID="tab-123" \
	CMUX_PANEL_ID="panel-456" \
	PI_CMUX_NOTIFY_DEDUPE_SECONDS="120" \
	run_harness

	assert_file_exists "$cmux_log" "cmux was invoked"

	local notify_count
	notify_count=$(rg -c "^notify$" "$cmux_log")
	assert_equals "$notify_count" "3" "high-signal notifications only (needs input, complete, failed)"

	local needs_input_count
	needs_input_count=$(rg -c "^Needs input$" "$cmux_log")
	assert_equals "$needs_input_count" "1" "AskUserQuestion duplicate notifications are deduped"

	local complete_count
	complete_count=$(rg -c "^Complete$" "$cmux_log")
	assert_equals "$complete_count" "1" "completion notification emitted once"

	local failed_count
	failed_count=$(rg -c "^Failed$" "$cmux_log")
	assert_equals "$failed_count" "1" "failure notification emitted once"

	local tab_count
	tab_count=$(rg -c "^--tab$" "$cmux_log")
	assert_equals "$tab_count" "3" "notifications include cmux tab routing"

	local panel_count
	panel_count=$(rg -c "^--panel$" "$cmux_log")
	assert_equals "$panel_count" "3" "notifications include cmux panel routing"

	rm -rf "$bin_dir"
	rm -f "$cmux_log"
}

test_no_osascript_fallback() {
	log_test "cmux-only mode does not call osascript fallback"

	local bin_dir
	bin_dir=$(mktemp -d)
	local osascript_log
	osascript_log=$(mktemp)

	cat >"$bin_dir/osascript" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "called" >> "$OSASCRIPT_LOG"
EOF
	chmod +x "$bin_dir/osascript"

	PATH="$bin_dir:$PATH" \
	OSASCRIPT_LOG="$osascript_log" \
	PI_CMUX_NOTIFY_DEDUPE_SECONDS="120" \
	run_harness

	assert_output_not_contains "$(<"$PROJECT_DIR/pi-extensions/cmux-status/index.ts")" "osascript" "extension source has no osascript fallback"

	if [ -s "$osascript_log" ]; then
		log_error "FAIL: osascript was called in cmux-only mode"
		TESTS_FAILED=$((TESTS_FAILED + 1))
	else
		log_info "PASS: osascript fallback not used"
		TESTS_PASSED=$((TESTS_PASSED + 1))
	fi

	rm -rf "$bin_dir"
	rm -f "$osascript_log"
}

main() {
	setup_sandbox

	test_cmux_notifications_and_dedupe
	test_no_osascript_fallback

	print_summary
}

main "$@"
