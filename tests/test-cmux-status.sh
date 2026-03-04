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

run_harness() {
	pnpm exec tsx tests/cmux-status-harness.ts >/dev/null
}

test_status_lifecycle() {
	log_test "set-status reflects agent lifecycle states"

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
	run_harness

	assert_file_exists "$cmux_log" "cmux was invoked"

	local set_status_count
	set_status_count=$(rg -c "^set-status$" "$cmux_log")
	assert_equals "$set_status_count" "5" "set-status called for each lifecycle transition"

	if ! rg -q "^notify$" "$cmux_log"; then
		log_info "PASS: no notifications emitted (status-only extension)"
		TESTS_PASSED=$((TESTS_PASSED + 1))
	else
		log_error "FAIL: unexpected notify calls found"
		TESTS_FAILED=$((TESTS_FAILED + 1))
	fi

	# Verify status transitions: running → waiting-input → complete, then running → failed
	local values
	values=$(rg -A2 "^set-status$" "$cmux_log" | rg -v "^set-status$|^pi$|^--|^---$" | tr '\n' ',')
	assert_equals "$values" "running,waiting-input,complete,running,failed," "status transitions match expected lifecycle"

	rm -rf "$bin_dir"
	rm -f "$cmux_log"
}

test_no_routing_flags() {
	log_test "no explicit routing flags (cmux auto-routes via env vars)"

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
	CMUX_WORKSPACE_ID="workspace:123" \
	CMUX_SURFACE_ID="surface:456" \
	run_harness

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

	test_status_lifecycle
	test_no_routing_flags

	print_summary
}

main "$@"
