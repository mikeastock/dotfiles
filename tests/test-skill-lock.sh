#!/usr/bin/env bash
#
# Tests for scripts/skill_lock.py (skills CLI lock + vendor bridge)
#
# Usage: ./tests/test-skill-lock.sh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

SKILL_LOCK_SCRIPT="$PROJECT_DIR/scripts/skill_lock.py"

setup_skill_lock_sandbox() {
    # Reuse one sandbox HOME; reset the fake repo root between tests.
    if [ -z "$SANDBOX_DIR" ] || [ ! -d "$SANDBOX_DIR" ]; then
        setup_sandbox
    fi
    export SKILL_LOCK_ROOT="$SANDBOX_DIR/repo"
    rm -rf "$SKILL_LOCK_ROOT"
    mkdir -p "$SKILL_LOCK_ROOT"
}

write_lock() {
    cat > "$SKILL_LOCK_ROOT/skills-lock.json" <<'EOF'
{
  "version": 1,
  "skills": {
    "demo-skill": {
      "source": "example/demo",
      "sourceType": "github",
      "skillPath": "skills/demo-skill/SKILL.md",
      "computedHash": "abc123"
    },
    "other-skill": {
      "source": "example/other",
      "sourceType": "github",
      "skillPath": "skills/other-skill/SKILL.md",
      "computedHash": "def456"
    }
  }
}
EOF
}

stage_skill() {
    local name="$1"
    local body="${2:-# ${name}}"
    mkdir -p "$SKILL_LOCK_ROOT/.agents/skills/$name"
    cat > "$SKILL_LOCK_ROOT/.agents/skills/$name/SKILL.md" <<EOF
---
name: ${name}
description: Test skill ${name}
---

${body}
EOF
}

test_vendor_copies_locked_skills() {
    log_test "skill_lock vendor copies staged locked skills into skills/"
    setup_skill_lock_sandbox
    write_lock
    stage_skill "demo-skill" "Demo body v1"
    stage_skill "other-skill" "Other body"

    local output
    output=$(python3 "$SKILL_LOCK_SCRIPT" vendor 2>&1)

    assert_output_contains "$output" "vendored demo-skill" "Vendors demo-skill"
    assert_output_contains "$output" "vendored other-skill" "Vendors other-skill"
    assert_file_exists "$SKILL_LOCK_ROOT/skills/demo-skill/SKILL.md" "demo-skill vendored"
    assert_file_exists "$SKILL_LOCK_ROOT/skills/other-skill/SKILL.md" "other-skill vendored"
    assert_output_contains "$(cat "$SKILL_LOCK_ROOT/skills/demo-skill/SKILL.md")" "Demo body v1" "Content preserved"
}

test_vendor_overwrites_existing() {
    log_test "skill_lock vendor overwrites existing skills/ copies"
    setup_skill_lock_sandbox
    write_lock
    mkdir -p "$SKILL_LOCK_ROOT/skills/demo-skill"
    echo "old content" > "$SKILL_LOCK_ROOT/skills/demo-skill/SKILL.md"
    stage_skill "demo-skill" "new content"
    # other-skill missing from staging — should skip
    local output
    output=$(python3 "$SKILL_LOCK_SCRIPT" vendor 2>&1)

    assert_output_contains "$output" "vendored demo-skill" "Re-vendors demo-skill"
    assert_output_contains "$output" "skip other-skill" "Skips unstaged other-skill"
    assert_output_contains "$(cat "$SKILL_LOCK_ROOT/skills/demo-skill/SKILL.md")" "new content" "Overwrote old content"
}

test_vendor_empty_lock() {
    log_test "skill_lock vendor handles empty lockfile"
    setup_skill_lock_sandbox
    cat > "$SKILL_LOCK_ROOT/skills-lock.json" <<'EOF'
{
  "version": 1,
  "skills": {}
}
EOF

    local output
    output=$(python3 "$SKILL_LOCK_SCRIPT" vendor 2>&1)

    assert_output_contains "$output" "No skills in skills-lock.json" "Reports empty lock"
}

test_vendor_fails_when_nothing_staged() {
    log_test "skill_lock vendor fails when lock has entries but staging is empty"
    setup_skill_lock_sandbox
    write_lock

    local output status=0
    output=$(python3 "$SKILL_LOCK_SCRIPT" vendor 2>&1) || status=$?

    assert_equals "$status" "1" "Exits non-zero when nothing staged"
    assert_output_contains "$output" "no staged skills found" "Explains missing staging"
}

test_rejects_unsafe_skill_name() {
    log_test "skill_lock vendor rejects path-traversal skill names"
    setup_skill_lock_sandbox
    cat > "$SKILL_LOCK_ROOT/skills-lock.json" <<'EOF'
{
  "version": 1,
  "skills": {
    "../escape": {
      "source": "evil/repo",
      "sourceType": "github",
      "skillPath": "SKILL.md",
      "computedHash": "x"
    }
  }
}
EOF
    mkdir -p "$SKILL_LOCK_ROOT/.agents/skills"
    # Even if a weird staged path existed, name validation should fail first.
    local output status=0
    output=$(python3 "$SKILL_LOCK_SCRIPT" vendor 2>&1) || status=$?

    assert_equals "$status" "1" "Exits non-zero for unsafe name"
    assert_output_contains "$output" "unsafe skill name" "Reports unsafe skill name"
}

test_make_help_lists_skill_commands() {
    log_test "make help lists skill-lock commands"
    cd "$PROJECT_DIR"
    local output
    output=$(make help 2>&1)

    assert_output_contains "$output" "make skill-add" "Help shows skill-add"
    assert_output_contains "$output" "make skill-vendor" "Help shows skill-vendor"
    assert_output_contains "$output" "make skill-update" "Help shows skill-update"
    assert_output_contains "$output" "make skill-sync" "Help shows skill-sync"
}

test_make_skill_add_requires_source() {
    log_test "make skill-add requires SOURCE"
    cd "$PROJECT_DIR"
    local output status=0
    output=$(make skill-add 2>&1) || status=$?

    # GNU make reports recipe failures as exit status 2
    if [ "$status" -ne 0 ]; then
        log_info "PASS: make skill-add without SOURCE fails (exit $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: make skill-add without SOURCE should fail"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    assert_output_contains "$output" "SOURCE=" "Usage mentions SOURCE"
}

main() {
    log_info "Starting skill-lock tests"
    log_info "Project directory: $PROJECT_DIR"

    test_vendor_copies_locked_skills
    test_vendor_overwrites_existing
    test_vendor_empty_lock
    test_vendor_fails_when_nothing_staged
    test_rejects_unsafe_skill_name
    test_make_help_lists_skill_commands
    test_make_skill_add_requires_source

    print_summary
}

main
