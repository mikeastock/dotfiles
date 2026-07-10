#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

seed_legacy_install() {
    local manifest_path="$SANDBOX_DIR/.local/state/dotfiles/agent-install-manifest.json"

    mkdir -p "$(dirname "$manifest_path")"
    for skills_dir in \
        "$SANDBOX_DIR/.config/agents/skills" \
        "$SANDBOX_DIR/.claude/skills" \
        "$SANDBOX_DIR/.codex/skills" \
        "$SANDBOX_DIR/.agents/skills"; do
        mkdir -p "$skills_dir/effect-examples"
        printf '%s\n' legacy > "$skills_dir/effect-examples/SKILL.md"
    done

    cat > "$manifest_path" <<'EOF'
{
  "targets": {
    "amp.skills": ["effect-examples"],
    "claude.skills": ["effect-examples"],
    "codex.skills": ["effect-examples"],
    "pi.skills": ["effect-examples"]
  },
  "version": 1
}
EOF
}

test_effect_skill_install() {
    log_test "Testing canonical Effect skill installation"
    setup_sandbox
    seed_legacy_install

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make -C "$PROJECT_DIR" install-skills >/dev/null

    for skills_dir in \
        "$SANDBOX_DIR/.config/agents/skills" \
        "$SANDBOX_DIR/.claude/skills" \
        "$SANDBOX_DIR/.codex/skills" \
        "$SANDBOX_DIR/.agents/skills"; do
        assert_dir_exists "$skills_dir/effect-ts" "effect-ts installs in $skills_dir"
        assert_file_not_exists "$skills_dir/effect-examples" "legacy effect-examples is removed from $skills_dir"
        assert_file_exists "$skills_dir/effect-ts/references/examples.md" "Effect examples are disclosed from effect-ts"
        assert_file_exists "$skills_dir/effect-ts/scripts/ensure-reference-repos.sh" "Effect reference setup is installed"

        local skill_content
        skill_content=$(<"$skills_dir/effect-ts/SKILL.md")
        assert_output_contains "$skill_content" "/data/workspace/code/oss/effect-smol/LLMS.md" "effect-ts routes Effect documentation through LLMS.md"
        assert_output_contains "$skill_content" "https://github.com/Effect-TS/effect-smol" "effect-ts links the Effect source repository"
        assert_output_contains "$skill_content" "/data/workspace/code/oss/opencode" "effect-ts uses the shared opencode reference checkout"
        assert_output_contains "$skill_content" "https://github.com/anomalyco/opencode" "effect-ts links the opencode reference repository"
        assert_output_contains "$skill_content" "/data/workspace/code/oss/executor" "effect-ts uses the shared executor reference checkout"
        assert_output_contains "$skill_content" "https://github.com/UsefulSoftwareCo/executor" "effect-ts links the executor reference repository"
        assert_output_not_contains "$skill_content" ".repos/effect" "effect-ts does not require repository-local Effect source"
        assert_output_not_contains "$skill_content" "agents:" "build metadata is stripped from installed effect-ts"
    done
}

seed_reference_checkout() {
    local root=$1
    local name=$2
    local origin=$3
    local marker=$4

    git init --quiet "$root/$name"
    git -C "$root/$name" remote add origin "$origin"
    mkdir -p "$(dirname "$root/$name/$marker")"
    printf '%s\n' fixture > "$root/$name/$marker"
    git -C "$root/$name" add -- "$marker"
    git -C "$root/$name" -c user.name=Test -c user.email=test@example.com commit --quiet -m "test fixture"
}

test_effect_reference_setup() {
    log_test "Testing Effect reference checkout validation"

    local reference_root="$SANDBOX_DIR/reference-repos"
    local setup_script="$PROJECT_DIR/skills/effect-ts/scripts/ensure-reference-repos.sh"
    mkdir -p "$reference_root"

    seed_reference_checkout "$reference_root" effect-smol https://github.com/Effect-TS/effect-smol LLMS.md
    seed_reference_checkout "$reference_root" opencode https://github.com/sst/opencode packages/core/src/catalog.ts
    seed_reference_checkout "$reference_root" executor https://github.com/RhysSullivan/executor.git packages/core/sdk/src/fuma-runtime.ts

    local before
    before=$(for repo in effect-smol opencode executor; do
        git -C "$reference_root/$repo" remote get-url origin
    done)

    EFFECT_REFERENCE_ROOT="$reference_root" "$setup_script"
    EFFECT_REFERENCE_ROOT="$reference_root" "$setup_script"

    local after
    after=$(for repo in effect-smol opencode executor; do
        git -C "$reference_root/$repo" remote get-url origin
    done)
    assert_equals "$after" "$before" "Effect reference setup is idempotent"

    git -C "$reference_root/effect-smol" remote set-url origin https://notgithub.com/Effect-TS/effect-smol
    if EFFECT_REFERENCE_ROOT="$reference_root" "$setup_script" >/dev/null 2>&1; then
        log_error "FAIL: Effect reference setup rejects lookalike GitHub hosts"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    log_info "PASS: Effect reference setup rejects lookalike GitHub hosts"
    TESTS_PASSED=$((TESTS_PASSED + 1))

    git -C "$reference_root/effect-smol" remote set-url origin https://github.com/Effect-TS/effect-smol
    mv "$reference_root/opencode/packages/core/src/catalog.ts" "$reference_root/opencode/packages/core/src/catalog.ts.missing"
    if EFFECT_REFERENCE_ROOT="$reference_root" "$setup_script" >/dev/null 2>&1; then
        log_error "FAIL: Effect reference setup rejects incomplete checkouts"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    log_info "PASS: Effect reference setup rejects incomplete checkouts"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

main() {
    test_effect_skill_install
    test_effect_reference_setup
    print_summary
}

main "$@"
