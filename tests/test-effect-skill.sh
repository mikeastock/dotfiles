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
        local skill_content
        skill_content=$(<"$skills_dir/effect-ts/SKILL.md")
        assert_output_contains "$skill_content" "/data/workspace/code/oss/effect-smol/LLMS.md" "effect-ts routes Effect documentation through LLMS.md"
        assert_output_contains "$skill_content" "https://github.com/Effect-TS/effect-smol" "effect-ts links the Effect source repository"
        assert_output_contains "$skill_content" "/data/workspace/code/oss/opencode" "effect-ts uses the shared opencode reference checkout"
        assert_output_contains "$skill_content" "https://github.com/anomalyco/opencode/tree/v2" "effect-ts links the opencode v2 reference branch"
        assert_output_contains "$skill_content" "/data/workspace/code/oss/executor" "effect-ts uses the shared executor reference checkout"
        assert_output_contains "$skill_content" "https://github.com/UsefulSoftwareCo/executor" "effect-ts links the executor reference repository"
        assert_output_not_contains "$skill_content" ".repos/effect" "effect-ts does not require repository-local Effect source"
        assert_output_not_contains "$skill_content" "agents:" "build metadata is stripped from installed effect-ts"

        local examples_content
        examples_content=$(<"$skills_dir/effect-ts/references/examples.md")
        assert_output_contains "$examples_content" "https://github.com/anomalyco/opencode/tree/v2" "Effect examples link the opencode v2 reference branch"
    done
}

main() {
    test_effect_skill_install
    print_summary
}

main "$@"
