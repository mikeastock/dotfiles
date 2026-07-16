#!/usr/bin/env bash
#
# Test script for Makefile commands
# Creates a sandbox filesystem to test installations without affecting real agent directories
#
# Usage: ./tests/test-make.sh
#

# Source shared test helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

# Set trap for cleanup on exit
trap cleanup EXIT

# Test: make help
test_make_help() {
    log_test "Testing 'make help'"
    cd "$PROJECT_DIR"

    local output
    output=$(make help 2>&1)

    assert_output_contains "$output" "Usage:" "Help shows usage"
    assert_output_contains "$output" "make install" "Help shows install command"
    assert_output_contains "$output" "make install-amp-plugins" "Help shows Amp plugin install command"
    assert_output_contains "$output" "make install-tools" "Help shows external tool install command"
    assert_output_contains "$output" "make install-prompts" "Help shows install-prompts command"
    assert_output_contains "$output" "make install-themes" "Help shows install-themes command"
    assert_output_contains "$output" "make build" "Help shows build command"
    assert_output_contains "$output" "make clean" "Help shows clean command"
    assert_output_contains "$output" "Dotfiles:" "Help shows dotfiles section"
    assert_output_contains "$output" "make dot-clean" "Help shows dot-clean command"
}

# Test: make install-tools installs pinned tools without configuring agents
test_make_install_tools() {
    log_test "Testing 'make install-tools' (sandboxed)"
    cd "$PROJECT_DIR"

    local fake_installer args_log output
    fake_installer="$SANDBOX_DIR/dcg-install.sh"
    args_log="$SANDBOX_DIR/dcg-install-args.log"
    cat > "$fake_installer" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$DCG_TEST_ARGS_LOG"
mkdir -p "$HOME/.local/bin"
printf '#!/usr/bin/env bash\necho 0.6.5\n' > "$HOME/.local/bin/dcg"
chmod +x "$HOME/.local/bin/dcg"
EOF
    chmod +x "$fake_installer"

    output=$(HOME="$SANDBOX_DIR" DCG_INSTALLER_PATH="$fake_installer" DCG_TEST_ARGS_LOG="$args_log" make install-tools 2>&1)

    assert_output_contains "$output" "Installing external tools" "Install shows external tool progress"
    assert_file_exists "$SANDBOX_DIR/.local/bin/dcg" "dcg binary was installed"

    local args
    args=$(<"$args_log")
    assert_output_contains "$args" "--version" "dcg installer receives a pinned version flag"
    assert_output_contains "$args" "v0.6.5" "dcg installer receives the configured version"
    assert_output_contains "$args" "--dest" "dcg installer receives an explicit destination"
    assert_output_contains "$args" "$SANDBOX_DIR/.local/bin" "dcg installs under the active HOME"
    assert_output_contains "$args" "--verify" "dcg installer runs its self-test"
    assert_output_contains "$args" "--no-configure" "dcg installer cannot mutate agent configs"
}

# Test: make build
test_make_build() {
    log_test "Testing 'make build'"
    cd "$PROJECT_DIR"

    # Clean first
    rm -rf "$PROJECT_DIR/build/claude" "$PROJECT_DIR/build/pi"

    # Run build
    local output
    output=$(make build 2>&1)

    assert_output_contains "$output" "Building skills" "Build shows skill progress"
    assert_output_contains "$output" "Building prompt templates" "Build shows prompt progress"
    assert_output_contains "$output" "Built" "Build shows completion"

    # Check build directories were created
    assert_dir_exists "$PROJECT_DIR/build/amp" "Build created amp directory"
    assert_dir_exists "$PROJECT_DIR/build/claude" "Build created claude directory"
    assert_dir_exists "$PROJECT_DIR/build/pi" "Build created pi directory"
    assert_dir_exists "$PROJECT_DIR/build/prompts/pi" "Build created Pi prompt directory"
    assert_file_exists "$PROJECT_DIR/build/prompts/pi/refactor-pass.md" "Build created refactor-pass prompt template"
    assert_dir_exists "$PROJECT_DIR/build/themes/pi" "Build created Pi themes directory"
    assert_file_exists "$PROJECT_DIR/build/themes/pi/catppuccin-latte.json" "Build created catppuccin-latte theme"
    assert_file_exists "$PROJECT_DIR/build/themes/pi/catppuccin-mocha.json" "Build created catppuccin-mocha theme"

    # Check that skills were built (at least one skill should exist)
    local skill_count
    skill_count=$(find "$PROJECT_DIR/build/claude" -maxdepth 1 -type d | wc -l)
    if [ "$skill_count" -gt 1 ]; then
        log_info "PASS: Build created skills ($((skill_count - 1)) skills found)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Build did not create any skills"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Check that SKILL.md files exist in built skills
    local has_skill_md=false
    for skill_dir in "$PROJECT_DIR/build/claude"/*/; do
        if [ -f "${skill_dir}SKILL.md" ]; then
            has_skill_md=true
            break
        fi
    done
    if $has_skill_md; then
        log_info "PASS: Built skills contain SKILL.md files"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Built skills missing SKILL.md files"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # breadboard-reflection upstream skill has no frontmatter; build should add description
    local breadboard_skill="$PROJECT_DIR/build/claude/breadboard-reflection/SKILL.md"
    assert_file_exists "$breadboard_skill" "breadboard-reflection skill is built"
    assert_file_exists "$PROJECT_DIR/skills/brainstorming/SKILL.md" "brainstorming skill is vendored locally"
    assert_file_exists "$PROJECT_DIR/skills/writing-plans/SKILL.md" "writing-plans skill is vendored locally"
    assert_file_exists "$PROJECT_DIR/skills/executing-plans/SKILL.md" "executing-plans skill is vendored locally"
    for agent in amp claude pi; do
        for skill in brainstorming writing-plans executing-plans; do
            assert_file_not_exists "$PROJECT_DIR/build/$agent/$skill" "$agent excludes $skill from the build"
        done
    done
    assert_file_exists "$PROJECT_DIR/build/subagents/pi/architecture-reviewer.md" "Build includes architecture-reviewer subagent"
    assert_file_exists "$PROJECT_DIR/build/claude/teach/SKILL.md" "Claude builds Matt Pocock teach skill"
    assert_file_exists "$PROJECT_DIR/build/claude/writing-great-skills/SKILL.md" "Claude builds Matt Pocock writing-great-skills skill"
    assert_file_exists "$PROJECT_DIR/build/amp/x-search/SKILL.md" "Amp builds x-search skill"
    assert_file_exists "$PROJECT_DIR/build/claude/x-search/SKILL.md" "Claude builds x-search skill"
    assert_file_exists "$PROJECT_DIR/build/pi/x-search/SKILL.md" "Pi builds x-search skill"
    assert_file_not_exists "$PROJECT_DIR/build/claude/semantic-commit" "semantic-commit skill is no longer built"
    for agent in amp claude pi; do
        assert_file_not_exists "$PROJECT_DIR/build/$agent/test-driven-development" "$agent no longer builds test-driven-development"
        assert_file_not_exists "$PROJECT_DIR/build/$agent/systematic-debugging" "$agent no longer builds systematic-debugging"
    done

    for agent in amp claude codex pi; do
        assert_file_exists "$PROJECT_DIR/build/$agent/effect/SKILL.md" "$agent builds the vendored effect skill"
        assert_file_exists "$PROJECT_DIR/build/$agent/effect/references/SCHEMA.md" "$agent builds effect references"
        assert_file_not_exists "$PROJECT_DIR/build/$agent/effect-ts" "$agent no longer builds effect-ts"
    done

    local effect_content
    effect_content=$(<"$PROJECT_DIR/build/codex/effect/SKILL.md")
    assert_output_contains "$effect_content" "name: effect" "Built effect skill keeps its canonical name"
    assert_output_not_contains "$effect_content" "agents: amp, claude, codex, pi" "Build strips repository-specific agent metadata"

    local breadboard_content
    breadboard_content=$(<"$breadboard_skill")
    assert_output_contains "$breadboard_content" "name: breadboard-reflection" "breadboard-reflection has normalized name"
    assert_output_contains "$breadboard_content" "description:" "breadboard-reflection has synthesized description"

    local shaping_skill shaping_content openai_metadata direct_policy_count
    for shaping_skill in shaping breadboarding breadboard-reflection; do
        for agent in claude pi; do
            shaping_content=$(<"$PROJECT_DIR/build/$agent/$shaping_skill/SKILL.md")
            assert_output_contains "$shaping_content" "disable-model-invocation: true" "$agent makes $shaping_skill user-invocable only"
        done

        shaping_content=$(<"$PROJECT_DIR/build/amp/$shaping_skill/SKILL.md")
        assert_output_not_contains "$shaping_content" "disable-model-invocation: true" "Amp build leaves $shaping_skill invocation metadata unchanged"

        assert_file_exists "$PROJECT_DIR/build/pi/$shaping_skill/agents/openai.yaml" "Pi/shared build includes Codex policy for $shaping_skill"
        openai_metadata=$(<"$PROJECT_DIR/build/pi/$shaping_skill/agents/openai.yaml")
        direct_policy_count=$(printf '%s\n' "$openai_metadata" | rg --count '^  allow_implicit_invocation: false$')
        assert_equals "$direct_policy_count" "1" "Codex requires explicit invocation for $shaping_skill"
    done

    local metadata_test_dir="$PROJECT_DIR/build/pi/shaping-metadata-test"
    mkdir -p "$metadata_test_dir/agents"
    cat > "$metadata_test_dir/agents/openai.yaml" <<'EOF'
interface:
  display_name: "Shaping"
policy: { allow_implicit_invocation: true, future_setting: "keep, me" } # keep comment
EOF
    python3 -c "import importlib.util, pathlib; spec = importlib.util.spec_from_file_location('build', 'scripts/build.py'); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module.disable_codex_implicit_invocation(pathlib.Path('$metadata_test_dir'))"
    openai_metadata=$(<"$metadata_test_dir/agents/openai.yaml")
    assert_output_contains "$openai_metadata" "display_name: \"Shaping\"" "Codex policy merge preserves interface metadata"
    assert_output_contains "$openai_metadata" "future_setting: \"keep, me\"" "Codex policy merge preserves flow policy metadata"
    assert_output_contains "$openai_metadata" 'policy: { allow_implicit_invocation: false, future_setting: "keep, me" } # keep comment' "Codex policy merge updates flow mappings"
    assert_output_contains "$openai_metadata" "# keep comment" "Codex policy merge preserves flow mapping comments"

    cat > "$metadata_test_dir/agents/openai.yaml" <<'EOF'
policy: # invocation policy
  nested:
    allow_implicit_invocation: true
interface:
  display_name: "Shaping"
EOF
    python3 -c "import importlib.util, pathlib; spec = importlib.util.spec_from_file_location('build', 'scripts/build.py'); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module.disable_codex_implicit_invocation(pathlib.Path('$metadata_test_dir'))"
    openai_metadata=$(<"$metadata_test_dir/agents/openai.yaml")
    assert_output_contains "$openai_metadata" "policy: # invocation policy" "Codex policy merge supports commented block mappings"
    direct_policy_count=$(printf '%s\n' "$openai_metadata" | rg --count '^  allow_implicit_invocation: false$')
    assert_equals "$direct_policy_count" "1" "Codex policy merge adds the direct policy key"
    assert_output_contains "$openai_metadata" "    allow_implicit_invocation: true" "Codex policy merge preserves nested metadata"
    assert_output_contains "$openai_metadata" "display_name: \"Shaping\"" "Codex block policy merge preserves following metadata"

    assert_file_exists "$PROJECT_DIR/skills/grok-review/SKILL.md" "grok-review source skill exists"
    assert_file_exists "$PROJECT_DIR/skills/grok-review/scripts/run_review.sh" "grok-review launcher exists"
    for agent in amp claude pi; do
        assert_file_exists "$PROJECT_DIR/build/$agent/grok-review/SKILL.md" "$agent builds grok-review skill"
        assert_file_exists "$PROJECT_DIR/build/$agent/grok-review/scripts/run_review.sh" "$agent builds the grok-review launcher"
    done

    local grok_review_content
    grok_review_content=$(<"$PROJECT_DIR/build/claude/grok-review/SKILL.md")
    local grok_review_launcher_content
    grok_review_launcher_content=$(<"$PROJECT_DIR/build/claude/grok-review/scripts/run_review.sh")
    assert_output_contains "$grok_review_content" "/review --branch" "grok-review delegates review standards to Grok's native branch mode"
    assert_output_contains "$grok_review_content" "origin/main" "grok-review defines the default base"
    assert_output_contains "$grok_review_content" "zmx" "grok-review uses zmx for long-running reviews"
    assert_output_contains "$grok_review_content" "Never blindly implement reviewer feedback" "grok-review requires finding validation before implementation"
    assert_output_contains "$grok_review_content" "Do not add a fallback reviewer" "grok-review forbids a fallback reviewer"
    assert_output_contains "$grok_review_launcher_content" "--output-format json" "launcher requests JSON output"
    assert_output_contains "$grok_review_launcher_content" "--sandbox read-only" "launcher enforces the read-only sandbox"
    assert_output_contains "$grok_review_launcher_content" "--prompt-file" "launcher passes the prompt file"
    assert_output_contains "$grok_review_launcher_content" "0.2.99" "launcher pins the validated Grok version"
    assert_output_contains "$grok_review_launcher_content" "--no-plan" "launcher disables plan mode"
    assert_output_not_contains "$grok_review_launcher_content" "--always-approve" "launcher does not auto-approve shell commands"
    assert_output_contains "$grok_review_launcher_content" '--disable-web-search' "launcher disables Grok web search"
    assert_output_contains "$grok_review_launcher_content" 'search_replace,write,web_search,web_fetch' "launcher removes mutating and external built-in tools"
    assert_output_contains "$grok_review_launcher_content" '--deny MCPTool' "launcher denies Grok MCP calls"
    assert_output_contains "$grok_review_launcher_content" "validate_result" "launcher validates structured results"
    assert_output_contains "$grok_review_launcher_content" "--resume" "launcher supports explicit session recovery"
    assert_output_not_contains "$grok_review_content" 'Do not add a speculative `--tools` override' "grok-review does not forbid the validated launcher controls"
    assert_output_not_contains "$grok_review_content" "Pull requests must be ready for review, never draft" "grok-review does not own PR publishing policy"

    assert_file_exists "$PROJECT_DIR/build/amp/impeccable/SKILL.md" "Amp builds impeccable skill"
    assert_file_exists "$PROJECT_DIR/build/claude/impeccable/SKILL.md" "Claude builds impeccable skill"
    assert_file_exists "$PROJECT_DIR/build/pi/impeccable/SKILL.md" "Pi builds impeccable skill"
    assert_file_exists "$PROJECT_DIR/build/amp/thermo-nuclear-code-review/SKILL.md" "Amp builds thermo-nuclear-code-review skill"
    assert_file_exists "$PROJECT_DIR/build/claude/thermo-nuclear-code-review/SKILL.md" "Claude builds thermo-nuclear-code-review skill"
    assert_file_exists "$PROJECT_DIR/build/pi/thermo-nuclear-code-review/SKILL.md" "Pi builds thermo-nuclear-code-review skill"

    local amp_impeccable_content
    local claude_impeccable_content
    local pi_impeccable_content
    amp_impeccable_content=$(<"$PROJECT_DIR/build/amp/impeccable/SKILL.md")
    claude_impeccable_content=$(<"$PROJECT_DIR/build/claude/impeccable/SKILL.md")
    pi_impeccable_content=$(<"$PROJECT_DIR/build/pi/impeccable/SKILL.md")
    assert_output_contains "$amp_impeccable_content" "node .agents/skills/impeccable/scripts/context.mjs" "Amp builds Codex/agents-flavored impeccable skill"
    assert_output_contains "$claude_impeccable_content" "node .claude/skills/impeccable/scripts/context.mjs" "Claude builds Claude-flavored impeccable skill"
    assert_output_contains "$pi_impeccable_content" "node .pi/skills/impeccable/scripts/context.mjs" "Pi builds Pi-flavored impeccable skill"
    assert_file_exists "$PROJECT_DIR/build/amp/impeccable/agents/impeccable_asset_producer.toml" "Amp/Codex impeccable skill includes nested asset producer agent"

    local has_lowercase_skill_md=false
    for file in "$PROJECT_DIR/build/claude/breadboard-reflection"/*; do
        if [ "$(basename "$file")" = "skill.md" ]; then
            has_lowercase_skill_md=true
            break
        fi
    done

    if ! $has_lowercase_skill_md; then
        log_info "PASS: breadboard-reflection keeps canonical SKILL.md filename"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: breadboard-reflection keeps canonical SKILL.md filename"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test: make install-skills (with sandbox)
test_make_install_skills() {
    log_test "Testing 'make install-skills' (sandboxed)"
    cd "$PROJECT_DIR"

    # Run install-skills with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills 2>&1)

    assert_output_contains "$output" "Installing skills" "Install shows progress"

    # Check directories were created in sandbox
    local amp_skills_count
    amp_skills_count=$(find "$SANDBOX_DIR/.config/agents/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$amp_skills_count" -gt 0 ]; then
        log_info "PASS: Amp skills installed ($amp_skills_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Amp skills installed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    local claude_skills_count
    claude_skills_count=$(find "$SANDBOX_DIR/.claude/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$claude_skills_count" -gt 0 ]; then
        log_info "PASS: Claude skills installed ($claude_skills_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Claude skills installed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi



    local pi_skills_count
    pi_skills_count=$(find "$SANDBOX_DIR/.agents/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$pi_skills_count" -gt 0 ]; then
        log_info "PASS: Pi skills installed ($pi_skills_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: No Pi skills installed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    for skills_dir in \
        "$SANDBOX_DIR/.config/agents/skills" \
        "$SANDBOX_DIR/.claude/skills" \
        "$SANDBOX_DIR/.agents/skills"; do
        for skill in brainstorming writing-plans executing-plans; do
            assert_file_not_exists "$skills_dir/$skill" "Install excludes $skill from $skills_dir"
        done
    done
    assert_dir_exists "$SANDBOX_DIR/.config/agents/skills/zmx" "Amp installs zmx skill"
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/zmx" "Claude installs zmx skill"
    assert_dir_exists "$SANDBOX_DIR/.agents/skills/zmx" "Pi installs zmx skill"
    assert_dir_exists "$SANDBOX_DIR/.config/agents/skills/x-search" "Amp installs x-search skill"
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/x-search" "Claude installs x-search skill"
    assert_dir_exists "$SANDBOX_DIR/.agents/skills/x-search" "Pi installs x-search skill"
    assert_dir_exists "$SANDBOX_DIR/.config/agents/skills/thermo-nuclear-code-review" "Amp installs thermo-nuclear-code-review skill"
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/thermo-nuclear-code-review" "Claude installs thermo-nuclear-code-review skill"
    assert_dir_exists "$SANDBOX_DIR/.agents/skills/thermo-nuclear-code-review" "Pi installs thermo-nuclear-code-review skill"
    assert_dir_exists "$SANDBOX_DIR/.config/agents/skills/effect" "Amp installs effect skill"
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/effect" "Claude installs effect skill"
    assert_dir_exists "$SANDBOX_DIR/.codex/skills/effect" "Codex installs effect skill"
    assert_dir_exists "$SANDBOX_DIR/.agents/skills/effect" "Pi installs effect skill"
    for skills_dir in \
        "$SANDBOX_DIR/.config/agents/skills" \
        "$SANDBOX_DIR/.claude/skills" \
        "$SANDBOX_DIR/.codex/skills" \
        "$SANDBOX_DIR/.agents/skills"; do
        assert_file_not_exists "$skills_dir/test-driven-development" "Install excludes test-driven-development from $skills_dir"
        assert_file_not_exists "$skills_dir/systematic-debugging" "Install excludes systematic-debugging from $skills_dir"
        assert_file_not_exists "$skills_dir/effect-ts" "Install excludes replaced effect-ts from $skills_dir"
    done
}

# Test: install-skills preserves unmanaged sibling skills
test_install_skills_preserves_unmanaged_siblings() {
    log_test "Testing install-skills preserves unmanaged skill siblings"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.codex/skills"
    mkdir -p "$SANDBOX_DIR/.claude/skills/manual-skill"
    cat > "$SANDBOX_DIR/.claude/skills/manual-skill/SKILL.md" <<'EOF'
---
name: manual-skill
description: Manual test skill
---

Manual content.
EOF

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills 2>&1)

    assert_output_contains "$output" "Installing skills" "Install shows skill progress"
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/manual-skill" "Unmanaged Claude skill survives install"
    assert_file_exists "$SANDBOX_DIR/.claude/skills/manual-skill/SKILL.md" "Unmanaged Claude skill file survives install"
}

# Test: install-skills removes previously managed sibling skills
test_install_skills_removes_previous_managed_siblings() {
    log_test "Testing install-skills removes previously managed skill siblings"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.codex/skills" "$SANDBOX_DIR/.local/state/dotfiles"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills >/dev/null 2>&1
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/zmx" "Managed skill initially installed"

    python3 - <<PY
import json
from pathlib import Path
manifest_path = Path("$SANDBOX_DIR/.local/state/dotfiles/agent-install-manifest.json")
manifest = json.loads(manifest_path.read_text())
manifest["targets"]["claude.skills"].append("obsolete-managed-skill")
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
    mkdir -p "$SANDBOX_DIR/.claude/skills/obsolete-managed-skill"
    touch "$SANDBOX_DIR/.claude/skills/obsolete-managed-skill/SKILL.md"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills >/dev/null 2>&1

    assert_file_not_exists "$SANDBOX_DIR/.claude/skills/obsolete-managed-skill" "Obsolete managed skill is removed"
}

# Test: install-skills refuses unmanaged same-name conflicts
test_install_skills_refuses_unmanaged_name_conflict() {
    log_test "Testing install-skills refuses unmanaged same-name conflict"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.codex/skills" "$SANDBOX_DIR/.local/state/dotfiles"
    mkdir -p "$SANDBOX_DIR/.claude/skills/zmx"
    cat > "$SANDBOX_DIR/.claude/skills/zmx/SKILL.md" <<'EOF'
manual conflict
EOF

    local output status
    set +e
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills 2>&1)
    status=$?
    set -e

    if [ "$status" -ne 0 ]; then
        log_info "PASS: install-skills failed on unmanaged conflict"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: install-skills should fail on unmanaged conflict"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    assert_output_contains "$output" "refusing to overwrite unmanaged install path" "Conflict error explains unmanaged path"
    assert_file_not_exists "$SANDBOX_DIR/.claude/skills/agent-browser" "Failed conflict check does not partially install earlier managed skills"
}

# Test: install refuses unsafe manifest child names
test_install_refuses_unsafe_manifest_child_names() {
    log_test "Testing install refuses unsafe manifest child names"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.codex/skills" "$SANDBOX_DIR/.local/state/dotfiles"
    mkdir -p "$SANDBOX_DIR/.local/state/dotfiles"
    cat > "$SANDBOX_DIR/.local/state/dotfiles/agent-install-manifest.json" <<'EOF'
{
  "version": 1,
  "targets": {
    "claude.skills": ["../unsafe"]
  }
}
EOF

    local output status
    set +e
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make clean 2>&1)
    status=$?
    set -e

    if [ "$status" -ne 0 ]; then
        log_info "PASS: clean failed on unsafe manifest child name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: clean should fail on unsafe manifest child name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    assert_output_contains "$output" "unsafe child name" "Unsafe manifest error explains bad child name"
}

# Test: install-skills --force claims unmanaged same-name conflicts
test_install_skills_force_claims_unmanaged_name_conflict() {
    log_test "Testing install-skills --force claims unmanaged same-name conflict"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.codex/skills" "$SANDBOX_DIR/.local/state/dotfiles"
    mkdir -p "$SANDBOX_DIR/.claude/skills/zmx"
    cat > "$SANDBOX_DIR/.claude/skills/zmx/SKILL.md" <<'EOF'
manual conflict
EOF

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" python3 scripts/build.py install-skills --force 2>&1)

    assert_output_contains "$output" "Installing skills" "Forced install shows skill progress"
    assert_output_not_contains "$(<"$SANDBOX_DIR/.claude/skills/zmx/SKILL.md")" "manual conflict" "Forced install overwrites conflicting unmanaged skill"
}

# Test: make install-extensions (with sandbox)
test_make_install_extensions() {
    log_test "Testing 'make install-extensions' (sandboxed)"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.pi/agent/extensions/manual-extension"
    cat > "$SANDBOX_DIR/.pi/agent/extensions/manual-extension/index.ts" <<'EOF'
export default {};
EOF

    # Run install-extensions with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-extensions 2>&1)

    assert_output_contains "$output" "Installing extensions" "Install shows extensions progress"
    assert_output_contains "$output" "Installed" "Install shows completion"

    # Check if extensions directory has any extensions
    local extensions_count
    extensions_count=$(find "$SANDBOX_DIR/.pi/agent/extensions" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$extensions_count" -gt 0 ]; then
        log_info "PASS: Pi extensions installed ($extensions_count directories)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        # May have no extensions configured in plugins.toml
        log_info "PASS: No extensions to install (may be expected)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi

    assert_output_contains "$output" "buildr-artifacts (from buildrtech/dotagents)" "buildr-artifacts comes from buildrtech plugin"
    assert_output_contains "$output" "handoff (from buildrtech/dotagents)" "handoff comes from buildrtech plugin"
    assert_output_contains "$output" "openai-fast (from buildrtech/dotagents)" "openai-fast comes from buildrtech plugin"
    assert_output_contains "$output" "session-query (from buildrtech/dotagents)" "session-query comes from buildrtech plugin"
    assert_output_not_contains "$output" "openai-fast (custom)" "openai-fast is no longer installed from the local copy"

    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/buildr-artifacts" "buildr-artifacts extension installed"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/handoff" "handoff extension installed"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/openai-fast" "openai-fast extension installed"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/session-query" "session-query extension installed"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/tmux-status" "tmux-status extension installed"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/web-access" "web-access extension installed"
    assert_file_not_exists "$SANDBOX_DIR/.pi/agent/extensions/subagent" "subagent extension removed"
    assert_file_not_exists "$SANDBOX_DIR/.pi/agent/extensions/pi-web-access" "pi-web-access extension removed"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/manual-extension" "Unmanaged Pi extension survives install"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/extensions/manual-extension/index.ts" "Unmanaged Pi extension file survives install"
}

# Test: make install-amp-plugins (with sandbox)
test_make_install_amp_plugins() {
    log_test "Testing 'make install-amp-plugins' (sandboxed)"
    cd "$PROJECT_DIR"

    mkdir -p "$PROJECT_DIR/amp-plugins" "$SANDBOX_DIR/.config/amp/plugins"
    local fixture="$PROJECT_DIR/amp-plugins/test-plugin.ts"
    rm -f "$fixture"
    cat > "$fixture" <<'EOF'
import type { PluginAPI } from '@ampcode/plugin'

export default function (amp: PluginAPI) {
  amp.logger.log('test plugin loaded')
}
EOF
    echo "manual" > "$SANDBOX_DIR/.config/amp/plugins/manual.ts"

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-amp-plugins 2>&1)

    assert_output_contains "$output" "Installing Amp plugins" "Install shows Amp plugin progress"
    assert_file_exists "$SANDBOX_DIR/.config/amp/plugins/test-plugin.ts" "Amp plugin was installed"
    if [ ! -L "$SANDBOX_DIR/.config/amp/plugins/test-plugin.ts" ]; then
        log_info "PASS: Amp plugin install creates a copied file"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Amp plugin install should copy, not symlink"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    assert_file_exists "$SANDBOX_DIR/.config/amp/plugins/manual.ts" "Unmanaged Amp plugin survives install"
    rm -f "$fixture"
}

# Test: make install-prompts (with sandbox)
test_make_install_prompts() {
    log_test "Testing 'make install-prompts' (sandboxed)"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.pi/agent/prompts"
    echo "manual prompt" > "$SANDBOX_DIR/.pi/agent/prompts/manual.md"

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-prompts 2>&1)

    assert_output_contains "$output" "Installing prompt templates" "Install shows prompt progress"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/prompts/refactor-pass.md" "Pi prompt template installed"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/prompts/manual.md" "Unmanaged Pi prompt survives install"
}

# Test: make install-subagents preserves unmanaged siblings
test_make_install_subagents_preserves_unmanaged_siblings() {
    log_test "Testing 'make install-subagents' preserves unmanaged siblings"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.pi/agent/agents"
    echo "manual subagent" > "$SANDBOX_DIR/.pi/agent/agents/manual.md"

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-subagents 2>&1)

    assert_output_contains "$output" "Installing subagents" "Install shows subagent progress"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/agents/architecture-reviewer.md" "Pi architecture-reviewer subagent installed"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/agents/manual.md" "Unmanaged Pi subagent survives install"
}

# Test: make install-themes (with sandbox)
test_make_install_themes() {
    log_test "Testing 'make install-themes' (sandboxed)"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.pi/agent/themes"
    echo '{"name":"manual"}' > "$SANDBOX_DIR/.pi/agent/themes/manual.json"

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-themes 2>&1)

    assert_output_contains "$output" "Installing themes" "Install shows theme progress"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/themes/catppuccin-latte.json" "Pi latte theme installed"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/themes/catppuccin-mocha.json" "Pi mocha theme installed"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/themes/manual.json" "Unmanaged Pi theme survives install"
}

# Test: make install (with sandbox)
test_make_install() {
    log_test "Testing 'make install' (sandboxed)"
    cd "$PROJECT_DIR"

    # Clean sandbox first
    rm -rf "$SANDBOX_DIR/.claude/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.agents/skills"/* 2>/dev/null || true
    rm -rf "$SANDBOX_DIR/.pi/agent/extensions"/* 2>/dev/null || true

    # Run full install with sandbox HOME
    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" DCG_INSTALLER_PATH="$SANDBOX_DIR/dcg-install.sh" DCG_TEST_ARGS_LOG="$SANDBOX_DIR/dcg-install-args.log" make install 2>&1)

    assert_output_contains "$output" "All skills, prompt templates, themes, extensions, and Amp plugins installed" "Install shows completion message"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/prompts/refactor-pass.md" "Install includes Pi prompts"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/themes/catppuccin-latte.json" "Install includes Pi themes"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/settings.json" "Install includes Pi settings"

    local pi_settings
    pi_settings=$(<"$SANDBOX_DIR/.pi/agent/settings.json")
    assert_output_contains "$pi_settings" "npm:pi-subagents" "Pi settings include npm pi-subagents package"
}

# Test: make clean (with sandbox)
test_make_clean() {
    log_test "Testing 'make clean' (sandboxed)"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.claude/skills/manual-clean-skill"
    echo "manual" > "$SANDBOX_DIR/.claude/skills/manual-clean-skill/SKILL.md"
    mkdir -p "$SANDBOX_DIR/.pi/agent/extensions/manual-clean-extension"
    echo "manual" > "$SANDBOX_DIR/.pi/agent/extensions/manual-clean-extension/index.ts"
    mkdir -p "$SANDBOX_DIR/.pi/agent/prompts"
    echo "manual" > "$SANDBOX_DIR/.pi/agent/prompts/manual-clean.md"
    mkdir -p "$SANDBOX_DIR/.pi/agent/agents"
    echo "manual" > "$SANDBOX_DIR/.pi/agent/agents/manual-clean.md"

    # First install
    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" DCG_INSTALLER_PATH="$SANDBOX_DIR/dcg-install.sh" DCG_TEST_ARGS_LOG="$SANDBOX_DIR/dcg-install-args.log" make install >/dev/null 2>&1

    # Then clean
    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make clean 2>&1)

    assert_output_contains "$output" "Cleaning installed artifacts" "Clean shows progress"

    # Verify build directories are removed
    if [ ! -d "$PROJECT_DIR/build/claude" ] && [ ! -d "$PROJECT_DIR/build/pi" ] && [ ! -d "$PROJECT_DIR/build/prompts" ]; then
        log_info "PASS: Build directories removed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Build directories still exist after clean"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    assert_file_not_exists "$SANDBOX_DIR/.claude/skills/zmx" "Clean removes managed skill"
    assert_file_not_exists "$SANDBOX_DIR/.pi/agent/extensions/web-access" "Clean removes managed extension"
    assert_file_not_exists "$SANDBOX_DIR/.pi/agent/prompts/refactor-pass.md" "Clean removes managed prompt"
    assert_file_not_exists "$SANDBOX_DIR/.pi/agent/agents/code-reviewer.md" "Clean removes managed subagent"
    assert_file_not_exists "$SANDBOX_DIR/.pi/agent/themes/catppuccin-latte.json" "Clean removes managed theme"
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/manual-clean-skill" "Clean preserves unmanaged skill"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/manual-clean-extension" "Clean preserves unmanaged extension"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/prompts/manual-clean.md" "Clean preserves unmanaged prompt"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/agents/manual-clean.md" "Clean preserves unmanaged subagent"
}

# Test: default make target (should run help)
test_make_default() {
    log_test "Testing default 'make' target (should show help)"
    cd "$PROJECT_DIR"

    local output
    output=$(make 2>&1)

    assert_output_contains "$output" "Agents - Skills" "Default make target shows help"
}

# Test: package manager security config uses global tool config and writes unmanaged config files
test_package_manager_security_config() {
    log_test "Testing 'make package-manager-security-config' (sandboxed)"
    cd "$PROJECT_DIR"

    local fake_bin command_log
    fake_bin="$SANDBOX_DIR/fake-bin"
    command_log="$SANDBOX_DIR/package-manager-commands.log"
    mkdir -p "$fake_bin"

    cat > "$fake_bin/npm" <<EOF
#!/usr/bin/env bash
echo "npm \$*" >> "$command_log"
EOF
    cat > "$fake_bin/pnpm" <<EOF
#!/usr/bin/env bash
echo "pnpm \$*" >> "$command_log"
EOF
    cat > "$fake_bin/bun" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat > "$fake_bin/uv" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$fake_bin/npm" "$fake_bin/pnpm" "$fake_bin/bun" "$fake_bin/uv"

    mkdir -p "$SANDBOX_DIR/.config/uv"
    cat > "$SANDBOX_DIR/.bunfig.toml" <<'EOF'
telemetry = false

[install]
registry = "https://registry.npmjs.org"
EOF
    cat > "$SANDBOX_DIR/.config/uv/uv.toml" <<'EOF'
native-tls = true
EOF

    local output
    output=$(PATH="$fake_bin:$PATH" HOME="$SANDBOX_DIR" make package-manager-security-config 2>&1)

    assert_output_contains "$output" "Configuring package-manager security settings" "Shows package-manager security progress"
    assert_file_exists "$SANDBOX_DIR/.bunfig.toml" "Bun security config was written"
    assert_file_exists "$SANDBOX_DIR/.config/uv/uv.toml" "uv security config was written"

    local commands bun_config uv_config
    commands=$(<"$command_log")
    bun_config=$(<"$SANDBOX_DIR/.bunfig.toml")
    uv_config=$(<"$SANDBOX_DIR/.config/uv/uv.toml")

    assert_output_contains "$commands" "npm config set min-release-age 7 --global" "npm minimum release age configured globally"
    assert_output_contains "$commands" "npm config set ignore-scripts true --global" "npm lifecycle scripts disabled globally"
    assert_output_contains "$commands" "pnpm config set minimum-release-age 10080 --global" "pnpm minimum release age configured globally"
    assert_output_contains "$bun_config" "minimumReleaseAge = 604800" "Bun minimum release age configured"
    assert_output_contains "$bun_config" "registry = \"https://registry.npmjs.org\"" "Bun existing config is preserved"
    assert_output_contains "$uv_config" "exclude-newer = \"7 days\"" "uv exclude-newer configured"
    assert_output_contains "$uv_config" "native-tls = true" "uv existing config is preserved"
}

# Test: plugins.toml exists and is valid
test_plugins_toml() {
    log_test "Testing plugins.toml configuration"
    cd "$PROJECT_DIR"

    assert_file_exists "$PROJECT_DIR/plugins.toml" "plugins.toml exists"

    # Check Python can parse it
    local output
    output=$(python3 -c "import tomllib; tomllib.load(open('plugins.toml', 'rb')); print('valid')" 2>&1)
    if [[ "$output" == *"valid"* ]]; then
        log_info "PASS: plugins.toml is valid TOML"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: plugins.toml is not valid TOML: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Main
main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Makefile Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    # Setup
    setup_sandbox
    init_submodules

    # Run tests
    test_make_help
    test_make_default
    test_plugins_toml
    test_make_build
    test_package_manager_security_config
    test_make_install_tools
    test_make_install_skills
    test_install_skills_preserves_unmanaged_siblings
    test_install_skills_removes_previous_managed_siblings
    test_install_skills_refuses_unmanaged_name_conflict
    test_install_refuses_unsafe_manifest_child_names
    test_install_skills_force_claims_unmanaged_name_conflict
    test_make_install_amp_plugins
    test_make_install_extensions
    test_make_install_prompts
    test_make_install_subagents_preserves_unmanaged_siblings
    test_make_install_themes
    test_make_install
    test_make_clean

    # Summary
    print_summary
}

# Run main
main "$@"
