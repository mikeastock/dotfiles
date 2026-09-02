#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

trap cleanup EXIT

reset_install_state() {
    rm -rf \
        "$SANDBOX_DIR/.config/agents/skills" \
        "$SANDBOX_DIR/.config/amp/plugins" \
        "$SANDBOX_DIR/.claude/skills" \
        "$SANDBOX_DIR/.codex/skills" \
        "$SANDBOX_DIR/.agents/skills" \
        "$SANDBOX_DIR/.pi/agent/extensions" \
        "$SANDBOX_DIR/.pi/agent/prompts" \
        "$SANDBOX_DIR/.pi/agent/themes" \
        "$SANDBOX_DIR/.local/state/dotfiles"
}

test_make_build() {
    log_test "Testing the complete build"
    cd "$PROJECT_DIR"
    rm -rf "$PROJECT_DIR/build"

    make build >/dev/null

    if python3 - "$PROJECT_DIR/build" <<'PY'
import re
import sys
from pathlib import Path

build = Path(sys.argv[1])
for agent in ("amp", "claude", "codex", "pi"):
    agent_dir = build / agent
    skills = [path for path in agent_dir.iterdir() if path.is_dir()]
    if not skills:
        raise SystemExit(f"{agent} build contains no skills")
    for skill_dir in skills:
        skill_file = skill_dir / "SKILL.md"
        content = skill_file.read_text()
        frontmatter = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if frontmatter is None:
            raise SystemExit(f"missing frontmatter in {skill_file}")
        metadata = frontmatter.group(1)
        if re.search(r"^(?:\s+)?agents:", metadata, re.MULTILINE):
            raise SystemExit(f"build-only agents metadata leaked into {skill_file}")
        if "user-invocable-only:" in metadata:
            raise SystemExit(f"build-only invocation metadata leaked into {skill_file}")

for artifact_dir, pattern in (
    (build / "prompts" / "pi", "*.md"),
    (build / "themes" / "pi", "*.json"),
):
    if not list(artifact_dir.glob(pattern)):
        raise SystemExit(f"no artifacts in {artifact_dir}")
PY
    then
        log_info "PASS: Build strips install-only metadata and emits skills"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Build leaked install-only metadata or emitted nothing"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

test_make_install_skills() {
    log_test "Testing managed skill installation"
    cd "$PROJECT_DIR"
    reset_install_state

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills >/dev/null

    if python3 - "$SANDBOX_DIR" <<'PY'
import json
import sys
from pathlib import Path

home = Path(sys.argv[1])
manifest = json.loads((home / ".local/state/dotfiles/agent-install-manifest.json").read_text())
destinations = {
    "amp.skills": home / ".config/agents/skills",
    "claude.skills": home / ".claude/skills",
    "codex.skills": home / ".codex/skills",
    "pi.skills": home / ".agents/skills",
}
for target, destination in destinations.items():
    names = manifest["targets"].get(target, [])
    if not names:
        raise SystemExit(f"no managed entries for {target}")
    for name in names:
        if not (destination / name / "SKILL.md").is_file():
            raise SystemExit(f"missing installed skill {destination / name}")
PY
    then
        log_info "PASS: Manifest matches every installed skill set"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Installed skills do not match the manifest"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

test_install_skills_preserves_unmanaged_siblings() {
    log_test "Testing install-skills preserves unmanaged siblings"
    cd "$PROJECT_DIR"
    reset_install_state
    mkdir -p "$SANDBOX_DIR/.claude/skills/manual-skill"
    printf '%s\n' "manual" > "$SANDBOX_DIR/.claude/skills/manual-skill/SKILL.md"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills >/dev/null 2>&1

    assert_file_exists "$SANDBOX_DIR/.claude/skills/manual-skill/SKILL.md" "Unmanaged skill survives install"
}

test_install_skills_removes_previous_managed_siblings() {
    log_test "Testing install-skills removes obsolete managed siblings"
    cd "$PROJECT_DIR"
    reset_install_state
    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills >/dev/null 2>&1

    python3 - "$SANDBOX_DIR/.local/state/dotfiles/agent-install-manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest["targets"]["claude.skills"].append("obsolete-managed-skill")
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
    mkdir -p "$SANDBOX_DIR/.claude/skills/obsolete-managed-skill"
    touch "$SANDBOX_DIR/.claude/skills/obsolete-managed-skill/SKILL.md"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills >/dev/null 2>&1

    assert_file_not_exists "$SANDBOX_DIR/.claude/skills/obsolete-managed-skill" "Obsolete managed skill is removed"
}

test_install_skills_refuses_unmanaged_name_conflict() {
    log_test "Testing install-skills refuses unmanaged name conflicts"
    cd "$PROJECT_DIR"
    reset_install_state
    mkdir -p "$SANDBOX_DIR/.claude/skills/zmx"
    printf '%s\n' "manual conflict" > "$SANDBOX_DIR/.claude/skills/zmx/SKILL.md"

    local output status
    set +e
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills 2>&1)
    status=$?
    set -e

    if [ "$status" -ne 0 ]; then
        log_info "PASS: install-skills rejects an unmanaged conflict"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: install-skills accepted an unmanaged conflict"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    assert_output_contains "$output" "refusing to overwrite unmanaged install path" "Conflict error explains the unsafe overwrite"
    assert_output_contains "$(<"$SANDBOX_DIR/.claude/skills/zmx/SKILL.md")" "manual conflict" "Rejected install preserves the unmanaged skill"
}

test_install_refuses_unsafe_manifest_child_names() {
    log_test "Testing clean rejects unsafe manifest entries"
    cd "$PROJECT_DIR"
    reset_install_state
    mkdir -p "$SANDBOX_DIR/.local/state/dotfiles"
    printf '%s\n' '{"version":1,"targets":{"claude.skills":["../unsafe"]}}' > "$SANDBOX_DIR/.local/state/dotfiles/agent-install-manifest.json"

    local output status
    set +e
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make clean 2>&1)
    status=$?
    set -e

    if [ "$status" -ne 0 ]; then
        log_info "PASS: clean rejects an unsafe manifest entry"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: clean accepted an unsafe manifest entry"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    assert_output_contains "$output" "unsafe child name" "Unsafe manifest error identifies the problem"
}

test_install_skills_force_claims_unmanaged_name_conflict() {
    log_test "Testing forced install claims unmanaged conflicts"
    cd "$PROJECT_DIR"
    reset_install_state
    mkdir -p "$SANDBOX_DIR/.claude/skills/zmx"
    printf '%s\n' "manual conflict" > "$SANDBOX_DIR/.claude/skills/zmx/SKILL.md"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" python3 scripts/build.py install-skills --force >/dev/null 2>&1

    assert_output_not_contains "$(<"$SANDBOX_DIR/.claude/skills/zmx/SKILL.md")" "manual conflict" "Forced install replaces the conflicting skill"
}

test_make_install_extensions() {
    log_test "Testing extension installation"
    cd "$PROJECT_DIR"
    reset_install_state
    mkdir -p "$SANDBOX_DIR/.pi/agent/extensions/manual-extension"
    printf '%s\n' "export default {};" > "$SANDBOX_DIR/.pi/agent/extensions/manual-extension/index.ts"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-extensions >/dev/null 2>&1

    assert_file_exists "$SANDBOX_DIR/.pi/agent/extensions/manual-extension/index.ts" "Unmanaged extension survives install"
    if python3 - "$SANDBOX_DIR" <<'PY'
import json
import sys
from pathlib import Path

home = Path(sys.argv[1])
manifest = json.loads((home / ".local/state/dotfiles/agent-install-manifest.json").read_text())
names = manifest["targets"].get("pi.extensions", [])
if not names:
    raise SystemExit("no managed extensions")
for name in names:
    extension = home / ".pi/agent/extensions" / name
    if not extension.is_dir():
        raise SystemExit(f"missing {extension}")
PY
    then
        log_info "PASS: Manifest matches installed extensions"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Installed extensions do not match the manifest"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

test_make_install_amp_plugins() {
    log_test "Testing Amp plugin installation"
    cd "$PROJECT_DIR"
    reset_install_state
    mkdir -p "$SANDBOX_DIR/.config/amp/plugins"
    printf '%s\n' "manual" > "$SANDBOX_DIR/.config/amp/plugins/manual.ts"

    local fixture="$PROJECT_DIR/amp-plugins/test-plugin.ts"
    printf '%s\n' "export default function () {}" > "$fixture"
    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-amp-plugins >/dev/null 2>&1

    assert_file_exists "$SANDBOX_DIR/.config/amp/plugins/test-plugin.ts" "Managed Amp plugin is installed"
    assert_file_exists "$SANDBOX_DIR/.config/amp/plugins/manual.ts" "Unmanaged Amp plugin survives install"
    if [ ! -L "$SANDBOX_DIR/.config/amp/plugins/test-plugin.ts" ]; then
        log_info "PASS: Amp plugin is copied instead of symlinked"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Amp plugin was symlinked"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    rm -f "$fixture"
}

test_make_install_prompts_and_themes() {
    log_test "Testing prompt and theme installation"
    cd "$PROJECT_DIR"
    reset_install_state
    mkdir -p "$SANDBOX_DIR/.pi/agent/prompts" "$SANDBOX_DIR/.pi/agent/themes"
    printf '%s\n' "manual" > "$SANDBOX_DIR/.pi/agent/prompts/manual.md"
    printf '%s\n' '{}' > "$SANDBOX_DIR/.pi/agent/themes/manual.json"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-prompts >/dev/null 2>&1
    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-themes >/dev/null 2>&1

    assert_file_exists "$SANDBOX_DIR/.pi/agent/prompts/manual.md" "Unmanaged prompt survives install"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/themes/manual.json" "Unmanaged theme survives install"
    if python3 - "$SANDBOX_DIR" <<'PY'
import json
import sys
from pathlib import Path

home = Path(sys.argv[1])
manifest = json.loads((home / ".local/state/dotfiles/agent-install-manifest.json").read_text())
for target, destination in (
    ("pi.prompts", home / ".pi/agent/prompts"),
    ("pi.themes", home / ".pi/agent/themes"),
):
    names = manifest["targets"].get(target, [])
    if not names or any(not (destination / name).is_file() for name in names):
        raise SystemExit(f"invalid {target} install")
PY
    then
        log_info "PASS: Manifests match installed prompts and themes"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: Installed prompts or themes do not match the manifest"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

test_make_clean() {
    log_test "Testing clean removes only managed artifacts"
    cd "$PROJECT_DIR"
    reset_install_state
    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills install-extensions install-prompts install-themes >/dev/null 2>&1

    mkdir -p "$SANDBOX_DIR/.claude/skills/manual" "$SANDBOX_DIR/.pi/agent/extensions/manual"
    printf '%s\n' "manual" > "$SANDBOX_DIR/.claude/skills/manual/SKILL.md"
    printf '%s\n' "manual" > "$SANDBOX_DIR/.pi/agent/extensions/manual/index.ts"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make clean >/dev/null 2>&1

    assert_file_exists "$SANDBOX_DIR/.claude/skills/manual/SKILL.md" "Clean preserves an unmanaged skill"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/extensions/manual/index.ts" "Clean preserves an unmanaged extension"
    assert_file_not_exists "$SANDBOX_DIR/.local/state/dotfiles/agent-install-manifest.json" "Clean removes the empty install manifest"
    assert_file_not_exists "$PROJECT_DIR/build" "Clean removes build outputs"
}

test_package_manager_security_config() {
    log_test "Testing package-manager security configuration"
    cd "$PROJECT_DIR"
    local fake_bin="$SANDBOX_DIR/fake-bin"
    local command_log="$SANDBOX_DIR/package-manager-commands.log"
    mkdir -p "$fake_bin" "$SANDBOX_DIR/.config/uv"

    for command in npm pnpm; do
        printf '#!/usr/bin/env bash\nprintf "%%s %%s\\n" "%s" "$*" >> "%s"\n' "$command" "$command_log" > "$fake_bin/$command"
    done
    for command in bun uv; do
        printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$fake_bin/$command"
    done
    chmod +x "$fake_bin"/*
    printf '%s\n' 'telemetry = false' '' '[install]' 'registry = "https://registry.npmjs.org"' > "$SANDBOX_DIR/.bunfig.toml"
    printf '%s\n' 'native-tls = true' > "$SANDBOX_DIR/.config/uv/uv.toml"

    HOME="$SANDBOX_DIR" PATH="$fake_bin:$PATH" make package-manager-security-config >/dev/null 2>&1

    local commands bun_config uv_config
    commands=$(<"$command_log")
    bun_config=$(<"$SANDBOX_DIR/.bunfig.toml")
    uv_config=$(<"$SANDBOX_DIR/.config/uv/uv.toml")
    assert_output_contains "$commands" "npm config set min-release-age 7 --global" "npm minimum release age is global"
    assert_output_contains "$commands" "npm config set ignore-scripts true --global" "npm lifecycle scripts are disabled"
    assert_output_contains "$commands" "pnpm config set minimum-release-age 10080 --global" "pnpm minimum release age is global"
    assert_output_contains "$bun_config" "minimumReleaseAge = 604800" "Bun minimum release age is configured"
    assert_output_contains "$bun_config" 'registry = "https://registry.npmjs.org"' "Bun preserves existing config"
    assert_output_contains "$uv_config" 'exclude-newer = "7 days"' "uv excludes new releases"
    assert_output_contains "$uv_config" "native-tls = true" "uv preserves existing config"
}

main() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Build and Install Test Suite${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    setup_sandbox
    init_submodules

    test_make_build
    test_make_install_skills
    test_install_skills_preserves_unmanaged_siblings
    test_install_skills_removes_previous_managed_siblings
    test_install_skills_refuses_unmanaged_name_conflict
    test_install_refuses_unsafe_manifest_child_names
    test_install_skills_force_claims_unmanaged_name_conflict
    test_make_install_extensions
    test_make_install_amp_plugins
    test_make_install_prompts_and_themes
    test_make_clean
    test_package_manager_security_config

    print_summary
}

main "$@"
