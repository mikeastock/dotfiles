# Managed Install Manifest Implementation Plan

> REQUIRED SUB-SKILL: Use superpowers:executing-plans skill to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `scripts/build.py` from wiping manually installed skills/extensions/prompts/subagents while still deleting and overwriting artifacts managed by this repo.

**Architecture:** Add a small name-level install manifest to `scripts/build.py`. Install commands will sync top-level children for each install target: remove previously managed children that are no longer desired, overwrite current managed children, and refuse to overwrite same-name unmanaged children unless `--force` is passed.

**Tech Stack:** Python 3.11 stdlib (`json`, `os`, `pathlib`, `shutil`), existing Bash test suite, existing Makefile command wrappers.

---

## File Structure

- Modify: `scripts/build.py`
  - Add manifest constants and helpers near the existing install path definitions.
  - Replace wholesale `shutil.rmtree(dest)` install behavior for skills, prompts, subagents, and extensions with name-level managed sync.
  - Add `--force` CLI flag and thread it into install commands.
  - Update `clean()` to remove manifest-managed children instead of whole install roots where possible.
- Modify: `tests/test-make.sh`
  - Add sandbox tests that prove unmanaged siblings survive install.
  - Add sandbox tests that prove removed managed artifacts are deleted on the next install.
  - Add sandbox tests that prove unmanaged same-name conflicts fail without `--force`.
- Optional modify: `README.md`
  - Add a short note that install preserves unmanaged sibling artifacts and uses `--force` to claim conflicting paths. Only do this if the implementation changes visible behavior enough that users need to know.

Manifest location:

```python
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME") or HOME / ".local" / "state") / "dotfiles"
INSTALL_MANIFEST = STATE_DIR / "agent-install-manifest.json"
INSTALL_MANIFEST_VERSION = 1
```

Manifest shape:

```json
{
  "version": 1,
  "targets": {
    "amp.skills": ["skill-a", "skill-b"],
    "claude.skills": ["skill-a", "skill-b"],
    "pi.skills": ["skill-a", "skill-b"],
    "pi.extensions": ["ext-a"],
    "pi.prompts": ["refactor-pass.md"],
    "pi.subagents": ["planner.md"],
    "pi.themes": ["catppuccin-latte.json"]
  }
}
```

The manifest tracks only top-level child names. It intentionally does not hash files or preserve local edits inside a managed child directory; installed artifacts are generated copies, and canonical edits belong in this repo.

Test environment rule: every sandboxed install command must set both `HOME="$SANDBOX_DIR"` and `XDG_STATE_HOME="$SANDBOX_DIR/.local/state"` so manifest state never leaks to or from the developer machine.

---

### Task 1: Add manifest helper tests for skills preservation

**Files:**
- Modify: `tests/test-make.sh`

- [ ] **Step 1: Add failing test for unmanaged skill siblings surviving install**

Add this helper near the other `test_make_install_skills` function or immediately after it:

```bash
test_install_skills_preserves_unmanaged_siblings() {
    log_test "Testing install-skills preserves unmanaged skill siblings"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills"
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
```

Call it in `main()` after `test_make_install_skills`:

```bash
    test_install_skills_preserves_unmanaged_siblings
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
./tests/test-make.sh
```

Expected: FAIL because current `install_skills()` deletes `~/.claude/skills` before copying built skills.

- [ ] **Step 3: Commit failing test**

```bash
git add tests/test-make.sh
git commit -m "test: cover preserving unmanaged installed skills"
```

---

### Task 2: Add simple manifest sync helpers

**Files:**
- Modify: `scripts/build.py`

- [ ] **Step 1: Implement manifest constants and load/save helpers**

Add after the existing `INSTALL_PATHS` definition:

```python
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME") or HOME / ".local" / "state") / "dotfiles"
INSTALL_MANIFEST = STATE_DIR / "agent-install-manifest.json"
INSTALL_MANIFEST_VERSION = 1
```

Add `import os` and `import json` at the top-level imports.

Add these helpers near `remove_path()`:

```python
def empty_install_manifest() -> dict:
    return {"version": INSTALL_MANIFEST_VERSION, "targets": {}}


def load_install_manifest() -> dict:
    if not INSTALL_MANIFEST.exists():
        return empty_install_manifest()

    manifest = json.loads(INSTALL_MANIFEST.read_text())
    if manifest.get("version") != INSTALL_MANIFEST_VERSION:
        sys.exit(
            f"Error: unsupported install manifest version at {INSTALL_MANIFEST}. "
            "Remove it manually to reinitialize managed install state."
        )
    manifest.setdefault("targets", {})
    return manifest


def save_install_manifest(manifest: dict) -> None:
    INSTALL_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    INSTALL_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
```

- [ ] **Step 2: Run a syntax check**

Run:

```bash
python3 -m py_compile scripts/build.py
```

Expected: PASS, no output.

---

### Task 3: Add generic top-level child sync

**Files:**
- Modify: `scripts/build.py`

- [ ] **Step 1: Implement `sync_managed_children`**

Add near the manifest helpers:

```python
def source_child_names(source: Path, *, pattern: str = "*") -> list[str]:
    if not source.exists():
        return []
    return sorted(path.name for path in source.glob(pattern))


def copy_child(source_child: Path, dest_child: Path) -> None:
    remove_path(dest_child)
    if source_child.is_dir():
        shutil.copytree(source_child, dest_child)
    else:
        dest_child.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source_child, dest_child)


def sync_managed_children(
    target_name: str,
    source: Path,
    dest: Path,
    *,
    pattern: str = "*",
    force: bool = False,
) -> int:
    manifest = load_install_manifest()
    targets = manifest.setdefault("targets", {})
    previous = set(targets.get(target_name, []))
    desired = set(source_child_names(source, pattern=pattern))

    dest.mkdir(parents=True, exist_ok=True)

    for name in sorted(previous - desired):
        installed = dest / name
        if installed.exists() or installed.is_symlink():
            remove_path(installed)

    for name in sorted(desired):
        source_child = source / name
        dest_child = dest / name
        if (dest_child.exists() or dest_child.is_symlink()) and name not in previous and not force:
            sys.exit(
                f"Error: refusing to overwrite unmanaged install path: {dest_child}\n"
                "Run the install command with --force to claim this path."
            )
        copy_child(source_child, dest_child)

    targets[target_name] = sorted(desired)
    save_install_manifest(manifest)
    return len(desired)
```

This is intentionally small. It has no per-file hashes, staging, locks, symlink traversal logic, or rollback.

- [ ] **Step 2: Run syntax check**

Run:

```bash
python3 -m py_compile scripts/build.py
```

Expected: PASS, no output.

---

### Task 4: Use managed sync for skill installs

**Files:**
- Modify: `scripts/build.py:734-769`

- [ ] **Step 1: Change `install_skills` signature and body**

Replace `install_skills()` with:

```python
def install_skills(force: bool = False):
    """Install built skills to agent directories."""
    print("Installing skills...")

    for agent, paths in INSTALL_PATHS.items():
        if "skills" not in paths:
            continue

        source = BUILD_DIR / agent
        if not source.exists():
            continue

        dest = paths["skills"]
        count = sync_managed_children(
            f"{agent}.skills",
            source,
            dest,
            force=force,
        )

        print(f"  {agent}: {count} skills -> {dest}")
```

- [ ] **Step 2: Thread `force` through skill CLI paths**

In `main()`, change calls:

```python
install_skills()
```

to:

```python
install_skills(force=args.force)
```

for both `install` and `install-skills` command branches.

- [ ] **Step 3: Add parser flag**

Add to the argument parser:

```python
parser.add_argument(
    "--force",
    action="store_true",
    help="Claim existing unmanaged install paths that conflict with managed artifact names",
)
```

- [ ] **Step 4: Run focused test**

Run:

```bash
./tests/test-make.sh
```

Expected: the new unmanaged skill preservation test passes. Other tests should still pass unless later install roots still wipe unrelated paths in full `make install`; fix those in following tasks.

- [ ] **Step 5: Commit skill sync implementation**

```bash
git add scripts/build.py tests/test-make.sh
git commit -m "fix: preserve unmanaged installed skills"
```

---

### Task 5: Add tests for managed deletion and unmanaged conflicts

**Files:**
- Modify: `tests/test-make.sh`

- [ ] **Step 1: Add test proving previously managed skills are deleted when removed from manifest source**

Add this function after the previous preservation test:

```bash
test_install_skills_removes_previous_managed_siblings() {
    log_test "Testing install-skills removes previously managed skill siblings"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.local/state/dotfiles"

    HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-skills >/dev/null 2>&1
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/how" "Managed skill initially installed"

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
```

Call it in `main()` after `test_install_skills_preserves_unmanaged_siblings`.

- [ ] **Step 2: Add test proving unmanaged same-name conflicts fail**

Add this function:

```bash
test_install_skills_refuses_unmanaged_name_conflict() {
    log_test "Testing install-skills refuses unmanaged same-name conflict"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.local/state/dotfiles"
    mkdir -p "$SANDBOX_DIR/.claude/skills/how"
    cat > "$SANDBOX_DIR/.claude/skills/how/SKILL.md" <<'EOF'
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
}
```

Call it in `main()` after the managed deletion test.

- [ ] **Step 3: Add test proving `--force` claims unmanaged same-name conflicts**

Add this function:

```bash
test_install_skills_force_claims_unmanaged_name_conflict() {
    log_test "Testing install-skills --force claims unmanaged same-name conflict"
    cd "$PROJECT_DIR"

    rm -rf "$SANDBOX_DIR/.config/agents/skills" "$SANDBOX_DIR/.claude/skills" "$SANDBOX_DIR/.agents/skills" "$SANDBOX_DIR/.local/state/dotfiles"
    mkdir -p "$SANDBOX_DIR/.claude/skills/how"
    cat > "$SANDBOX_DIR/.claude/skills/how/SKILL.md" <<'EOF'
manual conflict
EOF

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" python3 scripts/build.py install-skills --force 2>&1)

    assert_output_contains "$output" "Installing skills" "Forced install shows skill progress"
    assert_output_not_contains "$(<"$SANDBOX_DIR/.claude/skills/how/SKILL.md")" "manual conflict" "Forced install overwrites conflicting unmanaged skill"
}
```

Call it in `main()` after the unmanaged conflict failure test.

- [ ] **Step 4: Run tests**

Run:

```bash
./tests/test-make.sh
```

Expected: PASS for new skills behavior.

- [ ] **Step 5: Commit tests**

```bash
git add tests/test-make.sh
git commit -m "test: cover managed install conflict behavior"
```

---

### Task 6: Use managed sync for prompts, subagents, themes, and extensions

**Files:**
- Modify: `scripts/build.py`

- [ ] **Step 1: Update prompt install**

Change `install_prompts()` to accept `force` and replace the destination wipe/copy loop with:

```python
def install_prompts(force: bool = False):
    """Install built prompt templates to Pi prompt directory."""
    print("Installing prompt templates...")

    source = BUILD_DIR / "prompts" / "pi"
    if not source.exists():
        print("  No built prompt templates found, skipping")
        return

    dest = INSTALL_PATHS["pi"]["prompts"]
    count = sync_managed_children(
        "pi.prompts",
        source,
        dest,
        pattern="*.md",
        force=force,
    )

    print(f"  pi: {count} prompts -> {dest}")
```

- [ ] **Step 2: Update subagent install**

Change `install_subagents()` to accept `force` and replace the destination wipe/copy loop with:

```python
def install_subagents(force: bool = False):
    """Install built subagent definitions to Pi agents directory."""
    print("Installing subagents...")

    source = BUILD_DIR / "subagents" / "pi"
    if not source.exists():
        print("  No built subagents found, skipping")
        return

    dest = INSTALL_PATHS["pi"]["subagents"]
    count = sync_managed_children(
        "pi.subagents",
        source,
        dest,
        pattern="*.md",
        force=force,
    )

    print(f"  pi: {count} subagents -> {dest}")
```

- [ ] **Step 3: Update theme install**

Change `install_themes()` to accept `force` and use managed sync:

```python
def install_themes(force: bool = False):
    """Install built Pi themes."""
    print("Installing themes...")

    source = BUILD_DIR / "themes" / "pi"
    if not source.exists():
        print("  No built themes found, skipping")
        return

    dest = INSTALL_PATHS["pi"]["themes"]
    count = sync_managed_children(
        "pi.themes",
        source,
        dest,
        pattern="*.json",
        force=force,
    )

    print(f"  pi: {count} themes -> {dest}")
```

- [ ] **Step 4: Update extension install**

In `install_extensions`, keep plugin/custom discovery and dependency installation logic, but stop wiping the whole destination at the start.

Change signature:

```python
def install_extensions(plugins: dict[str, Plugin], force: bool = False):
```

Remove:

```python
# Clear existing extensions directory for a fresh install
if dest.exists():
    shutil.rmtree(dest)
dest.mkdir(parents=True, exist_ok=True)
```

Add after `installed = set()`:

```python
manifest = load_install_manifest()
previous = set(manifest.setdefault("targets", {}).get("pi.extensions", []))
dest.mkdir(parents=True, exist_ok=True)
```

Before copying each extension, replace direct `remove_path(dest_ext)` with this conflict check:

```python
if (dest_ext.exists() or dest_ext.is_symlink()) and name not in previous and not force:
    sys.exit(
        f"Error: refusing to overwrite unmanaged install path: {dest_ext}\n"
        "Run the install command with --force to claim this path."
    )
remove_path(dest_ext)
```

After custom extensions are installed and before final summary, remove obsolete previous extensions and save the manifest:

```python
for name in sorted(previous - installed):
    installed_ext = dest / name
    if installed_ext.exists() or installed_ext.is_symlink():
        remove_path(installed_ext)

manifest["targets"]["pi.extensions"] = sorted(installed)
save_install_manifest(manifest)
```

- [ ] **Step 5: Thread `force` through all CLI branches**

Update calls in `main()`:

```python
install_prompts(force=args.force)
install_subagents(force=args.force)
install_themes(force=args.force)
install_extensions(plugins, force=args.force)
```

Apply this to `install`, `install-extensions`, `install-prompts`, `install-subagents`, and `install-themes` branches.

- [ ] **Step 6: Run syntax check**

Run:

```bash
python3 -m py_compile scripts/build.py
```

Expected: PASS.

- [ ] **Step 7: Commit install target sync**

```bash
git add scripts/build.py
git commit -m "fix: preserve unmanaged installed agent artifacts"
```

---

### Task 7: Add preservation tests for extensions, prompts, subagents, and themes

**Files:**
- Modify: `tests/test-make.sh`

- [ ] **Step 1: Extend existing install tests with unmanaged sentinels**

For every sandboxed install invocation touched in this task, include `XDG_STATE_HOME="$SANDBOX_DIR/.local/state"` alongside `HOME="$SANDBOX_DIR"`. For example, change `output=$(HOME="$SANDBOX_DIR" make install-extensions 2>&1)` to `output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-extensions 2>&1)`.

In `test_make_install_extensions`, before running `make install-extensions`, add:

```bash
    mkdir -p "$SANDBOX_DIR/.pi/agent/extensions/manual-extension"
    cat > "$SANDBOX_DIR/.pi/agent/extensions/manual-extension/index.ts" <<'EOF'
export default {};
EOF
```

After existing extension assertions, add:

```bash
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/manual-extension" "Unmanaged Pi extension survives install"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/extensions/manual-extension/index.ts" "Unmanaged Pi extension file survives install"
```

In `test_make_install_prompts`, before the install command, add:

```bash
    mkdir -p "$SANDBOX_DIR/.pi/agent/prompts"
    echo "manual prompt" > "$SANDBOX_DIR/.pi/agent/prompts/manual.md"
```

After existing prompt assertion, add:

```bash
    assert_file_exists "$SANDBOX_DIR/.pi/agent/prompts/manual.md" "Unmanaged Pi prompt survives install"
```

In `test_make_install_themes`, before the install command, add:

```bash
    mkdir -p "$SANDBOX_DIR/.pi/agent/themes"
    echo '{"name":"manual"}' > "$SANDBOX_DIR/.pi/agent/themes/manual.json"
```

After existing theme assertions, add:

```bash
    assert_file_exists "$SANDBOX_DIR/.pi/agent/themes/manual.json" "Unmanaged Pi theme survives install"
```

Add a new test for subagents because `test-make.sh` currently does not cover `make install-subagents` directly:

```bash
test_make_install_subagents_preserves_unmanaged_siblings() {
    log_test "Testing 'make install-subagents' preserves unmanaged siblings"
    cd "$PROJECT_DIR"

    mkdir -p "$SANDBOX_DIR/.pi/agent/agents"
    echo "manual subagent" > "$SANDBOX_DIR/.pi/agent/agents/manual.md"

    local output
    output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install-subagents 2>&1)

    assert_output_contains "$output" "Installing subagents" "Install shows subagent progress"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/agents/manual.md" "Unmanaged Pi subagent survives install"
}
```

Call it in `main()` after `test_make_install_prompts`.

- [ ] **Step 2: Run focused tests**

Run:

```bash
./tests/test-make.sh
```

Expected: PASS.

- [ ] **Step 3: Commit tests**

```bash
git add tests/test-make.sh
git commit -m "test: preserve unmanaged installed agent artifacts"
```

---

### Task 8: Update clean behavior to use manifest-managed children

**Files:**
- Modify: `scripts/build.py`

- [ ] **Step 1: Add cleanup helper**

Add near sync helpers:

```python
def clean_manifest_target(manifest: dict, target_name: str, dest: Path) -> None:
    targets = manifest.setdefault("targets", {})
    for name in sorted(targets.get(target_name, [])):
        installed = dest / name
        if installed.exists() or installed.is_symlink():
            remove_path(installed)
            print(f"  Removed {installed}")
    targets.pop(target_name, None)
```

- [ ] **Step 2: Simplify `clean()` to remove manifest-managed artifacts first**

At the start of `clean(plugins)`, after the print, add:

```python
    manifest = load_install_manifest()

    for agent, paths in INSTALL_PATHS.items():
        if "skills" in paths:
            clean_manifest_target(manifest, f"{agent}.skills", paths["skills"])

    clean_manifest_target(manifest, "pi.extensions", INSTALL_PATHS["pi"]["extensions"])
    clean_manifest_target(manifest, "pi.prompts", INSTALL_PATHS["pi"]["prompts"])
    clean_manifest_target(manifest, "pi.subagents", INSTALL_PATHS["pi"]["subagents"])
    clean_manifest_target(manifest, "pi.themes", INSTALL_PATHS["pi"]["themes"])
    save_install_manifest(manifest)
```

Then remove the old build-dir-based skill cleanup, plugin/custom extension cleanup, whole prompt dir removal, whole subagent dir removal, and theme-source cleanup blocks. Keep build directory cleanup and existing config cleanup behavior unchanged for now.

- [ ] **Step 3: Remove empty manifest file when no targets remain**

After `save_install_manifest(manifest)`, add:

```python
    if not manifest.get("targets") and INSTALL_MANIFEST.exists():
        INSTALL_MANIFEST.unlink()
        print(f"  Removed {INSTALL_MANIFEST}")
```

- [ ] **Step 4: Run clean test**

Run:

```bash
./tests/test-make.sh
```

Expected: PASS. Existing clean test only checks build directories, so this should not regress.

- [ ] **Step 5: Commit clean behavior**

```bash
git add scripts/build.py
git commit -m "fix: clean only managed installed artifacts"
```

---

### Task 9: Add clean preservation test

**Files:**
- Modify: `tests/test-make.sh`

- [ ] **Step 1: Extend `test_make_clean` with unmanaged sentinels**

First change the install and clean invocations in `test_make_clean` to include manifest state isolation:

```bash
HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make install >/dev/null 2>&1
output=$(HOME="$SANDBOX_DIR" XDG_STATE_HOME="$SANDBOX_DIR/.local/state" make clean 2>&1)
```

Before that install line, add:

```bash
    mkdir -p "$SANDBOX_DIR/.claude/skills/manual-clean-skill"
    echo "manual" > "$SANDBOX_DIR/.claude/skills/manual-clean-skill/SKILL.md"
    mkdir -p "$SANDBOX_DIR/.pi/agent/extensions/manual-clean-extension"
    echo "manual" > "$SANDBOX_DIR/.pi/agent/extensions/manual-clean-extension/index.ts"
    mkdir -p "$SANDBOX_DIR/.pi/agent/prompts"
    echo "manual" > "$SANDBOX_DIR/.pi/agent/prompts/manual-clean.md"
    mkdir -p "$SANDBOX_DIR/.pi/agent/agents"
    echo "manual" > "$SANDBOX_DIR/.pi/agent/agents/manual-clean.md"
```

After the build directory assertions, add:

```bash
    assert_dir_exists "$SANDBOX_DIR/.claude/skills/manual-clean-skill" "Clean preserves unmanaged skill"
    assert_dir_exists "$SANDBOX_DIR/.pi/agent/extensions/manual-clean-extension" "Clean preserves unmanaged extension"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/prompts/manual-clean.md" "Clean preserves unmanaged prompt"
    assert_file_exists "$SANDBOX_DIR/.pi/agent/agents/manual-clean.md" "Clean preserves unmanaged subagent"
```

- [ ] **Step 2: Run focused test**

Run:

```bash
./tests/test-make.sh
```

Expected: PASS.

- [ ] **Step 3: Commit test**

```bash
git add tests/test-make.sh
git commit -m "test: preserve unmanaged artifacts during clean"
```

---

### Task 10: Optional README update

**Files:**
- Optional modify: `README.md`

- [ ] **Step 1: Search for install behavior docs**

Run:

```bash
rg -n "install|clean|skills|extensions|managed|wipe|remove" README.md
```

Expected: locate the command table / install notes.

- [ ] **Step 2: Add concise install state note if needed**

If README describes destructive install behavior or lacks any warning about conflicts, add:

```markdown
### Managed install behavior

`make install` preserves manually installed skills, Pi extensions, prompts, subagents, and themes that live beside dotfiles-managed artifacts. The installer tracks top-level managed names in `~/.local/state/dotfiles/agent-install-manifest.json`, overwrites those managed artifacts on each install, and removes managed artifacts that are no longer built. If a built artifact conflicts with an existing unmanaged path, the install fails; rerun the underlying build script with `--force` only when you want dotfiles to claim that path.
```

Do not document internals more deeply than this.

- [ ] **Step 3: Commit docs only if changed**

```bash
git add README.md
git commit -m "docs: explain managed agent installs"
```

---

### Task 11: Final verification

**Files:**
- No code changes expected.

- [ ] **Step 1: Run Python syntax check**

Run:

```bash
python3 -m py_compile scripts/build.py
```

Expected: PASS.

- [ ] **Step 2: Run focused installer suite**

Run:

```bash
./tests/test-make.sh
```

Expected: all tests pass.

- [ ] **Step 3: Run full test suite if time allows**

Run:

```bash
./tests/run-all.sh
```

Expected: all suites pass.

- [ ] **Step 4: Review final diff**

Run:

```bash
git diff --stat HEAD~10..HEAD
git diff HEAD~10..HEAD -- scripts/build.py tests/test-make.sh README.md
```

Expected: changes are limited to manifest-managed install behavior, tests, and optional docs.

---

## Notes for Implementation

- Keep the installer intentionally simpler than `plugins/buildrtech-dotagents/scripts/build.py`.
- Do not add per-file hashing, transaction staging, rollback, or locking unless tests reveal a real need.
- Do not preserve edits inside managed artifact directories. Managed children are generated outputs and should be overwritten.
- `--force` claims only same-name conflicts; it must not delete unrelated siblings.
- Keep configs unchanged in this plan. Config files have separate merge/overwrite semantics and are not part of the skill/extension/prompt/subagent wipe issue.
