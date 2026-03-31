# Pi Install Wrapper Implementation Plan

> REQUIRED SUB-SKILL: Use superpowers:executing-plans skill to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repo-managed Pi installer and stable launcher that maintain one canonical user-scoped Pi install, apply repo config, and run the local Pi patch.

**Architecture:** A new `bin/pi-install` script owns a fixed npm prefix at `~/.local/share/pi-coding-agent`, installs or updates Pi there, runs `make install-configs`, and applies the existing patch script to the derived package root. A new `bin/pi` wrapper derives the binary path from the same shared prefix constant and `exec`s the canonical Pi binary with pass-through arguments.

**Tech Stack:** Bash, npm, existing Makefile/config install flow, existing `configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh`, shell test scripts

---

## File structure

- Create: `bin/pi-paths.sh` — shared shell constants for the canonical Pi prefix and derived paths
- Create: `bin/pi-install` — canonical install/update/config/patch entrypoint
- Create: `bin/pi` — stable launcher for the canonical Pi binary
- Create: `tests/test-pi-install.sh` — focused shell tests for install/wrapper behavior
- Modify: `README.md` — document the new Pi workflow

### Task 1: Add install script test coverage

**Files:**
- Create: `tests/test-pi-install.sh`
- Test helpers: `tests/test-helpers.sh`

- [ ] **Step 1: Write the failing tests**

Add tests for:
- fresh install invokes npm with `--prefix "$HOME/.local/share/pi-coding-agent"`
- repeat install follows the same canonical prefix flow without changing target paths
- install invokes `make install-configs`
- install validates the derived package root exists before patching
- install invokes `configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh` with `"$PI_PREFIX/lib/node_modules/@mariozechner/pi-coding-agent"`
- wrapper passes through arguments to the canonical binary
- wrapper fails clearly when the canonical binary is missing

Use sandboxed `HOME` plus stub executables in a temporary `PATH` to capture calls instead of touching a real install.

- [ ] **Step 2: Run test to verify it fails**

Run: `./tests/test-pi-install.sh`
Expected: FAIL because `bin/pi-install` and `bin/pi` do not exist yet.

- [ ] **Step 3: Commit**

```bash
git add tests/test-pi-install.sh
git commit -m "test: add pi install wrapper coverage"
```

### Task 2: Implement shared path constants

**Files:**
- Create: `bin/pi-paths.sh`
- Test: `tests/test-pi-install.sh`

- [ ] **Step 1: Write the minimal shared path file**

Implement a shell file that defines the single source of truth:
- `PI_PREFIX="$HOME/.local/share/pi-coding-agent"`
- `PI_ROOT="$PI_PREFIX/lib/node_modules/@mariozechner/pi-coding-agent"`
- `PI_BIN="$PI_PREFIX/bin/pi"`

- [ ] **Step 2: Run test to verify path-dependent assertions still fail for missing scripts**

Run: `./tests/test-pi-install.sh`
Expected: still FAIL overall because `bin/pi-install` and `bin/pi` do not exist yet.

- [ ] **Step 3: Commit**

```bash
git add bin/pi-paths.sh tests/test-pi-install.sh
git commit -m "refactor: add shared pi path constants"
```

### Task 3: Implement `bin/pi-install`

**Files:**
- Create: `bin/pi-install`
- Modify: `bin/pi-paths.sh`
- Test: `tests/test-pi-install.sh`

- [ ] **Step 1: Write the minimal script**

Implement a bash script that:
- sources `bin/pi-paths.sh`
- checks `npm` and `make`
- runs `npm install -g --prefix "$PI_PREFIX" @mariozechner/pi-coding-agent`
- validates `"$PI_ROOT"` exists after install and fails with a direct message if it does not
- runs `make install-configs`
- runs `configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh "$PI_ROOT"`
- prints the resolved canonical paths and the instruction to use `bin/pi`
- exits non-zero on any failure

- [ ] **Step 2: Run test to verify it passes**

Run: `./tests/test-pi-install.sh`
Expected: targeted install-script assertions PASS, including the repeat-run/idempotent path checks; wrapper assertions may still fail until Task 4.

- [ ] **Step 3: Commit**

```bash
git add bin/pi-paths.sh bin/pi-install tests/test-pi-install.sh
git commit -m "feat: add canonical pi installer"
```

### Task 4: Implement `bin/pi`

**Files:**
- Create: `bin/pi`
- Modify: `bin/pi-paths.sh`
- Test: `tests/test-pi-install.sh`

- [ ] **Step 1: Write the minimal wrapper**

Implement a bash script that:
- sources `bin/pi-paths.sh`
- errors with a direct message if `PI_BIN` is missing or not executable
- otherwise `exec "$PI_BIN" "$@"`

- [ ] **Step 2: Run test to verify it passes**

Run: `./tests/test-pi-install.sh`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add bin/pi tests/test-pi-install.sh
git commit -m "feat: add pi launcher wrapper"
```

### Task 5: Document the workflow

**Files:**
- Modify: `README.md`
- Test: `tests/test-pi-install.sh`

- [ ] **Step 1: Update docs**

Add a short section documenting:
- canonical prefix: `~/.local/share/pi-coding-agent`
- `bin/pi-install` installs/updates the canonical Pi copy
- it also runs repo config install and the Ghostty/tmux patch against the canonical package root
- `bin/pi` is the stable launcher for that canonical install

- [ ] **Step 2: Re-run tests**

Run: `./tests/test-pi-install.sh`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add pi install wrapper workflow"
```

### Task 6: Final verification

**Files:**
- Verify: `bin/pi-install`
- Verify: `bin/pi`
- Verify: `tests/test-pi-install.sh`

- [ ] **Step 1: Run focused verification**

Run: `./tests/test-pi-install.sh`
Expected: PASS with no failing assertions

- [ ] **Step 2: Sanity-check scripts**

Run: `bash -n bin/pi-install bin/pi tests/test-pi-install.sh`
Expected: no output, zero exit status

- [ ] **Step 3: Confirm changed files**

Run: `git status --short`
Expected: only intended files are modified
