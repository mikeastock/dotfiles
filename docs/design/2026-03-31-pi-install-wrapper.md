# Pi Install Wrapper Design

## Goal

Provide one canonical Pi installation for this user account and one stable launcher command, while preserving this repo as the source of truth for Pi config and the local Ghostty/tmux patch in `configs/pi-patch/`.

## Problem

Pi is currently easy to install in multiple places via different Node versions or package managers. That makes patching fragile because the patch must target the exact installed copy of Pi's bundled `@mariozechner/pi-tui` build. The desired state is one install for the whole computer, one command to run, and one repeatable update flow.

## Recommended approach

Create a repo-managed install/maintenance script in `bin/` that owns the full lifecycle:

1. ensure a single canonical install location exists
2. install or update `@mariozechner/pi-coding-agent` into that location
3. run `make install-configs` so global Pi settings and `AGENTS.md` stay in sync with this repo
4. apply `configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh` against that exact install
5. expose a stable wrapper command that always launches the canonical patched install

This avoids relying on whichever `pi` happens to be on `PATH` and removes ambiguity about which install should be patched.

## Canonical ownership model

Use a repo-managed wrapper model with a fixed user-scoped install prefix:

- canonical npm prefix: `~/.local/share/pi-coding-agent`
- canonical package root: `~/.local/share/pi-coding-agent/lib/node_modules/@mariozechner/pi-coding-agent`
- canonical binary: `~/.local/share/pi-coding-agent/bin/pi`
- `bin/pi-install` performs install/update + config + patch
- `bin/pi` `exec`s the canonical binary at that exact fixed path

Installation uses npm with an explicit prefix, e.g. `npm install -g --prefix "$HOME/.local/share/pi-coding-agent" @mariozechner/pi-coding-agent`.

This fixed prefix is the source of truth. Implementation must define it once as a shared shell constant (for example `PI_PREFIX="$HOME/.local/share/pi-coding-agent"`) and derive the package root and binary path from that prefix in both scripts. The installer must always pass the derived package root into `configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh`, and the wrapper must always launch the derived binary from the same prefix.

## Components

### 1. Install/update script

Responsibilities:
- verify required commands exist (`npm`, optionally `node`, `make`)
- create/maintain the fixed canonical prefix at `~/.local/share/pi-coding-agent`
- install or update Pi there with `npm install -g --prefix ...`
- call `make install-configs`
- call the existing patch script with the canonical package root `~/.local/share/pi-coding-agent/lib/node_modules/@mariozechner/pi-coding-agent`
- print the resolved install path and next steps

Behavioral requirements:
- idempotent when re-run
- fail fast if install, config, or patch steps fail
- never silently patch an arbitrary PATH-discovered Pi copy

### 2. Stable launcher wrapper

Responsibilities:
- use the fixed canonical Pi binary path `~/.local/share/pi-coding-agent/bin/pi`
- `exec` into it with all user arguments preserved

Behavioral requirements:
- no extra logic beyond locating the canonical binary
- clear error if Pi has not been installed yet

### 3. Existing patch script reuse

`configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh` already accepts an explicit Pi package path. The new install flow should reuse that interface instead of duplicating patch logic.

## File changes

- Create: `bin/pi-install` — canonical install/update/config/patch entrypoint
- Create: `bin/pi` — stable launcher wrapper
- Create: `tests/test-pi-install.sh` — focused behavior tests for the new scripts
- Update: `README.md` — document the new machine-wide Pi workflow

## Data flow

```text
bin/pi-install
  -> npm install -g --prefix ~/.local/share/pi-coding-agent @mariozechner/pi-coding-agent
  -> make install-configs
  -> configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh ~/.local/share/pi-coding-agent/lib/node_modules/@mariozechner/pi-coding-agent
  -> user runs bin/pi
  -> bin/pi execs ~/.local/share/pi-coding-agent/bin/pi
```

## Error handling

- Missing prerequisites: exit with a direct install hint
- Missing canonical install after update: exit with the expected path
- Patch failure: exit non-zero and preserve patch script diagnostics
- Wrapper before install: exit with instruction to run `bin/pi-install`

## Testing

Use shell tests with sandboxed `HOME` and stubbed executables to verify:
- fresh install flow
- repeat install flow (idempotent update path)
- `make install-configs` is invoked
- patch script is invoked with the canonical package path
- launcher passes through arguments
- wrapper fails clearly when install has not happened

## Non-goals

- supporting multiple concurrent Pi installs on one machine
- automatic migration from arbitrary prior local installs
- patching whatever `pi` binary happens to be first on `PATH`

## Command exposure

The repo-local `bin/pi` is the stable launcher checked into the repo. The user-facing command can be this script directly, or a PATH entry/symlink can point to it, but the launcher itself must not perform discovery: it always targets `~/.local/share/pi-coding-agent/bin/pi`.
