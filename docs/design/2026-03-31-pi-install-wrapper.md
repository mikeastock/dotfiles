# Pi Install Workflow Design

## Goal

Provide one canonical Pi installation for this user account while preserving this repo as the source of truth for Pi config and the local Ghostty/tmux patch in `configs/pi-patch/`.

## Problem

Pi is easy to install in multiple places via different Node versions or package managers. That makes patching fragile because the patch must target the exact installed copy of Pi's bundled `@mariozechner/pi-tui` build. The desired state is one mise-managed install for the whole computer and one repeatable update/config/patch flow.

## Canonical ownership model

Mise owns the Pi npm package and command exposure:

- canonical mise tool: `npm:@mariozechner/pi-coding-agent@latest`
- package root: resolved with `mise where npm:@mariozechner/pi-coding-agent@latest`
- command: `pi`, provided by mise after install/reshim
- `bin/pi-install` performs install/update + config + patch

Installation uses mise's npm backend: `mise use -g npm:@mariozechner/pi-coding-agent@latest` followed by `mise install`.

Mise is the source of truth. The installer passes the resolved package root into `configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh`. This repo does not provide a `bin/pi` wrapper because mise may put managed tool bins ahead of `~/.local/bin` after reshimming.

## Components

### Install/update script

Responsibilities:
- verify required commands exist (`mise`, `make`)
- record Pi in global mise config as `npm:@mariozechner/pi-coding-agent@latest`
- install or update Pi through mise
- call `make install-configs`
- call the existing patch script with the mise-managed package root
- print installed/updated version information

Behavioral requirements:
- idempotent when re-run
- fail fast if install, config, or patch steps fail
- never silently patch an arbitrary PATH-discovered Pi copy

### Existing patch script reuse

`configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh` already accepts an explicit Pi package path. The install flow reuses that interface instead of duplicating patch logic.

## Data flow

```text
pi-install
  -> mise use -g npm:@mariozechner/pi-coding-agent@latest
  -> mise install
  -> make install-configs
  -> configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh $(mise where ...)/lib/node_modules/@mariozechner/pi-coding-agent
  -> user runs pi from mise
```

## Error handling

- Missing prerequisites: exit with a direct install hint
- Missing mise-managed package after update: exit with the expected path
- Patch failure: exit non-zero and preserve patch script diagnostics

## Testing

Use shell tests with sandboxed `HOME` and stubbed executables to verify:
- fresh install flow
- repeat install flow
- `make install-configs` is invoked
- patch script is invoked with the mise-managed package path
- installer works when invoked via symlink

## Non-goals

- supporting multiple concurrent Pi installs on one machine
- automatic migration from arbitrary prior local installs
- patching whatever `pi` binary happens to be first on `PATH`
- wrapping the mise-managed `pi` command
