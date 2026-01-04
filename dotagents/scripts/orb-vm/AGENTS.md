# OrbStack VM Setup

This directory contains scripts and documentation for setting up OrbStack Linux VMs with a consistent development environment.

## Overview

OrbStack provides lightweight Linux VMs on macOS. This setup creates a sandboxed development environment where:

1. The Mac's `~/code` directory is mounted at `/code` in the VM
2. Other Mac filesystem paths are blocked for security/isolation
3. Shell configs auto-cd to the equivalent `/code` path when entering the VM

## Architecture

### Mac Side (fish shell functions in `~/.config/fish/config.fish`)

```fish
function orb -d "OrbStack wrapper with auto-cd to relative path in ~/code"
  if test (count $argv) -eq 0; or test "$argv[1]" = "shell"
    set mac_pwd (pwd)
    command orb run -s "MAC_PWD='$mac_pwd' fish -l"
  else
    command orb $argv
  end
end
```

The `orb` function captures the current Mac directory in `MAC_PWD` and passes it to the VM shell.

### VM Side

#### Profile.d Scripts (`/etc/profile.d/`)

1. **`z-restrict-mac-access.sh`** - Runs on shell login:
   - Bind mounts `/Users/mikeastock/code` to `/code` (before blocking)
   - Unmounts Mac filesystem leaks: `/mnt/mac`, `/Users`, `/Volumes`, `/private`, `/Applications`, `/Library`
   - For interactive bash shells, handles `MAC_PWD` to cd to the right directory

2. **`bundler.sh`** - Sets `BUNDLE_PATH=../vendor/bundle` for Ruby projects

3. **`01-locale-fix.sh`** - Ensures UTF-8 locale is set

#### Shell Configs

- **Fish** (`~/.config/fish/config.fish`): Handles `MAC_PWD` translation to `/code/*` path
- **Bash** (`~/.bashrc.orb-setup`): Same logic for bash users

The cd logic:
```
MAC_PWD=/Users/mikeastock/code/buildr/app
  → translates to → /code/buildr/app
```

## Key Files in the VM

| Path | Purpose |
|------|---------|
| `~/.config/fish/config.fish` | Fish shell config with auto-cd, aliases, env vars |
| `~/.bashrc.orb-setup` | Bash equivalent (sourced from .bashrc) |
| `/etc/profile.d/z-restrict-mac-access.sh` | Mount /code, block Mac paths |
| `/etc/profile.d/bundler.sh` | Ruby bundler config (BUNDLE_PATH=../vendor/bundle) |
| `~/.config/pnpm/rc` | pnpm config (virtual-store-dir-suffix=.linux) |
| `~/.gitconfig` | Git aliases, colors, pull rebase, rerere |
| `~/.ssh/config` | Uses OrbStack's host SSH agent forwarding |
| `~/.config/mise/config.toml` | Runtime versions (node, ruby, python, go, etc.) |
| `~/.claude/settings.json` | Claude Code settings |
| `~/.claude/statusline-git.sh` | Custom Claude statusline with git info |
| `~/.pi/agent/settings.json` | Pi coding agent settings |

## Environment Variables

### OrbStack Service Discovery

The VM uses OrbStack's internal DNS for Docker services:

```bash
PGHOST=docker.orb.internal
REDIS_URL=redis://docker.orb.internal:6379
DOLT_HOST=docker.orb.internal
MLFLOW_TRACKING_URI=http://host.orb.internal:5500
```

## Isolated Package Installs

Since the VM shares the `/code` filesystem with Mac, we need to keep platform-specific dependencies separate. Native extensions compiled for Linux won't work on Mac and vice versa.

### Ruby (Bundler)

Set via `/etc/profile.d/bundler.sh`:

```bash
BUNDLE_PATH="../vendor/bundle"
```

This installs gems to `../vendor/bundle` relative to the project, keeping them outside the project directory. Each platform maintains its own gem installations.

Alternatively, projects can use `.bundle/config` with platform-specific paths.

### Python (UV)

Set via shell configs:

```bash
UV_PROJECT_ENVIRONMENT=".venv-linux"
```

This creates Linux venvs in `.venv-linux/` instead of `.venv/`, so Mac uses `.venv/` and Linux uses `.venv-linux/` in the same project.

### Node.js (pnpm)

Set via `~/.npmrc`:

```ini
virtual-store-dir-suffix=.linux
```

This appends `.linux` to pnpm's virtual store directory, creating `node_modules/.pnpm.linux/` instead of `node_modules/.pnpm/`. The `node_modules/` symlinks point to the platform-appropriate store.

### Summary

| Package Manager | Mac Location | Linux Location |
|-----------------|--------------|----------------|
| Bundler | `vendor/bundle` (default) | `../vendor/bundle` |
| UV | `.venv/` | `.venv-linux/` |
| pnpm | `node_modules/.pnpm/` | `node_modules/.pnpm.linux/` |

## Tools Installed via Mise

The `~/.config/mise/config.toml` installs:
- node (latest)
- ruby (3.4)
- python (3.13)
- go (latest)
- deno (latest)
- rust (stable)
- npm:@mariozechner/pi-coding-agent (latest)

## SSH Agent Forwarding

OrbStack automatically forwards the Mac's SSH agent. The VM's `~/.ssh/config` points to:

```
Host *
    IdentityAgent /opt/orbstack-guest/run/host-ssh-agent.sock
```

This means git operations using SSH keys work without copying keys to the VM.

## Usage

### Initial Setup

```bash
# Start an OrbStack VM (ubuntu is default)
orb create ubuntu

# Run the setup script
./setup-orb-vm.sh ubuntu
```

### Daily Use

From any directory under `~/code` on Mac:

```bash
# Enter the VM - automatically cd's to /code equivalent
orb

# Or run a specific command
orb run -s 'ls -la'
```

### Variant Functions (defined on Mac)

```fish
# Run codex in VM at current directory
orb-codex

# Run pi agent in VM at current directory  
orb-pi

# Run claude in VM at current directory
orb-claude
```

## Troubleshooting

### /code is empty

The bind mount happens in `/etc/profile.d/z-restrict-mac-access.sh` which only runs on login shells. Try:

```bash
orb run -m ubuntu -s 'bash -l -c "ls /code"'
```

Or restart the VM:
```bash
orbctl restart ubuntu
```

### MAC_PWD not working

Make sure you're using the `orb` fish function (not raw `orb` command) which passes `MAC_PWD`.

### Fish config not loading

The auto-cd logic is inside `if status is-interactive`, so it only runs for interactive shells. Use `fish -i` or `fish -l` flags.

## Aliases Reference

Both fish and bash configs include these aliases:

### Git
- `g` → git
- `s` → git status
- `co` → git checkout
- `br` → git branch --sort=-committerdate
- `gc` → git commit -v
- `gp` → git push -u
- `gpoh` → git push -u origin HEAD
- `grm` → git pull --rebase origin main
- `gmm` → git pull --no-rebase origin main

### Rails
- `r` → bin/rails
- `m` / `migrate` → bin/rails db:migrate
- `b` → bundle
- `be` → bundle exec

### Tools
- `n` → pnpm
- `claude` → claude --dangerously-skip-permissions
- `codex` → codex --yolo
- `vim` → nvim
