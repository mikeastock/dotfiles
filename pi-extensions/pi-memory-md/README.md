# pi-memory-md

Git-backed markdown memory for Pi, stored per project under a local memory repository.

## What it does

This extension gives Pi a small memory system backed by markdown files:

- keeps memory in regular `.md` files with frontmatter
- builds a lightweight per-project memory index from `core/`
- injects that index into Pi so the model knows what memory files exist
- lets the model read, write, search, list, and sync memory files with tools
- supports git-backed storage so memory can be pulled/pushed like normal project data

The memory layout is per project, and project keys are hashed so two repos with the same directory name do not collide.

## Configuration

Add this to `~/.pi/agent/settings.json`:

```json
{
  "pi-memory-md": {
    "enabled": true,
    "repoUrl": "git@github.com:you/pi-memory.git",
    "localPath": "~/.pi/memory-md",
    "injection": "message-append",
    "autoSync": {
      "onSessionStart": true
    }
  }
}
```

### Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Turns the extension on/off |
| `repoUrl` | required | Remote git repo to clone/pull/push |
| `localPath` | `~/.pi/memory-md` | Local checkout for the memory repo |
| `injection` | `message-append` | How the memory index is exposed to the model |
| `autoSync.onSessionStart` | `true` | Pull from the repo when a session starts |

### Injection modes

- `message-append`: inject the memory index once per session as a hidden message
- `system-prompt`: append the memory index to the system prompt every turn

`message-append` is cheaper. `system-prompt` keeps memory more visible to the model.

## Directory layout

The extension stores memory at:

```text
<localPath>/<project-key>/
```

Typical structure:

```text
~/.pi/memory-md/
└── dotfiles-a1b2c3d4/
    ├── core/
    │   ├── user/
    │   │   ├── identity.md
    │   │   └── preferences.md
    │   └── project/
    │       └── overview.md
    └── reference/
```

Only files under `core/` are indexed and injected automatically. `reference/` is for larger material the model can read on demand.

## Memory file format

Each memory file is markdown with simple frontmatter:

```markdown
---
description: "User TypeScript style preferences"
tags: ["user", "typescript", "style"]
created: "2026-03-11"
updated: "2026-03-11"
---

# Preferences

- Prefer 2-space indentation
- Prefer explicit types on exported functions
```

Required:

- `description`

Optional:

- `tags`
- `created`
- `updated`
- `limit`

## Tools

The extension registers these tools:

| Tool | Purpose |
| --- | --- |
| `memory_init` | Initialize the repo and starter project files |
| `memory_sync` | `pull`, `push`, or `status` against the git repo |
| `memory_read` | Read one memory file |
| `memory_write` | Create or update one memory file |
| `memory_list` | List memory files |
| `memory_search` | Search descriptions, tags, or content |
| `memory_check` | Show memory directory structure |

Large tool output is truncated using Pi's standard truncation helpers, with full output saved to a temp file when needed.

## Slash commands

The extension also registers:

- `/memory-status`
- `/memory-init`
- `/memory-refresh`
- `/memory-check`

## Workflow

1. Session starts
2. Extension resolves the current project identity
3. Optional git sync runs for the backing memory repo
4. The extension builds an index from `core/**/*.md`
5. Pi sees the index and can use tools to inspect or update full files

## Notes

- Paths passed to memory tools must stay inside the current project's memory directory
- `repoUrl` is required; the extension only supports a git-backed memory repository
- Project identity prefers git remote metadata when available; otherwise it falls back to the local project path

## Install in this repo

From the repo root:

```bash
make install-extensions
```

Then configure `~/.pi/agent/settings.json` and restart or reload Pi.
