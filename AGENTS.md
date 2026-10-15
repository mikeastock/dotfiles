# AGENTS.md

This file provides guidance for AI assistants working with this codebase.

## Project Overview

This repository manages reusable skills and extensions for AI coding agents including:
- **Claude Code** (Anthropic)
- **Pi Coding Agent** (badlogic)

Skills are specialized instruction sets that guide AI agents through specific tasks. The repository aggregates skills from multiple sources (git submodules) and custom implementations, applies agent-specific overrides, and installs them to the appropriate locations.

## Repository Structure

```
├── plugins.toml                    # Plugin configuration (URLs, enabled items, paths)
├── mise.toml                       # Shared mise dotfiles and bootstrap
├── mise.home.toml                  # macOS/Ubuntu terminals and brew packages
├── mise.omarchy.toml               # Omarchy-only links, bashrc block, login shell
├── plugins/                        # Git submodules (skill sources, owner-repo format)
│   └── <owner>-<repo>/
├── patches/                        # Local changes to plugin skills (<skill>.patch)
├── skills/                         # Custom skills (local)
│   └── <skill-name>/
│       ├── SKILL.md                # Skill definition (YAML frontmatter + markdown)
│       └── <additional files>      # Supporting scripts/resources
├── pi-extensions/                  # Custom Pi extensions (local)
│   └── <extension-name>/index.ts
├── scripts/
│   ├── build.py                    # Python build system (requires Python 3.11+)
│   └── dotfiles.sh                 # mise bootstrap wrapper
├── build/                          # Generated during build (gitignored)
│   ├── amp/
│   ├── bb/
│   ├── claude/
│   ├── codex/
│   └── pi/
├── Makefile                        # Build and install automation
└── README.md                       # User documentation
```

## Key Concepts

### Skills
Skills follow the [Agent Skills specification](https://agentskills.io/specification.md). When creating or modifying skills, fetch the latest specification from that URL for current format requirements.

### Skill Patches
Local changes to a plugin skill live in `patches/<skill>.patch`, a `git diff` against the pristine skill as the build assembles it (after `skills_bundle` and `skills_exclude`). The build applies the patch before installing and fails if it no longer applies. Never edit files inside `plugins/`; edit custom skills in `skills/` directly.

```bash
make skill-patch SKILL=<skill>         # editable copy in build/skill-patch/<skill>/ with the patch applied
make skill-patch-commit SKILL=<skill>  # write its changes to patches/<skill>.patch
```

The patch header records the plugin commit it was written against. After a submodule bump breaks the patch, `make skill-patch` rebuilds that old pristine tree and replays the patch with `git apply --3way`. Conflicts use standard markers, where `ours` is the new upstream and `theirs` is the patch. `skill-patch-commit` refuses while markers remain.

### Plugin Configuration
All plugin configuration is in `plugins.toml`. Plugins use fully qualified names (`owner/repo`) as table keys. The corresponding directory uses hyphen separator: `owner/repo` → `plugins/owner-repo/`.

Each plugin can specify:
- `url` - Git repository URL (required)
- `skills_path` - Glob pattern to find skills (default: `skills/*`)
- `skills` - List of skills to install: `["*"]` for all, `["a", "b"]` for specific, `[]` or omit for none
- `skills_agents` - Agents that receive this plugin's skills (default: amp, claude, pi). List `codex` or `bb` to target those opt-in agents
- `skills_bundle` - Per skill, sibling skill names or globs copied into `<skill>/skills/` so one installed skill carries the skills it reads by path
- `skills_exclude` - Glob patterns of files removed from built plugin skills
- `extensions_path` - Glob pattern to find extensions (default: `extensions/*.ts`)
- `extensions` - List of extensions to install: `["*"]` for all, `["a", "b"]` for specific, `[]` or omit for none
- `alias` - Optional prefix to prevent name collisions

## Development Workflow

### Setup
```bash
git submodule update --init --recursive
make install
```

### Common Commands
| Command | Description |
|---------|-------------|
| `make install` | Build and install skills, extensions, prompts, themes, and Amp plugins |
| `make install DOTFILES=1` | Build and install agent artifacts plus machine dotfiles |
| `make dotfiles` | Install machine dotfiles (auto-detects Omarchy) |
| `make dotfiles-clean` | Remove machine dotfile links |
| `make install-non-interactive` | Install for headless/automated environments (skips interactive extensions) |
| `make build` | Build skills to `build/` without installing |
| `make install-skills` | Install skills only |
| `make install-extensions` | Install Pi extensions only |
| `make clean` | Remove all installed artifacts and build directory |
| `make plugin-update` | Update all plugin submodules to latest |

### Verification: end-to-end only

**Unit tests are banned. Do not write, restore, or add infrastructure for them.** This applies to extensions, plugins, skills, scripts, and vendored code maintained in this repository. Do not disguise unit tests as integration or end-to-end tests.

All previous test suites have been removed. There is currently no automated end-to-end suite or `test` command. Future tests must follow these rules:

- Exercise real user flows through public interfaces: installed agent commands, CLI processes, HTTP APIs, or the running UI. Use real components and storage, not mocks, stubs, or direct calls to internal helpers.
- Cover a few meaningful happy paths and likely user-visible refusals. Before writing a test, name the bug it catches. One test per distinct failure mode; avoid duplicate coverage and matrices of near-identical cases.
- Assert observable behavior, not source-code strings, implementation structure, private invariants, or the existence of tests.
- New end-to-end files, helpers, fixtures, and runners require explicit user approval. A request to implement, fix, test, or verify something does not by itself authorize adding them. Never recreate the removed suites automatically.
- When no approved test change is in scope, use direct end-to-end runtime checks and the static gates below. Use disposable directories and a temporary HOME for installation checks; do not alter real agent installations as a side effect of verification.
- Run only the affected end-to-end checks. Report the exact command, observed result, and any logs, screenshots, or other reproducible evidence. Be explicit about flows not verified; typechecking alone does not prove runtime behavior.

Static gates (not tests):

```bash
pnpm typecheck
npm run typecheck --prefix bb-plugins/bb-plugin-t3sidebar
npm run typecheck --prefix bb-plugins/bb-plugin-tok-speed
npm run typecheck --prefix bb-plugins/bb-plugin-provider-muse
npm run typecheck --prefix bb-plugins/bb-plugin-diffr
```

### CI/CD
GitHub Actions (`.github/workflows/typecheck.yml`) runs the root and vendored BB plugin typechecks on push/PR to main/master. It does not run tests.

## Code Conventions

### Skills (SKILL.md)
- Follow the [Agent Skills specification](https://agentskills.io/specification.md) - fetch it for current format requirements
- Include workflow diagrams (graphviz dot format) for complex processes
- Document prerequisites, step-by-step processes, and common mistakes
- Reference related skills when appropriate
- Use the `agents` frontmatter field to limit which agents receive a skill:
  ```yaml
  ---
  name: my-skill
  description: Only for claude
  agents: [claude]  # Only install for claude (omit for all agents)
  ---
  ```
  The `agents` field is stripped from the built skill. Omitting it installs for Amp, Claude, and Pi only. Codex and bb are opt-in: they receive a custom skill only when its `agents` list names them.
- Use `metadata.user-invocable-only: true` to prevent auto-triggering. The build emits `disable-model-invocation: true` for Claude and Pi, plus `policy.allow_implicit_invocation: false` for Codex:
  ```yaml
  ---
  name: my-skill
  description: Only when the user explicitly asks
  metadata:
    user-invocable-only: "true"
  ---
  ```

### Skill Scripts (Python)
When skills include Python scripts, use [uv inline script metadata](https://docs.astral.sh/uv/guides/scripts/) for dependency management. This allows scripts to declare their dependencies directly in the file, and uv automatically manages the virtual environment.

Example script with inline dependencies:
```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests<3",
#     "rich",
# ]
# ///

import requests
from rich.pretty import pprint

resp = requests.get("https://api.example.com/data")
pprint(resp.json())
```

Benefits:
- No separate `requirements.txt` or virtual environment setup needed
- Dependencies are self-documented in the script
- uv handles environment creation and caching automatically
- Scripts remain portable and reproducible

To add dependencies to an existing script: `uv add --script script.py 'package-name'`

### Extensions (TypeScript - Pi only)
Location: `pi-extensions/<extension-name>/index.ts`

Fetch the latest documentation from [Pi Coding Agent extensions](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md) for current extension API and format requirements.

Extensions use the unified `ExtensionAPI` which provides:
- Event subscriptions via `pi.on("event_name", handler)`
- Tool registration via `pi.registerTool({ ... })`
- Command registration via `pi.registerCommand("name", { ... })`
- UI interactions via `pi.ui.select()`, `pi.ui.confirm()`, etc.

## Installation Locations

| Agent | Skills | Extensions | Config |
|-------|--------|------------|--------|
| Amp | `~/.config/agents/skills/` | N/A | `~/.config/amp/settings.json` |
| bb | `~/.bb/skills/` (opt-in) | N/A | N/A |
| Claude Code | `~/.claude/skills/` | N/A | N/A |
| Codex | `~/.codex/skills/` | N/A | `~/.codex/config.toml` |
| OpenCode | N/A | N/A | `~/.config/opencode/opencode.jsonc` |
| Pi Agent | `~/.agents/skills/` | `~/.pi/agent/extensions/` | `~/.pi/agent/settings.json` |

## Adding New Content

### Adding a Custom Skill
1. Fetch the [Agent Skills specification](https://agentskills.io/specification.md) for the current format
2. Create `skills/<skill-name>/SKILL.md` following the specification
3. Optionally add `agents: [claude, pi]` to frontmatter to limit installation to specific agents
4. Add any supporting files to the same directory
5. When vendoring an upstream skill, read its `description` before copying it verbatim. A description that claims every turn ("must always apply", "use on any task") will auto-trigger on unrelated work; narrow it to the explicit ask or add `metadata.user-invocable-only: "true"`.
6. Run `make install` to build and install
7. Update README.md: add to "Notable custom skills" and directory structure

### Patching a Plugin Skill
1. Run `make skill-patch SKILL=<skill-name>` and edit the printed copy
2. Run `make skill-patch-commit SKILL=<skill-name>` to write `patches/<skill-name>.patch`
3. Run `make install-skills` and verify the installed skill

### Adding an Extension (Pi only)
1. Fetch the [Pi Coding Agent extensions documentation](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md) for the current API
2. Create `pi-extensions/<extension-name>/index.ts` following the documentation
3. Run `make install-extensions`
4. Update README.md: add to "Notable custom Pi extensions" and directory structure

### Adding a New Plugin
1. Add submodule: `git submodule add <url> plugins/<owner>-<repo>`
2. Add plugin configuration to `plugins.toml`:
   ```toml
   ["owner/repo"]
   url = "https://github.com/owner/repo"
   skills = ["*"]  # Use ["*"] for all, or list specific skills
   ```
3. Run `make install`

## Important Notes

- Skills are **copied** (not symlinked) during installation
- The `build/` directory is regenerated on each build
- Running `make clean` removes both installed files and build artifacts
- **Keep README.md up to date**: When adding, removing, or renaming skills or extensions, update the corresponding README lists and directory structure
- **Keep verification guidance current**: Update the verification and CI sections when changing gates or adding explicitly approved end-to-end checks. Unit tests remain prohibited.
- **Requires Python 3.11+** for the build system (uses `tomllib` from stdlib)
