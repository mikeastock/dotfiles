# CLAUDE.md

This file provides guidance for AI assistants working with this codebase.

## Project Overview

This repository manages reusable skills and extensions for AI coding agents including:
- **Claude Code** (Anthropic)
- **Pi Coding Agent** (badlogic)
- **Codex CLI** (OpenAI)

Skills are specialized instruction sets that guide AI agents through specific tasks. The repository aggregates skills from multiple sources (git submodules) and custom implementations, applies agent-specific overrides, and installs them to the appropriate locations.

## Repository Structure

```
agents/
├── plugins.toml                    # Plugin configuration (URLs, enabled items, paths)
├── plugins/                        # Git submodules (skill sources, owner-repo format)
│   ├── anthropics-skills/          # github.com/anthropics/skills
│   ├── obra-superpowers/           # github.com/obra/superpowers
│   ├── SawyerHood-dev-browser/     # github.com/SawyerHood/dev-browser
│   ├── EveryInc-compound-engineering-plugin/  # github.com/EveryInc/compound-engineering-plugin
│   └── mitsuhiko-agent-stuff/      # github.com/mitsuhiko/agent-stuff
├── skills/                         # Custom skills (local)
│   └── <skill-name>/
│       ├── SKILL.md                # Skill definition (YAML frontmatter + markdown)
│       └── <additional files>      # Supporting scripts/resources
├── skill-overrides/                # Agent-specific appends
│   └── <skill>-<agent>.md          # Appended to SKILL.md during build
├── extensions/                     # Custom extensions (Pi only)
│   └── pi/
│       └── <extension-name>/index.ts
├── scripts/
│   └── build.py                    # Python build system (requires Python 3.11+)
├── tests/                          # Test suite
│   ├── test-helpers.sh             # Shared test utilities
│   ├── test-make.sh                # Makefile tests
│   ├── test-pi-skills-config.sh    # Pi config tests
│   ├── test-pi-extensions.sh       # Pi extensions type-check tests
│   └── run-all.sh                  # Run all tests
├── build/                          # Generated during build (gitignored)
│   ├── claude/                     # Skills built for Claude Code
│   └── pi/                         # Skills built for Pi/Codex
├── Makefile                        # Build and install automation
└── README.md                       # User documentation
```

## Key Concepts

### Skills
Skills follow the [Agent Skills specification](https://agentskills.io/specification). When creating or modifying skills, fetch the latest specification from that URL for current format requirements.

### Skill Overrides
Files in `skill-overrides/<skill>-<agent>.md` are **appended** to the skill's SKILL.md during build. This allows agent-specific customizations without modifying upstream skills.

### Plugin Configuration
All plugin configuration is in `plugins.toml`. Plugins use fully qualified names (`owner/repo`) as table keys. The corresponding directory uses hyphen separator: `owner/repo` → `plugins/owner-repo/`.

Each plugin can specify:
- `url` - Git repository URL (required)
- `skills_path` - Glob pattern to find skills (default: `skills/*`)
- `skills` - List of skills to install: `["*"]` for all, `["a", "b"]` for specific, `[]` or omit for none
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
| `make install` | Build and install skills and extensions for all agents |
| `make build` | Build skills to `build/` without installing |
| `make install-skills` | Install skills only |
| `make install-extensions` | Install Pi extensions only |
| `make clean` | Remove all installed artifacts and build directory |
| `make plugin-update` | Update all plugin submodules to latest |
| `make pi-skills-config` | Configure Pi to use only its own skills (avoid duplicates) |

### Testing
```bash
./tests/run-all.sh          # Run all tests
./tests/test-make.sh        # Test Makefile commands
./tests/test-pi-skills-config.sh  # Test Pi config command
./tests/test-pi-extensions.sh     # Test Pi extensions type-checking
```

Tests use a sandbox environment (temporary HOME directory) to avoid affecting real agent installations. The test framework provides assertion helpers in `tests/test-helpers.sh`.

### CI/CD
GitHub Actions runs `./tests/run-all.sh` on push/PR to main/master branches.

## Code Conventions

### Skills (SKILL.md)
- Follow the [Agent Skills specification](https://agentskills.io/specification) - fetch it for current format requirements
- Include workflow diagrams (graphviz dot format) for complex processes
- Document prerequisites, step-by-step processes, and common mistakes
- Reference related skills when appropriate

### Extensions (TypeScript - Pi only)
Location: `extensions/pi/<extension-name>/index.ts`

Fetch the latest documentation from [Pi Coding Agent extensions](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md) for current extension API and format requirements.

Extensions use the unified `ExtensionAPI` which provides:
- Event subscriptions via `pi.on("event_name", handler)`
- Tool registration via `pi.registerTool({ ... })`
- Command registration via `pi.registerCommand("name", { ... })`
- UI interactions via `pi.ui.select()`, `pi.ui.confirm()`, etc.

### Test Scripts (Bash)
- Source `test-helpers.sh` for shared utilities
- Use `setup_sandbox` for isolated testing
- Use assertion helpers: `assert_success`, `assert_file_exists`, `assert_output_contains`, etc.
- Call `print_summary` at end to report results
- Set `trap cleanup EXIT` for automatic cleanup

## Installation Locations

| Agent | Skills | Extensions |
|-------|--------|------------|
| Claude Code | `~/.claude/skills/` | N/A |
| Codex CLI | `~/.codex/skills/` | N/A |
| Pi Agent | `~/.pi/agent/skills/` | `~/.pi/agent/extensions/` |

## Adding New Content

### Adding a Custom Skill
1. Fetch the [Agent Skills specification](https://agentskills.io/specification) for the current format
2. Create `skills/<skill-name>/SKILL.md` following the specification
3. Add any supporting files to the same directory
4. Run `make install` to build and install
5. Update README.md: add to "Custom Skills" table and directory structure

### Adding a Skill Override
1. Create `skill-overrides/<skill-name>-<agent>.md` (agent: `claude` or `pi`)
2. Content will be appended to the skill during build

### Adding an Extension (Pi only)
1. Fetch the [Pi Coding Agent extensions documentation](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md) for the current API
2. Create `extensions/pi/<extension-name>/index.ts` following the documentation
3. Run `make install-extensions`
4. Update README.md: add to "Available Extensions" table and directory structure

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
- Use `make pi-skills-config` after installation to prevent duplicate skill warnings in Pi when using Claude/Codex skill directories
- **Keep README.md up to date**: When adding, removing, or renaming skills or extensions, update the corresponding tables and directory structure in README.md
- **Requires Python 3.11+** for the build system (uses `tomllib` from stdlib)
