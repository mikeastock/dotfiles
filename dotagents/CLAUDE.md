# CLAUDE.md

This file provides guidance for AI assistants working with this codebase.

## Project Overview

This repository manages reusable skills, custom tools, and hooks for AI coding agents including:
- **Claude Code** (Anthropic)
- **Pi Coding Agent** (badlogic)
- **Codex CLI** (OpenAI)

Skills are specialized instruction sets that guide AI agents through specific tasks. The repository aggregates skills from multiple sources (git submodules) and custom implementations, applies agent-specific overrides, and installs them to the appropriate locations.

## Repository Structure

```
agents/
├── plugins/                        # Git submodules (skill sources)
│   ├── anthropic-skills/           # github.com/anthropics/skills
│   ├── superpowers/                # github.com/obra/superpowers
│   ├── dev-browser/                # github.com/SawyerHood/dev-browser
│   ├── <name>-enabled.txt          # Filter which skills to install
├── skills/                         # Custom skills (local)
│   └── <skill-name>/
│       ├── SKILL.md                # Skill definition (YAML frontmatter + markdown)
│       └── <additional files>      # Supporting scripts/resources
├── skill-overrides/                # Agent-specific prepends
│   └── <skill>-<agent>.md          # Appended to SKILL.md during build
├── tools/                          # Custom tools (Pi only)
│   └── pi/
│       └── <tool-name>/index.ts
├── hooks/                          # Event hooks (Pi only)
│   └── pi/
│       └── <hook-name>/index.ts
├── tests/                          # Test suite
│   ├── test-helpers.sh             # Shared test utilities
│   ├── test-make.sh                # Makefile tests
│   ├── test-pi-skills-config.sh    # Pi config tests
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

### Enabled Files
Files like `plugins/<name>-enabled.txt` list which skills to install (one per line). If the file is missing, all skills from that plugin are installed.

## Development Workflow

### Setup
```bash
git submodule update --init --recursive
make install
```

### Common Commands
| Command | Description |
|---------|-------------|
| `make install` | Build and install skills, tools, hooks for all agents |
| `make build` | Build skills to `build/` without installing |
| `make install-skills` | Install skills only |
| `make install-tools` | Install Pi tools only |
| `make install-hooks` | Install Pi hooks only |
| `make clean` | Remove all installed artifacts and build directory |
| `make plugin-update` | Update all plugin submodules to latest |
| `make pi-skills-config` | Configure Pi to use only its own skills (avoid duplicates) |

### Testing
```bash
./tests/run-all.sh          # Run all tests
./tests/test-make.sh        # Test Makefile commands
./tests/test-pi-skills-config.sh  # Test Pi config command
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

### Custom Tools (TypeScript - Pi only)
Location: `tools/pi/<tool-name>/index.ts`

Fetch the latest documentation from [Pi Coding Agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) for current tool API and format requirements.

### Hooks (TypeScript - Pi only)
Location: `hooks/pi/<hook-name>/index.ts`

Fetch the latest documentation from [Pi Coding Agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) for current hook API and format requirements.

### Test Scripts (Bash)
- Source `test-helpers.sh` for shared utilities
- Use `setup_sandbox` for isolated testing
- Use assertion helpers: `assert_success`, `assert_file_exists`, `assert_output_contains`, etc.
- Call `print_summary` at end to report results
- Set `trap cleanup EXIT` for automatic cleanup

## Installation Locations

| Agent | Skills | Tools | Hooks |
|-------|--------|-------|-------|
| Claude Code | `~/.claude/skills/` | N/A | N/A |
| Codex CLI | `~/.codex/skills/` | N/A | N/A |
| Pi Agent | `~/.pi/agent/skills/` | `~/.pi/agent/tools/` | `~/.pi/agent/hooks/` |

## Adding New Content

### Adding a Custom Skill
1. Fetch the [Agent Skills specification](https://agentskills.io/specification) for the current format
2. Create `skills/<skill-name>/SKILL.md` following the specification
3. Add any supporting files to the same directory
4. Run `make install` to build and install

### Adding a Skill Override
1. Create `skill-overrides/<skill-name>-<agent>.md` (agent: `claude` or `pi`)
2. Content will be appended to the skill during build

### Adding a Custom Tool (Pi only)
1. Fetch the [Pi Coding Agent documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) for the current tool API
2. Create `tools/pi/<tool-name>/index.ts` following the documentation
3. Run `make install-tools`

### Adding a Hook (Pi only)
1. Fetch the [Pi Coding Agent documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) for the current hook API
2. Create `hooks/pi/<hook-name>/index.ts` following the documentation
3. Run `make install-hooks`

### Adding a New Plugin
1. Add submodule: `git submodule add <url> plugins/<name>`
2. Optionally create `plugins/<name>-enabled.txt` to filter skills
3. Run `make install`

## Important Notes

- Skills are **copied** (not symlinked) during installation
- The `build/` directory is regenerated on each build
- Running `make clean` removes both installed files and build artifacts
- Use `make pi-skills-config` after installation to prevent duplicate skill warnings in Pi when using Claude/Codex skill directories
