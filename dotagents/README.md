# Agents

This repository contains reusable skills and custom tools for AI coding agents including [Pi Coding Agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent), Claude Code, and [Codex CLI](https://github.com/openai/codex).

## Installation

```bash
git submodule update --init --recursive
make install
```

This builds skills (applying overrides) and installs them for all supported agents. See `make help` for more options:

```
make install         Install skills and tools for all agents
make install-skills  Install skills only (Claude Code, Pi agent)
make install-tools   Install custom tools only (Pi agent)
make build           Build skills with overrides (without installing)
make clean           Remove all installed skills, tools, and build artifacts
```

## Structure

```
agents/
├── plugins/
│   ├── superpowers/                  # git submodule (github.com/obra/superpowers)
│   ├── superpowers-enabled.txt       # which skills to install (optional)
│   ├── dev-browser/                  # git submodule (github.com/SawyerHood/dev-browser)
│   └── dev-browser-enabled.txt       # which skills to install (optional)
├── skills/                           # custom skills
│   └── fetching-buildkite-failures/
├── skill-overrides/                  # agent-specific prepends
│   ├── brainstorming-claude.md
│   └── brainstorming-pi.md
├── tools/
│   └── pi/
│       └── question/
├── build/                            # generated during install
│   ├── claude/
│   └── pi/
├── Makefile
└── README.md
```

## Plugins

Skills are pulled from git submodules in `plugins/`. Each plugin can have an optional `<name>-enabled.txt` file listing which skills to install (one per line). If the file is missing, all skills from that plugin are installed.

| Plugin | Source | Description |
|--------|--------|-------------|
| `superpowers` | [obra/superpowers](https://github.com/obra/superpowers) | Workflow skills for brainstorming, debugging, TDD, etc. |
| `dev-browser` | [SawyerHood/dev-browser](https://github.com/SawyerHood/dev-browser) | Browser automation skill |

### Updating Plugins

```bash
git submodule update --remote --merge
make install
```

## Skill Overrides

Override files in `skill-overrides/<skill>-<agent>.md` are prepended to skills during build. This allows agent-specific customizations without modifying upstream skills.

Example: `skill-overrides/brainstorming-claude.md` is prepended to the brainstorming skill when building for Claude Code.

## Available Skills

### From superpowers

| Skill | Description |
|-------|-------------|
| `brainstorming` | Explores user intent, requirements and design before implementation |
| `dispatching-parallel-agents` | Use when facing 2+ independent tasks without shared state |
| `executing-plans` | Execute implementation plans with review checkpoints |
| `subagent-driven-development` | Execute implementation plans with independent tasks |
| `systematic-debugging` | Use when encountering bugs or unexpected behavior |
| `test-driven-development` | Use when implementing features, before writing implementation code |
| `using-superpowers` | Establishes how to find and use skills at conversation start |
| `verification-before-completion` | Requires running verification before making success claims |
| `writing-plans` | Use when you have requirements for a multi-step task |
| `writing-skills` | Use when creating or editing skills |

### From dev-browser

| Skill | Description |
|-------|-------------|
| `dev-browser` | Browser automation for web development |

### Custom Skills

| Skill | Description |
|-------|-------------|
| `fetching-buildkite-failures` | Fetches build results from Buildkite and helps diagnose CI failures |

## Available Tools

| Tool | Agent | Description |
|------|-------|-------------|
| `question` | Pi | Let the LLM ask the user a question with selectable options |

## What are Skills?

Skills are specialized instruction sets that guide AI agents through specific tasks and workflows. Each skill provides structured guidance for a particular type of work.

Skills follow the [Agent Skills standard](https://agentskills.io/specification) with YAML frontmatter containing `name` and `description` fields.

### Skill Locations

| Agent | User Skills | Project Skills |
|-------|-------------|----------------|
| Pi Coding Agent | `~/.codex/skills/**/SKILL.md` | `.pi/skills/**/SKILL.md` |
| Claude Code | `~/.claude/skills/*/SKILL.md` | `.claude/skills/*/SKILL.md` |
| Codex CLI | `~/.codex/skills/**/SKILL.md` | - |

## What are Custom Tools?

Custom tools extend the built-in toolset and are called by the LLM directly. They are TypeScript modules with custom TUI integration.

> **Note:** Custom tools are currently only supported by Pi Coding Agent.

### Tool Locations

| Agent | User Tools | Project Tools |
|-------|------------|---------------|
| Pi Coding Agent | `~/.pi/agent/tools/*/index.ts` | `.pi/tools/*/index.ts` |

## References

- [Pi Coding Agent Documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent)
- [Codex CLI Skills Documentation](https://developers.openai.com/codex/skills)
- [Agent Skills Specification](https://agentskills.io/specification)
