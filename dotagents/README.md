# Agents

This repository contains reusable skills and custom tools for AI coding agents including [Pi Coding Agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent), Claude Code, and [Codex CLI](https://github.com/openai/codex).

## Installation

```bash
git submodule update --init --recursive
make install
```

This builds skills (applying overrides) and installs them for all supported agents. See `make help` for more options:

```
make install           Install skills, tools, and hooks for all agents
make install-skills    Install skills only (Claude Code, Pi agent)
make install-tools     Install custom tools only (Pi agent)
make install-hooks     Install hooks only (Pi agent)
make build             Build skills with overrides (without installing)
make clean             Remove all installed skills, tools, hooks, and build artifacts
make pi-skills-config  Configure Pi agent to use only Pi-specific skills
```

## Structure

```
agents/
├── plugins/
│   ├── anthropic-skills/             # git submodule (github.com/anthropics/skills)
│   ├── anthropic-skills-enabled.txt  # which skills to install (optional)
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
├── hooks/
│   └── pi/
│       ├── confirm-destructive/
│       └── protected-paths/
├── tests/                            # test suite
│   ├── test-helpers.sh               # shared test utilities
│   ├── test-make.sh                  # Makefile tests
│   ├── test-pi-skills-config.sh      # pi-skills-config tests
│   └── run-all.sh                    # run all tests
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
| `anthropic-skills` | [anthropics/skills](https://github.com/anthropics/skills) | Official Anthropic skills for documents, design, etc. |
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

### From anthropic-skills

| Skill | Description |
|-------|-------------|
| `frontend-design` | Design and build frontend UIs with Tailwind CSS |

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

## Available Hooks

| Hook | Agent | Description |
|------|-------|-------------|
| `confirm-destructive` | Pi | Prompts for confirmation before destructive session actions (macOS only) |
| `protected-paths` | Pi | Blocks write and edit operations to protected paths (.env, .git/, node_modules/) |

## What are Skills?

Skills are specialized instruction sets that guide AI agents through specific tasks and workflows. Each skill provides structured guidance for a particular type of work.

Skills follow the [Agent Skills standard](https://agentskills.io/specification) with YAML frontmatter containing `name` and `description` fields.

### Skill Locations

Skills are installed to:

| Agent | Location |
|-------|----------|
| Claude Code | `~/.claude/skills/` |
| Codex CLI | `~/.codex/skills/` |
| Pi Coding Agent | `~/.pi/agent/skills/` |

Since skills are installed to all three locations, disable Claude and Codex skill loading in Pi to avoid duplicate skill warnings:

```bash
make pi-skills-config
```

This uses `jq` to update `~/.pi/agent/settings.json` with:

```json
{
  "skills": {
    "enableClaudeUser": false,
    "enableCodexUser": false
  }
}
```

The command preserves any existing settings in the file. Requires `jq` to be installed (`brew install jq` on macOS or `apt install jq` on Linux).

See Pi's [skills documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent/docs/skills.md) for all available options.

## What are Custom Tools?

Custom tools extend the built-in toolset and are called by the LLM directly. They are TypeScript modules with custom TUI integration.

> **Note:** Custom tools are currently only supported by Pi Coding Agent.

### Tool Locations

| Agent | User Tools | Project Tools |
|-------|------------|---------------|
| Pi Coding Agent | `~/.pi/agent/tools/*/index.ts` | `.pi/tools/*/index.ts` |

## What are Hooks?

Hooks are event listeners that intercept and can modify agent behavior. They can block operations, add logging, enforce policies, or extend functionality.

> **Note:** Hooks are currently only supported by Pi Coding Agent.

Hooks are TypeScript modules that export a default function taking a `HookAPI` object. They can listen to events like `tool_call` and return actions like `{ block: true, reason: "..." }`.

See Pi's [hooks documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent#hooks) for details.

### Hook Locations

| Agent | User Hooks | Project Hooks |
|-------|------------|---------------|
| Pi Coding Agent | `~/.pi/agent/hooks/*/index.ts` | `.pi/hooks/*/index.ts` |

## References

- [Pi Coding Agent Documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent)
- [Codex CLI Skills Documentation](https://developers.openai.com/codex/skills)
- [Agent Skills Specification](https://agentskills.io/specification)
