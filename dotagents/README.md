# Agents

This repository contains reusable skills and extensions for AI coding agents including [Pi Coding Agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent), Claude Code, and [Codex CLI](https://github.com/openai/codex).

## Requirements

- Python 3.11+ (uses `tomllib` from stdlib)
- Git (for submodule management)

## Installation

```bash
make install
```

This initializes submodules, builds skills (applying overrides), and installs them for all supported agents. See `make help` for more options:

```
make install             Initialize submodules and install skills, commands, and extensions
make install-skills      Install skills only (Claude Code, Codex, Pi agent)
make install-commands    Install slash commands only (Claude Code, Codex, Pi agent)
make install-extensions  Install extensions only (Pi agent)
make build               Build skills with overrides (without installing)
make clean               Remove all installed skills, commands, extensions, and build artifacts
make pi-skills-config    Configure Pi agent to use only Pi-specific skills
```

## Structure

```
agents/
├── plugins.toml                      # plugin configuration
├── plugins/
│   ├── anthropic-skills/             # git submodule (github.com/anthropics/skills)
│   ├── superpowers/                  # git submodule (github.com/obra/superpowers)
│   ├── dev-browser/                  # git submodule (github.com/SawyerHood/dev-browser)
│   ├── compound-engineering/         # git submodule (github.com/EveryInc/compound-engineering-plugin)
│   ├── agent-stuff/                  # git submodule (github.com/mitsuhiko/agent-stuff)
│   └── pi-interview-tool/            # git submodule (github.com/nicobailon/pi-interview-tool)
├── skills/                           # custom skills
│   └── fetching-buildkite-failures/
├── commands/                         # slash commands (Claude Code, Codex)
│   └── commit.md
├── skill-overrides/                  # agent-specific appends
│   ├── brainstorming-claude.md
│   └── brainstorming-pi.md
├── extensions/
│   └── pi/
│       ├── AskUserQuestion/
│       ├── confirm-destructive/
│       └── protected-paths/
├── scripts/
│   └── build.py                      # Python build system
├── tests/                            # test suite
│   ├── test-helpers.sh
│   ├── test-make.sh
│   ├── test-pi-skills-config.sh
│   ├── test-pi-extensions.sh
│   └── run-all.sh
├── build/                            # generated during install
│   ├── claude/
│   └── pi/
├── Makefile
└── README.md
```

## Configuration

All plugin configuration is in `plugins.toml`:

```toml
[superpowers]
url = "https://github.com/obra/superpowers"
skills = [
    "brainstorming",
    "systematic-debugging",
    "test-driven-development",
]

[agent-stuff]
url = "https://github.com/mitsuhiko/agent-stuff"
skills = []  # No skills from this plugin
extensions = ["answer"]

[compound-engineering]
url = "https://github.com/EveryInc/compound-engineering-plugin"
skills_path = "plugins/*/skills/*"  # Custom path for nested structure
skills = ["dspy-ruby"]

[dev-browser]
url = "https://github.com/SawyerHood/dev-browser"
skills = ["*"]  # Install all skills from this plugin
```

### Configuration Options

Each plugin supports these options:

| Option | Description |
|--------|-------------|
| `url` | Git repository URL (required) |
| `skills_path` | Glob pattern to find skills (default: `skills/*`) |
| `skills` | List of skills to install, or omit for all |
| `extensions_path` | Glob pattern to find extensions (default: `extensions/*.ts`) |
| `extensions` | List of extensions to install, or omit for all |
| `alias` | Optional prefix to prevent name collisions |

### Updating Plugins

```bash
make plugin-update
make install
```

## Skill Overrides

Override files in `skill-overrides/<skill>-<agent>.md` are appended to skills during build. This allows agent-specific customizations without modifying upstream skills.

Example: `skill-overrides/brainstorming-pi.md` is appended to the brainstorming skill when building for Pi agent.

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

### From compound-engineering

| Skill | Description |
|-------|-------------|
| `dspy-ruby` | DSPy patterns for Ruby development |

### From dev-browser

| Skill | Description |
|-------|-------------|
| `dev-browser` | Browser automation for web development |

### Custom Skills

| Skill | Description |
|-------|-------------|
| `fetching-buildkite-failures` | Fetches build results from Buildkite and helps diagnose CI failures |

## Available Commands

| Command | Description |
|---------|-------------|
| `/commit` | Create a semantic commit following Conventional Commits specification |

## Available Extensions

### From agent-stuff

| Extension | Agent | Description |
|-----------|-------|-------------|
| `answer` | Pi | Extracts questions from assistant responses into interactive Q&A with custom TUI |

### From pi-interview-tool

| Extension | Agent | Description |
|-----------|-------|-------------|
| `pi-interview-tool` | Pi | Interactive web-based form for gathering user responses to clarification questions |

### Custom Extensions

| Extension | Agent | Description |
|-----------|-------|-------------|
| `AskUserQuestion` | Pi | Ask the user a question and let them pick from options or enter a custom response |
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

## What are Slash Commands?

Slash commands are shortcuts that trigger specific prompts or actions. They are markdown files that define a prompt template invoked via `/command-name` syntax.

All three agents support the same markdown format with YAML frontmatter (`description`) and content with argument placeholders (`$1`, `$ARGUMENTS`).

### Command Locations

| Agent | Location |
|-------|----------|
| Claude Code | `~/.claude/commands/` |
| Codex CLI | `~/.codex/commands/` |
| Pi Coding Agent | `~/.pi/agent/prompts/` |

## What are Extensions?

Extensions are TypeScript modules that extend Pi Coding Agent functionality. They can:
- Register custom tools callable by the LLM
- Subscribe to lifecycle events (tool calls, session changes, etc.)
- Block or modify operations
- Add custom TUI components
- Register slash commands

> **Note:** Extensions are currently only supported by Pi Coding Agent.

Extensions use the unified `ExtensionAPI` which provides:
- Event subscriptions via `pi.on("event_name", handler)`
- Tool registration via `pi.registerTool({ ... })`
- Command registration via `pi.registerCommand("name", { ... })`
- UI interactions via `pi.ui.select()`, `pi.ui.confirm()`, etc.

See Pi's [extensions documentation](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md) for details.

### Extension Locations

| Agent | User Extensions | Project Extensions |
|-------|-----------------|-------------------|
| Pi Coding Agent | `~/.pi/agent/extensions/*/index.ts` | `.pi/extensions/*/index.ts` |

## References

- [Claude Code Skills Documentation](https://docs.anthropic.com/en/docs/claude-code/skills)
- [Pi Coding Agent Documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent)
- [Pi Extensions Documentation](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md)
- [Codex CLI Skills Documentation](https://developers.openai.com/codex/skills)
- [Agent Skills Specification](https://agentskills.io/specification)
