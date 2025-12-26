# Agents

This repository contains reusable skills and custom tools for AI coding agents including [Pi Coding Agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent), Claude Code, and [Codex CLI](https://github.com/openai/codex).

## Installation

```bash
make install
```

This installs skills and tools for all supported agents. See `make help` for more options:

```
make install         Install skills and tools for all agents
make install-skills  Install skills only (Claude Code, Codex CLI, Pi via Codex)
make install-tools   Install custom tools only (Pi agent)
make install-claude  Install skills for Claude Code
make install-codex   Install skills for Codex CLI (also used by Pi agent)
make clean           Remove all installed skills and tools
```

## What are Skills?

Skills are specialized instruction sets that guide AI agents through specific tasks and workflows. Each skill provides structured guidance for a particular type of work, helping agents follow best practices and consistent processes.

Skills are loaded by agents when a task matches the skill's description. The agent reads the skill file and follows its instructions to complete the task effectively.

Skills follow the [Agent Skills standard](https://agentskills.io/specification) with YAML frontmatter containing `name` and `description` fields.

### Skill Locations

| Agent | User Skills | Project Skills |
|-------|-------------|----------------|
| Pi Coding Agent | `~/.codex/skills/**/SKILL.md` (reads Codex skills) | `.pi/skills/**/SKILL.md` |
| Claude Code | `~/.claude/skills/*/SKILL.md` | `.claude/skills/*/SKILL.md` |
| Codex CLI | `~/.codex/skills/**/SKILL.md` | - |

> **Note:** Pi Coding Agent automatically reads skills from the Codex CLI location (`~/.codex/skills`), so installing skills for Codex also makes them available to Pi.

### Skill Format

```markdown
---
name: my-skill
description: Description of what this skill does and when to use it.
---

# My Skill

Instructions for the agent...
```

## What are Custom Tools?

Custom tools extend the built-in toolset (read, write, edit, bash, etc.) and are called by the LLM directly. They are TypeScript modules that can include custom TUI integration for user input and custom rendering.

> **Note:** Custom tools are currently only supported by Pi Coding Agent.

### Tool Locations

| Agent | User Tools | Project Tools |
|-------|------------|---------------|
| Pi Coding Agent | `~/.pi/agent/tools/*/index.ts` | `.pi/tools/*/index.ts` |

## Available Skills

| Skill | Description |
|-------|-------------|
| `brainstorming` | Explores user intent, requirements and design before implementation |
| `dispatching-parallel-agents` | Use when facing 2+ independent tasks that can be worked on without shared state or sequential dependencies |
| `executing-plans` | Use when you have a written implementation plan to execute in a separate session with review checkpoints |
| `fetching-buildkite-failures` | Fetches build results from Buildkite, extracts errors from logs, and helps diagnose and fix CI failures |
| `subagent-driven-development` | Use when executing implementation plans with independent tasks in the current session |
| `systematic-debugging` | Use when encountering any bug, test failure, or unexpected behavior, before proposing fixes |
| `test-driven-development` | Use when implementing any feature or bugfix, before writing implementation code |
| `using-superpowers` | Establishes how to find and use skills at conversation start |
| `verification-before-completion` | Requires running verification commands and confirming output before making any success claims |
| `writing-plans` | Use when you have a spec or requirements for a multi-step task, before touching code |
| `writing-skills` | Use when creating new skills, editing existing skills, or verifying skills work before deployment |

## Available Tools

| Tool | Description |
|------|-------------|
| `question` | Let the LLM ask the user a question with selectable options |

## Structure

```
agents/
├── skills/
│   ├── brainstorming/
│   │   └── SKILL.md
│   ├── fetching-buildkite-failures/
│   │   └── SKILL.md
│   └── ...
├── tools/
│   └── pi/
│       ├── question/
│       │   └── index.ts
│       └── ...
├── Makefile
└── README.md
```

## References

- [Pi Coding Agent Skills Documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent#skills)
- [Pi Coding Agent Custom Tools Documentation](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent#custom-tools)
- [Codex CLI Skills Documentation](https://developers.openai.com/codex/skills)
- [Agent Skills Specification](https://agentskills.io/specification)
