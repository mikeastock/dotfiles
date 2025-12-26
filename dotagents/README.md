# Agent Skills

This repository contains reusable skills for AI coding agents including Claude Code, Codex, and Pi Coding Agent.

## What are Skills?

Skills are specialized instruction sets that guide AI agents through specific tasks and workflows. Each skill provides structured guidance for a particular type of work, helping agents follow best practices and consistent processes.

## Usage

Skills are loaded by agents when a task matches the skill's description. The agent reads the skill file and follows its instructions to complete the task effectively.

## Available Skills

| Skill | Description |
|-------|-------------|
| `fetching-buildkite-failures` | Fetches build results from Buildkite, extracts errors from logs, and helps diagnose and fix CI failures |

## Structure

Each skill lives in its own directory and contains a `SKILL.md` file with the instructions for that skill.

```
skills/
├── brainstorming/
│   └── SKILL.md
├── test-driven-development/
│   └── SKILL.md
└── ...
```
