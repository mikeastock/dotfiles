# dotagents

Skills for AI coding agents.

## Quick Start

```bash
make install
```

## Install Paths

| Agent | Skills Path |
|-------|-------------|
| Claude Code | `~/.claude/skills/` |
| OpenCode, Pi, Codex | `~/.agents/skills/` |

## Super Power Skills

These methodology skills improve AI agent effectiveness:

| Skill | Description |
|-------|-------------|
| `brainstorming` | Explore ideas before implementation through collaborative dialogue |
| `writing-plans` | Create detailed implementation plans with bite-sized tasks |
| `executing-plans` | Execute plans task-by-task with verification |
| `test-driven-development` | Write tests first, watch them fail, implement minimally |
| `systematic-debugging` | Find root cause before attempting fixes |
| `verification-before-completion` | Evidence before claims, always |
| `dispatching-parallel-agents` | Run multiple independent investigations concurrently |
| `receiving-code-review` | Technical rigor when implementing feedback |
| `requesting-code-review` | Verify work meets requirements before merging |
| `semantic-commit` | Conventional commits for clear history |

## Commands

| Command | Description |
|---------|-------------|
| `make install` | Build and install skills for all agents |
| `make build` | Build skills to `build/` without installing |
| `make install-skills` | Install skills only |
| `make clean` | Remove all installed artifacts |
| `make help` | Show all available commands |

## Adding Skills

1. Create `skills/<skill-name>/SKILL.md` with YAML frontmatter
2. Add supporting files to the same directory
3. Run `make install`

See [Agent Skills specification](https://agentskills.io/specification.md) for format details.

## Adding External Plugins

1. Add submodule: `git submodule add <url> plugins/<owner>-<repo>`
2. Configure in `plugins.toml`:
   ```toml
   ["owner/repo"]
   url = "https://github.com/owner/repo"
   skills = ["*"]  # or specific skill names
   ```
3. Run `make install`

## Requirements

- Python 3.11+ (uses `tomllib` from stdlib)
- Git (for submodule management)
