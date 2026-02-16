---
summary: 'Slash commands overview and redirect to docs/slash-commands.'
read_when:
  - Editing or adding slash commands.
---
# Slash Commands

Moved to `docs/slash-commands/`. See `docs/slash-commands/README.md` for the index.

1. **Create a markdown file** in `~/.codex/prompts/`:
   ```bash
   echo "# /mycommand\n\nYour prompt instructions..." > ~/.codex/prompts/mycommand.md
   ```

2. **Use the command** in any Codex/Claude Code session:
```text
   /mycommand
   ```

3. **The agent will execute** the prompt from the file

## Best Practices

- **Be specific:** Include exact commands, safety checks, and exit conditions
- **Document constraints:** No destructive git, coordination rules, scope boundaries
- **Make them reusable:** Avoid task-specific details (dates, ticket numbers)
- **Test them:** Run the slash command to verify it works as expected
- **Version control:** Consider storing project-specific commands in `.claude/commands/` (repo-local)

## Project-Local Commands

For project-specific workflows, you can also create commands in the repo root:

**`.claude/commands/`** - For Claude Code
**`.cursor/commands/`** - For Cursor AI

These are checked into version control and shared with the team.

### This Project's Commands

This repository includes the following commands in both `.claude/commands/` and `.cursor/commands/`:

```bash
.claude/commands/          .cursor/commands/
├── automerge.md          ├── automerge.md
├── build.md              ├── build.md
├── commit.md             ├── commit.md
├── commitgroup.md        ├── commitgroup.md
├── improve.md            ├── improve.md
├── fix.md                ├── fix.md
└── massageprs.md         └── massageprs.md
```

**Available commands:**
- `/automerge` - Automated PR review & merge
- `/build` - Build validation with fixes
- `/commit` - Selective commit helper
- `/commitgroup` - Group multiple commits logically
- `/cppp` - Commit all changes in grouped commits and push
- `/different` - Post-review reflection: what would you change?
- `/doit` - Enter autonomous coding mode and execute the plan
- `/improve` - Post-ship retro helper
- `/fix` - Run quality checks & fix all failures
- `/massageprs` - Continuous PR maintenance loop

These commands work identically in both Claude Code and Cursor.
