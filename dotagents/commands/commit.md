---
description: Create a semantic commit following Conventional Commits specification
allowed-tools: Bash(git status:*), Bash(git diff:*), Bash(git add:*), Bash(git commit:*), Bash(git log:*)
argument-hint: [type] [optional: scope] [optional: message]
---

# Semantic Commit

Create a git commit following the [Conventional Commits](https://www.conventionalcommits.org/) specification.

## Current Repository State

**Git Status:**
!`git status --short`

**Staged Changes:**
!`git diff --cached --stat`

**Unstaged Changes:**
!`git diff --stat`

## Commit Types

| Type | Description |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation only changes |
| `style` | Changes that do not affect the meaning of the code (formatting, semicolons, etc.) |
| `refactor` | A code change that neither fixes a bug nor adds a feature |
| `perf` | A code change that improves performance |
| `test` | Adding missing tests or correcting existing tests |
| `build` | Changes that affect the build system or external dependencies |
| `ci` | Changes to CI configuration files and scripts |
| `chore` | Other changes that don't modify src or test files |
| `revert` | Reverts a previous commit |

## Commit Format

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

- **Breaking changes**: Add `!` after the type/scope, or include `BREAKING CHANGE:` in the footer
- **Scope**: Optional, describes the section of the codebase (e.g., `feat(api):`, `fix(auth):`)

## Instructions

If arguments are provided: `$ARGUMENTS`

1. If no changes are staged, ask which files to stage or stage all changes
2. Review the staged changes to understand what was modified
3. Based on the changes and any provided arguments, create an appropriate semantic commit:
   - If a type is provided as the first argument, use it
   - If a scope is provided as the second argument, include it
   - If a message is provided, incorporate it into the commit description
   - Otherwise, analyze the changes and generate an appropriate type and message
4. The commit message should:
   - Use imperative mood ("add feature" not "added feature")
   - Be concise but descriptive (50 chars or less for the subject line)
   - Explain the "why" not just the "what" in the body if needed
5. Execute the git commit command

## Examples

- `/commit` - Analyze changes and auto-generate appropriate commit
- `/commit feat` - Create a feature commit with auto-generated message
- `/commit fix auth` - Create a fix commit with "auth" scope
- `/commit feat api add user authentication endpoint` - Full specification
