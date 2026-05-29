---
argument-hint: "[message guidance]"
description: Create a clean semantic commit from the current task changes
---
Create a semantic commit for the current task changes. Message guidance: $@

Workflow:

1. Check `git status --short`.
2. Inspect unstaged and staged diffs.
3. Stage only files that belong to this task. Do not include unrelated user changes.
4. Use the `semantic-commit` skill if available.
5. Write a Conventional Commit message that explains what changed.
6. Run the narrowest relevant verification if it has not already been run.
7. Commit with a non-interactive editor environment, for example `GIT_EDITOR=true git commit`.

If the worktree contains unrelated changes and the correct staging set is ambiguous, stop and ask before committing.
