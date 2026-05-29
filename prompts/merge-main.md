---
argument-hint: "[base branch]"
description: Merge main into the current branch and handle conflicts carefully
---
Merge the latest base branch into the current branch. Base branch: ${1:-main}

Workflow:

1. Check `git status --short` and stop if there are unrelated uncommitted changes that would make the merge unsafe.
2. Fetch the latest refs from the default remote.
3. Confirm the current branch is not the base branch.
4. Merge `origin/${1:-main}` into the current branch.
5. If conflicts appear, inspect each conflict, preserve the current branch's intent, and integrate upstream changes deliberately.
6. Run targeted tests or build checks for the conflicted areas.
7. If the merge produced a merge commit, use a non-interactive editor environment, for example `GIT_EDITOR=true git merge --continue`.
8. Report the merge result, conflicts resolved, verification run, and any remaining risk.

Do not use destructive commands like `git reset --hard` or `git checkout --` unless the user explicitly asks for that exact operation.
