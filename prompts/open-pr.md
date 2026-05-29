---
argument-hint: "[base branch or instructions]"
description: Push the current branch and open a pull request
---
Open a pull request for the current branch. Extra instructions: $@

Workflow:

1. Inspect `git status --short`, current branch, and remotes.
2. Confirm the branch has the intended commits and no unrelated staged changes.
3. Push the branch if needed.
4. Create the PR with a concise title, summary, and verification section.
5. Use the repository's preferred PR tooling if present; otherwise use `gh pr create`.
6. Return the PR URL and any follow-up checks that are still running or needed.

Do not create a PR from `main` or with uncommitted task changes unless the user explicitly asks for that.
