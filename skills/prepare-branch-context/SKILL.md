---
name: prepare-branch-context
description: Analyze the current branch's diff from main and related PR to build context for followup requests. Triggers on "prepare context", "branch context", "catch me up", "what's on this branch".
user-invocable: true
---

# Prepare Branch Context

Build a comprehensive understanding of the current branch so you can handle followup requests with full context.

## Steps

1. **Identify the current branch and base branch**:
   ```bash
   git branch --show-current
   git merge-base HEAD main
   ```

2. **Gather the diff from main**:
   ```bash
   git diff main...HEAD --stat
   git diff main...HEAD
   ```
   Read through the full diff carefully. Understand what files were changed, added, or removed, and what the changes do.

3. **Review the commit history on this branch**:
   ```bash
   git log main..HEAD --oneline
   ```
   Read commit messages to understand the progression of changes.

4. **Check for a related PR**:
   ```bash
   gh pr list --head "$(git branch --show-current)" --json number,title,body,url,state,comments --jq '.[0]'
   ```
   If a PR exists, read its title, description, and comments for additional context (acceptance criteria, discussion, review feedback).

5. **Summarize your understanding** to the user:
   - What this branch does (high-level purpose)
   - Key files and areas of the codebase affected
   - Notable decisions or patterns visible in the changes
   - Any open review comments or discussion from the PR
   - Current state (clean, uncommitted changes, etc.)

6. **Signal readiness**: Tell the user you're ready for followup questions or tasks related to this branch.

## Rules

- Do NOT make any changes to files. This skill is read-only.
- Read the actual diff content, not just the stat summary. You need to understand the code changes.
- If there's no PR, that's fine — just skip that step and note it.
- If the diff is very large, focus on understanding the overall structure first, then read key files in detail.
- Keep the summary concise but thorough enough that you could confidently make changes to this branch.
- If the branch is `main` or has no divergence from main, tell the user there's nothing to analyze.
