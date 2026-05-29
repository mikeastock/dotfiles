---
argument-hint: "[PR-URL]"
description: Fetch PR review comments and evaluate them before changing code
---
Fetch review comments for this PR and help evaluate them before changing code: $@

Use the `receiving-code-review` skill if available.

Workflow:

1. Fetch unresolved PR review comments, issue comments, requested changes, and failed check summaries.
2. Group comments by concrete required change.
3. Verify each comment against the current codebase before accepting it.
4. Identify comments that are correct, unclear, stale, already fixed, or worth pushing back on.
5. Talk through the findings before editing unless the user explicitly asked to fix them immediately.
6. If edits are requested, implement one coherent group at a time and run targeted verification.

Do not blindly implement external review feedback. Technical correctness for this codebase wins.
