---
summary: 'Raise next patch Unreleased section in CHANGELOG.md (commit + push).'
read_when:
  - You just cut a release and want to open the next patch cycle.
---
# /raise

Goal: If `CHANGELOG.md` top release is dated (not `Unreleased`), create a new top section for the next patch version as `Unreleased`, then commit + push **only** `CHANGELOG.md`.

0) Guardrails
- Must be on `main` (or repo default) and `git status -sb` clean.
- If `CHANGELOG.md` already starts with `## <version> — Unreleased`: stop (nothing to do).
- If the top `##` version can’t be parsed as `X.Y.Z`: stop + ask.

1) Compute next patch
- In `CHANGELOG.md`, find the first header like: `## X.Y.Z — <date|Unreleased>`.
- If suffix is a date (released), bump patch: `X.Y.(Z+1)`.

2) Edit changelog
- Insert at the top (above the last released section):
  - `## X.Y.(Z+1) — Unreleased`
  - blank line
- Do not touch any other release sections.

3) Commit + push
- `committer "docs(changelog): start X.Y.(Z+1) cycle" CHANGELOG.md`
- `git push`

4) Verify CI
- `GH_PAGER=cat gh run list -L 5 --branch main --json status,conclusion,workflowName,displayTitle,updatedAt`
- If any run fails: `gh run view <id> --log`, fix, commit, push, repeat.
