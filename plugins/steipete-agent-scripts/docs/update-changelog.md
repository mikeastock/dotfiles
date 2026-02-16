---
summary: 'Checklist for curating CHANGELOG.md from recent commits'
read_when:
  - Updating CHANGELOG.md or drafting release notes.
---
# Update CHANGELOG.md

Purpose: curate user-facing changes since the last release tag and record them in `CHANGELOG.md` (Unreleased section) for this repo. Derived from the `/update-changelog` prompt, the macOS release notes guide, and CodexBar/Trimmy AGENTS notes.

## Scope & Inputs
- Read the repo’s `AGENTS.MD` first (and the repo-local release doc if it exists, e.g., `docs/RELEASING.md` in app projects).
- Baseline version: use the provided baseline; otherwise the latest tag from `git describe --tags --abbrev=0`.
- Target file: the repo’s `CHANGELOG.md` (keep Trimmy/CodexBar entries app-specific).

## Steps
1) **Pick baseline**
   - If none given: `git describe --tags --abbrev=0` → `<tag>`.
2) **Collect commits since baseline**
   ```bash
   git log <tag>..HEAD --oneline --reverse
   ```
   Skim the diff as needed to understand user-visible impact.
3) **Curate entries (user-facing only)**
   - Include: shipped features, fixes, breaking changes, notable UX or behavior tweaks.
   - Exclude: internal refactors, typo-only edits, dependency bumps without user impact, features added then removed in the same window.
   - Order by impact: breaking → features → fixes → misc.
   - Add PR/issue numbers when available (`#123`)—if you work commit-only, skip the reference and keep the bullet concise (avoid raw hashes).
   - For Trimmy and CodexBar: changelog must stay user-focused; add entries only relevant to that app.
4) **Edit `CHANGELOG.md`**
   - Ensure there is an `## Unreleased` section at the top; create it if missing.
   - Append bullets under `Unreleased`; keep existing style (bullets, past-tense verbs or short descriptors, code in backticks).
   - If preparing a release, keep the “Unreleased” block separate from the versioned section and move the curated notes under the new version when tagging.
5) **Sanity checks**
   - Markdown renders; no duplicate entries; wording concise.
   - If a release just shipped, start a fresh `Unreleased` section for the next patch (per `docs/RELEASING-MAC.md` guidance).

## Quick format example
```markdown
## Unreleased
- Added configurable status probe refresh interval. #123
- Fixed menu bar icon dimming on sleep/wake. #128
```
