---
summary: 'Shared release guardrails (GitHub releases + changelog hygiene)'
read_when:
  - Preparing a release or editing release notes.
---

# Shared Release Guardrails

- Title every GitHub release as `<Project> <version>` — never the version alone.
- Release body = the curated changelog bullets for that version, verbatim and in order; no extra meta text.
- Attach all shipping artifacts (zips/tarballs/checksums/dSYMs as applicable) that the downstream clients expect.
- If the repo has its own release doc, follow it; otherwise adapt this guidance to the stack and add a repo-local checklist.
- When a release publishes, verify the tag, assets, and notes on GitHub before announcing; fix mismatches immediately (retitle, re-upload assets, or retag if necessary).
- NPM releases: assume login is already set up; publish may require the user’s 6-digit OTP or it will fail. If OTP/TOTP is in 1Password, prefer `op` (see `docs/npm-publish-with-1password.md`).
