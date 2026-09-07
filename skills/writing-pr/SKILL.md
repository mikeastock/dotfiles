---
name: writing-pr
description: Use when writing or editing a pull request title or body.
---

# Writing a PR title and body

- Write a concise body. Do not write an essay or include routine "validation / I ran tests" text.
- Focus on Mermaid code-block diagrams and code samples or snippets, including internals or sample usage. Use bullet points for prose.
- For visual changes, whether direct or indirect, show a before/after table with uploaded images or videos.
- For benchmarks, always show before/after tables using the target branch as the baseline and the PR as the candidate.
- Describe the final aggregate change that will land in the squash merge. Omit intermediate PR details: if the PR shrank from 6,000 lines to 1,000, or was refactored between commits, that history does not belong in the commentary.
- For truly impressive, difficult, high-risk, or wide-scope changes, a technical-blog-style body is appropriate. Include context, storytelling, code samples, before/after comparisons, diagrams, and images as useful.
- Use code references where helpful.
