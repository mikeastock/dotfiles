---
name: deviation-retro
description: Use when asked for a deviation retro, when a project/milestone accumulated several implementation runs, or before deleting plan docs — mines the Deviations/As-built sections of design docs for recurring patterns and promotes them into docs, plan templates, and skills.
metadata:
  category: superpowers
---

# Deviation Retro

Deviations are data. Every implementation run logs a `## Deviations` section at the bottom of its design doc, recording where the territory contradicted the plan (see executing-plans); at ship it is distilled into the doc's `## As built` tail. This skill is the learning half: collect those logs, find what recurs, and fix the map — so the next plan doesn't contain the same defect.

**The rule: a deviation that recurs across runs is a map defect, not executor noise. Fix the map.**

## When to run

- The user asks for a retro ("deviation retro", "what did we learn", "mine the notes").
- A project or milestone closes with several implementation runs behind it.
- Plan/design docs are about to be deleted (pre-merge cleanup) — mine before deleting; the notes are an inbox, not an archive.

## Collect

Gather every Deviations log in reach for the period/project:

- `## Deviations` / `## As built` sections at the bottom of design docs (`docs/design/`), in-repo and in live worktrees.
- Legacy: archived `~/.local/state/wiki-workers/*.notes.md` and stray `implementation-notes.md` files (the pre-2026-07-09 convention).
- Deviations sections quoted in PR descriptions and final reports.

If a run demonstrably deviated but logged nothing, note that too — a silent deviation is a reporting defect worth fixing at the source.

## Cluster and classify

For each deviation, decide: **one-off** (a genuine territory quirk — drop it) or **recurring / structural** (seen across runs, or obviously will recur). Recurring items get a promotion target:

| Pattern | Promote to |
|---|---|
| Environment/toolchain gotcha (paths, sandbox limits, flaky suites, credentials) | the repo's agent instructions (CLAUDE.md / AGENTS.md) — landmines section |
| Plan-shape defect (missing evidence, stale file refs, unstated convention the executor had to discover) | the plan template / writing-plans habits for that repo |
| Reusable judgment pattern (a move that worked and will again) | a skill — extend an existing one before creating a new one |
| Product bug found but deferred mid-run | the project's backlog/issue tracker |

## Apply

1. Present the promotion list — each item with its target file — for approval. Group by target; lead with the highest-recurrence items.
2. Apply approved promotions. Edit pages in place; never append contradictions.
3. Delete the consumed notes (and say which were consumed). The archive of record is the promoted page, not the log.
4. Report: promotions applied, one-offs dropped, silent-deviation runs flagged, anything needing a human call.

## Remember

- Recurrence is the signal — resist promoting every clever one-off
- Fix the map at the highest-leverage layer: instructions beat templates beat skills only when the lesson is truly general
- Notes are an inbox: mined, promoted, deleted
- If the same deviation survives two retros, the promotion isn't working — escalate to the human
