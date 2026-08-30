---
name: skill-doctor
description: >-
  Grade installed agent skills by scoring real local coding-agent sessions
  (normalized with a bundled Letta trajectory pipeline) against efficiency and
  code-quality rubrics, then draft concrete skill edits and one report page.
  Use when the user asks to grade their agent setup, audit which skills are
  actually working, or run skill-doctor.
metadata:
  user-invocable-only: "true"
---

# skill-doctor

Grade the user's agent setup by scoring recent local agent sessions, then
propose concrete skill edits and render one report page.

Sessions come from a local Letta trajectory pipeline bundled with this skill
(`$SKILL_ROOT/scripts/trajectories/`), not from raw harness files. Every
source the `@letta-ai/trajectory` package can list (claude-code, codex, pi,
droid, letta-code, openclaw, omp, hermes, …) plus locally discovered cursor
and opencode sessions is normalized into one transcript shape, so this skill
runs from any harness. Read `$SKILL_ROOT/references/trajectory-sources.md`
for the pipeline layout.

Everything runs locally. Never upload transcripts, normalized session files, or
any excerpt of them. The only artifact meant to leave the machine is the report
the user chooses to share.

Let `SKILL_ROOT` be the directory containing this SKILL.md.

Every run is self-contained: it builds its own trajectory data root under a
fresh scratch directory and never reads or writes any other trajectory
directory the user may have. Re-running produces the same layout from
scratch.

## Step 0: Start the run

### Create the run directory

Never write artifacts into the user's repo. Create one fresh scratch directory
per run and use it as `REPORT_DIR` for every artifact, including the
trajectory data root:

```bash
REPORT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/skill-doctor-XXXXXXXX")"
TRAJ="$REPORT_DIR/trajectories"
```

### Ask which conversations to grade

Check whether the current directory is inside a git repository:

```bash
git rev-parse --show-toplevel
```

Use the harness's user-question tool when available.

When a current repository is available, ask **"Which conversations should I
grade?"** with:

1. **Conversations in this repository** — recommended. Includes its worktrees.
2. **All conversations**.
3. **Choose projects to analyze**.

When there is no current repository, offer only options 2 and 3, recommending
**All conversations**.

If the user chooses projects, ask for one or more project paths and validate
each as a git repository. The run produces one combined report.

### Ask which skills to evaluate

Then ask **"Which skills should I evaluate?"** with:

1. **Project skills + global skills** — recommended.
2. **Project skills only**.

For an all-conversations run, "project skills" means skills from local git
repositories inferred from the sessions' working directories. After these
answers, proceed immediately.

### Build the trajectory index

Normalize local sessions into the run's own data root, limited to the scoring
window (default 45 days):

```bash
"$SKILL_ROOT/scripts/ingest.sh" --root "$TRAJ" --days 45
```

This installs `@letta-ai/trajectory` (pinned, with a bundled pnpm patch that
adds the `grok-build` adapter) into `$TRAJ` and normalizes every discoverable
session updated inside the window. Requires Node 22+ and pnpm. Pass the same
`--days` you will pass to the collector. `--source NAME` (repeatable) narrows
to specific agents.

If ingest fails or `$TRAJ/state/history.jsonl` does not exist afterwards,
stop and show the user the error.

## Step 1: Collect

Build the collector arguments from the startup answers:

- Current repository: `--repo "$REPO"`.
- Selected projects: repeat `--repo PATH` for every project.
- All conversations: `--all-conversations`.
- Project and global skills: add `--include-global-skills`.
- Project skills only: do not add `--include-global-skills`.

```bash
python3 "$SKILL_ROOT/scripts/collect_sessions.py" \
  --trajectories-root "$TRAJ" \
  --out "$REPORT_DIR" \
  <conversation-scope arguments> \
  <skill-scope arguments>
```

Useful flags:

- `--trajectories-root PATH` — required; the root built by `ingest.sh` for this run.
- `--source NAME` — restrict to one normalized source; repeatable (default: all).
- `--repo PATH` — include a project; repeatable. Sessions in its git worktrees count.
- `--all-conversations` — do not filter sessions by project.
- `--include-global-skills` — also grade global skills.
- `--days N` — lookback window (default 45); match the value given to `ingest.sh`.
- `--max-sessions N` — cap on sampled sessions (default 12).
- `--per-skill N` / `--no-skill N` — sampling caps per skill and for skill-less sessions.
- `--skills-dir PATH` — nonstandard skill locations; repeatable.
- `--include-subagents` — include child/sidechain sessions and helper-prompt runs (reviewers, work orders).
- `--min-assistant-turns N` — skip trivially short sessions (default 3).

Read `$REPORT_DIR/inventory.json`. If `sessions_sampled` is 0, tell the user
there is nothing recent to score in the selected scope (suggest raising
`--days` for both ingest and collect, or choosing different projects) and stop.
If `skills_found` is 0, continue — the report becomes a case for creating
skills, and `skill_coverage` is 0.

## Step 2: Score each sampled transcript

Score every transcript in `$REPORT_DIR/transcripts/` against both rubrics:

- `$SKILL_ROOT/scorers/efficiency.md`
- `$SKILL_ROOT/scorers/code-quality.md`

Process up to 50 transcripts in one pass. Above that, split into batches of
about 20 and score them in local child agents only; transcript contents must
stay on the user's machine.

For each transcript and scorer record: label, numeric score (from the rubric's
label table), and a 1–3 sentence reason citing specifics from the transcript.
Apply the code-quality scorer only where the transcript shows code changes
(the transcript header says `code_edits: yes`); otherwise record
`insufficient_evidence` and exclude that result from the code-quality average
and the failed-conversation filter.

## Step 3: Aggregate

- `raw_efficiency` = mean of efficiency scores across all scored sessions.
- `raw_code_quality` = mean of code-quality scores, excluding `insufficient_evidence`. If no session had enough evidence, set it to 0.5 and say so in the findings.
- Curve rubric means into report scores with `curve(score) = 0.5 + 0.5 * score`.
- `efficiency = curve(raw_efficiency)`; `code_quality = curve(raw_code_quality)`.
- `skill_coverage` = fraction of sampled sessions where at least one installed skill was detected. If `skills_found` is 0, coverage is 0.
- `overall = 0.5 * efficiency + 0.35 * code_quality + 0.15 * skill_coverage`.

Define `failed_conversations` from each session's raw, uncurved scores: a
session fails when at least one applicable efficiency or code-quality score is
below `0.5`. `insufficient_evidence` never fails a session. Use only
`failed_conversations` as evidence for suggestions and drafted edits.

Then derive:

- `top_findings`: the 3 most impactful, specific patterns across sessions. Concrete and short.
- `suggestions`: concrete skill changes, if any. Each names a skill (existing or proposed-new) and one specific change: a trigger-description fix so it fires when it should, a missing step or check, a command to encode, a new skill to create. Every suggestion must trace to observed waste or defects in `failed_conversations` — cite the session id, source, scorer, and moment. An installed skill that never triggered in a failed session where it applied is usually a description problem and worth its own suggestion. Per-source patterns matter: a skill that works in claude-code but is never picked up in pi or codex points at a description or install gap for that harness.

## Step 4: Draft skill edits

Follow `$SKILL_ROOT/references/skill-improvements.md`. Propose edits only from
`failed_conversations`.

1. Read the skill's current file (path is in `inventory.json`). For skills managed by the dotfiles repo, the canonical source is `skills/<name>/SKILL.md` there, not the installed copy under `~/.claude/skills` or `~/.agents/skills`; draft against the source when it exists (`inventory.json` records `source_path` when found).
2. Write the full improved version to `$REPORT_DIR/proposed/<skill-name>/SKILL.md`, changing only what the evidence justifies.
3. Produce a unified diff (`diff -u <current> <proposed>`) and put it in the suggestion's `diff` field.

For a proposed-new skill, write the complete new SKILL.md under `proposed/`
and set `diff` to its full content as an addition.

Do not modify the user's real skill files in this step.

## Step 5: Write report.json and render

Write `$REPORT_DIR/report.json`. Store the curved `efficiency` and
`code_quality`, literal `skill_coverage`, and weighted `overall` in `scores`.

```json
{
  "title": "Agent Skill Report",
  "generated_at": "<ISO timestamp>",
  "sources": ["claude-code", "pi"],
  "handle": "<repo_name from inventory.json>",
  "stats": {
    "sessions_analyzed": 0, "sessions_scanned": 0,
    "skills_found": 0, "skills_used": 0, "window_days": 45
  },
  "scores": {"efficiency": 0.0, "code_quality": 0.0, "skill_coverage": 0.0, "overall": 0.0},
  "top_findings": ["", "", ""],
  "sessions": [
    {"id": "", "source": "", "efficiency": 0.0, "code_quality": 0.0, "skills": [], "note": ""}
  ],
  "suggestions": [
    {
      "skill": "",
      "change": "<one-sentence summary of the edit>",
      "evidence": "<which session(s) and what happened that motivates this>",
      "proposed_path": "<path under proposed/, if an edit was drafted>",
      "diff": "<unified diff, or full content for a new skill>"
    }
  ]
}
```

```bash
python3 "$SKILL_ROOT/scripts/render_report.py" "$REPORT_DIR/report.json" --open
```

This writes a self-contained `$REPORT_DIR/report.html` and tries to open it.

## Step 6: Output

Tell the user the grade and the three findings in text, then list each
suggestion with its skill and the drafted diff path.

Finish with:

- Your agent skill report: file://$REPORT_DIR/report.html
- Transcripts scored: `$REPORT_DIR/transcripts/`

Then ask whether to apply the proposed edits. When applying, edit the dotfiles
source skill (then `make install`) rather than the installed copy.
