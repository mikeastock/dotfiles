---
name: reflect
description: Spawn three parallel review subagents over the active transcript, surface learnings, and route each to a concrete edit on an existing skill. Use when the user says reflect.
agents: [pi]
metadata:
  user-invocable-only: "true"
---

# Reflect

> Pi: other pstack skills named here (for example **how** or `principle-prove-it-works`) are installed as siblings of this skill. Read `../<name>/SKILL.md`. A `/name` reference means that skill. Subagents run through the pstack `task` tool, and per-role models come from `~/.pi/agent/pstack-models.md` when it exists.

Mine the current conversation for durable learnings, then route them into skill edits.

## When to invoke

Invoke when the user says "reflect" or "/reflect". Skip when the conversation is trivial, off-topic, or already covered by an existing skill the parent followed correctly. One-offs are not learnings.

## Process

### 1. Locate the active transcript

The parent's own transcript is the current Pi session file. The `pstack_session` system prompt section names it. Do not glob across `~/.pi/agent/sessions/*/`. That crosses workspace boundaries and reads private chats from unrelated projects.

Pi transcripts are JSONL session files: a header line, then one entry per line, with conversation turns as `{"type":"message","message":{...}}` entries. Each `task` result names its subagent's own transcript on a `transcript:` line (under `~/.pi/agent/pstack/task-sessions/`). Pass those paths to reviewers when the subagents' work matters. If the session file is missing (an ephemeral `--no-session` run), write a tight digest of the session and pass that instead.

### 2. Spawn three reviewers in parallel

One `task` call with three entries, `agent: "general"`, `readonly: true`, with `model` set as below. Read-only keeps MCP access for context lookups (tickets, chat threads, observability traces referenced in the transcript).

Each reviewer and the synthesizer name a role line in the pstack model config (`~/.pi/agent/pstack-models.md`) and a default. Set `model` to that line's value, or to the default if the config or the line is missing. Leave `model` unset when the value is `auto` or `inherit-parent`. If a `task` entry fails because its model is unavailable, rerun it on the default and say so. If the default is unavailable too, use the closest model of the same family from `pi --list-models`.

| Lens | Role line | Default `model` | Prompt template |
|---|---|---|---|
| Judgment | `reflect judgment, divergent, synthesizer` | `anthropic/claude-opus-5-5:max` | `references/judgment-reviewer.md` |
| Tooling | `reflect tooling` | `openai/gpt-5.6-sol:max` | `references/tooling-reviewer.md` |
| Divergent | `reflect judgment, divergent, synthesizer` | `anthropic/claude-opus-5-5:max` | `references/divergent-reviewer.md` |

Pass each template verbatim, substituting the transcript path or digest where marked. Reviewers return findings in their final message, which the `task` tool returns.

### 3. Synthesize

One `task` call, `agent: "general"`, `readonly: true`, with `model` from the `reflect judgment, divergent, synthesizer` line (default `anthropic/claude-opus-5-5:max`). The synthesizer's quality check spot-verifies citations, which can need MCP access, and read-only keeps it. Use `references/synthesizer.md` verbatim, with each reviewer's full output inlined where marked. The synthesizer returns a structured Accepted / Rejected / Backlog list.

### 4. Structural enforcement check

Sanity-check the synthesizer's Accepted list. For any item that would be enforced more reliably by a lint rule, script, metadata flag, or runtime check, move it from Accepted to Backlog. See the **encode-lessons-in-structure** principle skill.

### 5. Apply

Before applying any Accepted edit, present the synthesizer's full Accepted/Rejected/Backlog output to the user and wait for explicit approval. The user picks which subset to apply and may redirect routings. Skill changes affect every future agent in the org. Do not auto-apply.

Backlog items file to whatever devex / backlog tracker your team uses automatically. Only the Accepted list waits for approval.

Skills installed under `~/.agents/skills/` are build output from the dotfiles repo (usually `/data/workspace/code/personal/dotfiles`). Edit the source at `skills/<name>/` there, never the installed copy, then run `make install-skills` in that repo.

For each approved Accepted item, follow the Routing field exactly:

- Trivial existing-skill edit (a one-line bullet, a tightened sentence, a stale fact corrected): parent does directly.
- Substantive existing-skill edit (a new section, a new pattern table, more than ~10 lines): hand to the **writing-great-skills** skill (`../writing-great-skills/SKILL.md`) and run its draft / test / iterate loop.
- `tune description: <skill path>` (the skill exists but didn't trigger when it should have): hand to **writing-great-skills** and tune the description against the prompts that should have triggered it.
- `new skill via writing-great-skills: <kebab-name>`: hand creation to **writing-great-skills**. Do not invent the shape ad hoc.

Run the dotfiles repo's `make build` on every touched skill before declaring done. It validates frontmatter.

### 6. Summarize for the user

Short list, no preamble:

- Edits applied: `<skill path>`. What changed, one line each.
- New skills created: `<skill path>`. One line each (rare).
- Backlog filed to the devex tracker: `<issue title>` (`<tags>`). One line each.
- Dropped: one line per rejected finding + reason from the synthesizer.
