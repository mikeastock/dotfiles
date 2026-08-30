# Trajectory sources

skill-doctor reads sessions from a local Letta trajectory pipeline bundled
with the skill instead of each harness's native session store. This file is
the single source of truth for that contract.

## Pipeline layout

Scripts live in `scripts/` of the skill. Data lives under a root passed with
`--root`, created fresh for each run (`$REPORT_DIR/trajectories`); there is
no default or shared root, so runs are idempotent and never touch any other
trajectory directory on the machine.

```
scripts/ingest.sh                       install package, normalize, combine
scripts/trajectories/normalize.mjs      discover + normalize native session files
scripts/trajectories/combine.mjs        rebuild <root>/state/history.jsonl
scripts/trajectories/root.mjs           root resolution + package loading
scripts/trajectories/package.json       pinned @letta-ai/trajectory version
scripts/trajectories/pnpm-workspace.yaml  patchedDependencies mapping
scripts/trajectories/patches/*.patch    grok-build adapter patch

<root>/package.json, pnpm-workspace.yaml, patches/   copied from the skill by ingest.sh
<root>/node_modules/                    @letta-ai/trajectory, installed by pnpm
<root>/normalized/<source>/<id>.json    normalized session (provenance + records)
<root>/state/history.jsonl              one row per normalized session, newest first
<root>/state/last-run.json              last normalize manifest
```

`ingest.sh --root PATH --days N` normalizes only sessions updated inside the
window, which keeps a from-scratch build fast. `--source NAME` and
`--limit N` narrow further. Re-running against the same root skips sessions
whose output is already current.

## The grok-build patch

Upstream `@letta-ai/trajectory` has no Grok Build adapter. The skill ships a
`pnpm patch` (`patches/@letta-ai__trajectory@<version>.patch`) generated from
the `mikeastock/trajectory` fork's compiled `dist/adapters/grok-build/` plus
registry edits in `dist/index.js`, `dist/listing.js`, and `dist/types.d.ts`.
pnpm applies it on install, so `grok-build` lists and normalizes like any
upstream source.

To bump the package version: in a scratch dir, `pnpm add
@letta-ai/trajectory@<new>`, `pnpm patch @letta-ai/trajectory@<new>`, reapply
the same file additions and registry edits, `pnpm patch-commit`, then copy the
new `patches/*.patch`, `pnpm-workspace.yaml`, and the version in
`package.json` back into `scripts/trajectories/`. If upstream ships
`grok-build` natively, delete the patch and the `patchedDependencies` entry.

## history.jsonl row

Fields the collector uses:

| Field | Meaning |
| --- | --- |
| `source` | normalized source id (`claude-code`, `codex`, `pi`, `grok-build`, `cursor`, `opencode`, `droid`, …) |
| `id` | session id |
| `file` | absolute path to the normalized JSON |
| `sourcePath` | native session file (used only to detect subagent files) |
| `sourceUpdatedAt`, `lastTimestamp`, `firstTimestamp` | recency filtering |
| `cwd`, `gitBranch`, `model` | from the `meta` record |
| `roleCounts` | per-role record counts; sessions with too few assistant turns are skipped |

## Normalized records

`records` is the trajectory-v1 payload. Roles: `meta`, `user`, `assistant`,
`reasoning`, `tool`. Assistant records may carry `tool_calls: [{id, name, args}]`
with `args` as a JSON string. Tool records carry `tool_call_id`, `content`, and
optionally `ok`.

## Skill detection

Tool names differ per source, so detection is text-based across every record:

- `Skill` / `skill` tool calls (`{"skill": name}` or `{"name": name}`)
- any path matching `skills/<name>/SKILL.md` or `/skills/<name>/` in tool args or content (Read/read/read_file/cat of a skill file)
- injected skill blocks in user content: `<skill name="X"`, `Base directory for this skill: …/X`, `<skills_referenced>` entries
- a user turn starting with `/X` or `$X` when `X` is an installed skill name

Detected names are matched against installed skills; unmatched names are kept
under `skills_unknown` so a skill that fires under a different name or from an
unmanaged directory is still visible.

## Skill locations

Project skills: `.agents/skills`, `.claude/skills`, `.codex/skills`,
`.opencode/skills`, `.pi/skills` under each repo.

Global skills (with `--include-global-skills`): `~/.agents/skills`,
`~/.claude/skills`, `~/.codex/skills`, `~/.grok/skills`, `~/.pi/agent/skills`,
`~/.config/agents/skills`, `~/.config/opencode/skills`.

Skills with the same name in several locations are one skill; every path is
recorded. When a dotfiles repo (`skills/<name>/SKILL.md` under a directory
containing `plugins.toml`) is among the repos or the default dotfiles path
exists, that path is recorded as `source_path` so edits target the source.

## Coverage gaps

Amp and BB sessions have no Letta adapter yet and are not scored.
