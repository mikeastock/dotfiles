---
name: humanlayer
description: Reference the HumanLayer source code (humanlayer/humanlayer monorepo) from a local clone. Use when you need to know how HumanLayer works or copy its patterns — its daemon, API, desktop/web app, CLI, Claude Code/OpenCode/Pi plugins, RPI skills, Electric sync, or docs — or when the user mentions HumanLayer, CodeLayer, or Riptide.
agents: [amp, claude, codex, pi]
---

# HumanLayer source reference

A local clone of https://github.com/humanlayer/humanlayer lives at:

```
/data/workspace/code/oss/humanlayer
```

It is read-only reference material. Do not edit it or commit to it.

## Before reading

Pull so you read current code:

```bash
git -C /data/workspace/code/oss/humanlayer pull --ff-only -q
```

If the directory is missing, clone it:

```bash
git clone https://github.com/humanlayer/humanlayer.git /data/workspace/code/oss/humanlayer
```

Search with `rg` and `fd` from the repo root, and cite paths relative to it.
Start from the repo's own `AGENTS.md` and `README.md` for conventions.

## Map

HumanLayer runs coding agents (Claude Code, Codex, OpenCode, Pi) on your
machines and lets a team steer them from one place. "Riptide" is the codename
for the current product. Turborepo + Bun, TypeScript throughout, Effect in
newer code.

| Path | What it is |
| --- | --- |
| `apps/riptide-daemon` | Daemon on each host that runs agent sessions; reacts to Postgres changes synced via Electric |
| `apps/riptide-api` | oRPC + Hono API (`src/orpc/api/...` per resource, `src/auth/`, `src/effects/services/`) |
| `contracts/riptide-api-contract` | oRPC contracts (API side and daemon side); OpenAPI generated from them |
| `contracts/riptide-electron-rpc` | Effect RPC contracts between Electron main and renderer |
| `apps/riptide-ui` | The app (TanStack Router + TanStack DB), web and inside desktop shells |
| `apps/riptide-electron`, `apps/riptide-native` | macOS desktop shells (Electron, Tauri) |
| `apps/riptide-electric-proxy` | Auth proxy in front of Electric SQL |
| `apps/riptide-cloud` | Admin web app (orgs, invites, settings) |
| `apps/cli` | `humanlayer` CLI: login (WorkOS device auth), daemon launch, `api` commands |
| `apps/riptide-claude-code-plugin`, `apps/riptide-opencode-plugin`, `apps/riptide-pi-extension` | Mirror agent sessions into HumanLayer |
| `apps/riptide-humanlayer-claude-plugin/skills` | Built-in skills: `orchestrate`, `teleport`, `show-me` |
| `apps/riptide-rpi-claude-plugin/skills` | Research-Plan-Implement skills (create/iterate research, plan, PRD, TDD, outline) |
| `apps/linear-cli` | Linear CLI |
| `apps/devstack` | Full local stack per worktree |
| `apps/docs` | User docs (guides, explanations, reference) — good for product behavior |
| `packages/db` | Drizzle Postgres schemas |
| `packages/sync`, `packages/streams`, `packages/y-durable-streams` | Electric/TanStack DB sync and durable streams |
| `packages/session-sdk-*` | Session SDK pieces (sessions, tools, diffs, artifacts, auth) |
| `packages/ai` | AI agents (summarizer, task generator, doc researcher) |
| `packages/ui` | shadcn/ui component library |
| `.claude/skills` | The HumanLayer team's own agent skills |
