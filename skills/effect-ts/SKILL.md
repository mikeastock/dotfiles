---
name: effect-ts
description: Write, review, refactor, debug, or research TypeScript in repositories that use Effect. Apply this skill to Effect v4 code, including new files, services and layers, Schema, typed errors, observability, testing, runtime boundaries, and source-level API questions.
metadata:
  agents: amp, claude, codex, pi
---

# Effect TypeScript

Use the current repository for local architecture, its installed Effect package for compatible API truth, Effect's generated documentation for guidance, and the reference repositories for source-backed patterns.

## Reference sources

- [Effect v4 source](https://github.com/Effect-TS/effect-smol) at `/data/workspace/code/oss/effect-smol`
- [opencode v2](https://github.com/anomalyco/opencode/tree/v2) at `/data/workspace/code/oss/opencode`
- [executor](https://github.com/UsefulSoftwareCo/executor) at `/data/workspace/code/oss/executor`

## Research in this order

1. Inspect repository instructions, Effect imports, package versions, service and layer shapes, errors, and tests.
2. Read `/data/workspace/code/oss/effect-smol/LLMS.md` for Effect's generated guidance. Follow its direct links into `ai-docs/src` and `packages` instead of maintaining a parallel manual in this skill. Interpret its relative paths and repository-local source rules inside the Effect checkout; an application's installed package still decides compatibility.
3. Verify every version-sensitive API against the project's installed Effect package types or source. Use the shared Effect checkout as API truth only when its version matches the project.
4. Search the Effect checkout's public exports and tests for behavior the documentation does not settle.
5. Use opencode and executor only as implementation-pattern references, not as Effect API authorities.

Resolve conflicts in that order. Prefer source-correct code over stale local precedent, explain deliberate deviations, and never add a compatibility path for an obsolete Effect API.

## Apply house style when it matters

Read [examples.md](references/examples.md) when writing or reviewing module anatomy, public APIs, control flow, typed errors, Promise adapters, runtime boundaries, or absence handling. It contains Mike's conventions and pinned examples from all three reference repositories; the installed Effect version still decides whether an API is valid.
