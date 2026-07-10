---
name: effect-ts
description: Effect v4 TypeScript implementation and source research. Use when writing or refactoring Effect code, reviewing or debugging Effect behavior, or answering version-sensitive Effect API questions.
metadata:
  agents: amp, claude, codex, pi
---

# Effect TypeScript

Treat the target repository's architecture as a local constraint; its resolved `effect` dependency defines the available API and behavior. Do not transplant architecture or APIs from a reference project.

## Establish scope

1. Identify whether the task is writing/refactoring, review/debugging, or source research.
2. For repository work, read its instructions and resolve the `effect` version used by each affected workspace package. If dependencies are unavailable, use manifest and lockfile evidence and state that limitation.
3. For upstream-only research, establish the exact tag, commit, or branch being analyzed.
4. Inspect nearby conventions and the code, runtime path, or focused tests relevant to the claim or seam being changed.

Do not make an unqualified version-sensitive claim or code change until the applicable version or ref is known.

## Resolve API and behavior questions

1. Use the target version's public exports and types to establish reachability and compile-time contract. Internal source alone does not make an API public.
2. Inspect matching runtime source when implementation semantics matter, and matching tests when expected cases matter. Treat tests as behavioral evidence, not automatically as public contract.
3. If exports, types, source, documentation, or observed behavior disagree, report the discrepancy instead of hiding it behind a precedence rule.
4. Use [Effect v4's generated guidance](https://github.com/Effect-TS/effect-smol/blob/main/LLMS.md) as navigation into the [Effect source](https://github.com/Effect-TS/effect-smol). Confirm the ref of `/data/workspace/code/oss/effect-smol` before using it; when it does not match the target, use a matching tag or commit and verify every relevant claim there.
5. When static inspection is ambiguous, run a minimal typecheck or runtime probe against the target dependency version.
6. Use the shared `oss` checkouts: [opencode v2](https://github.com/anomalyco/opencode/tree/v2) at `/data/workspace/code/oss/opencode` and [executor](https://github.com/UsefulSoftwareCo/executor) at `/data/workspace/code/oss/executor`. Consult them regularly for implementation patterns and concrete design comparisons. Verify each checkout's ref and Effect version, re-check borrowed patterns against the target, and never treat them as API authority.

Do not import remembered Effect v3 APIs into v4 work without verifying them against the target version.

## Complete by task mode

- **Writing/refactoring:** Match local architecture unless the task explicitly changes it. Verify changed or uncertain Effect APIs, then report the exact focused checks and results.
- **Review/debugging:** Trace the concrete call path or failure before concluding. Diagnose without editing unless a fix was requested; verify APIs central to the finding and state remaining uncertainty.
- **Source research:** State the exact package version or ref, cite the public definition and runtime evidence when applicable, and distinguish verified behavior, inference, and unavailable evidence.

Finish only when the applicable mode's required evidence and limitations are explicit.
