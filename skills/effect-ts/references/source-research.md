# Source research

Use `/data/workspace/code/oss/effect-smol` as the only shared Effect source checkout.

## Source boundary

- If the path is absent, clone `https://github.com/Effect-TS/effect-smol` there.
- If it exists, use it as-is. Never fetch, pull, reset, replace, clean, or silently update it.
- Never add Effect source to the application repository as a subtree, submodule, ignored clone, gitignore entry, or prepare task.
- If the existing path lacks the file needed for research, report the exact path and stop. Do not repair user state implicitly.

## Research order

1. Read the repository's installed Effect package versions and nearby code.
2. Use the task-specific guide linked directly from `SKILL.md`.
3. Search the shared checkout for the exact export, type, implementation, and tests.
4. Prefer public exports and current tests over internal implementation details. Use internals only to verify behavior that the public surface does not settle.
5. Cite a pinned GitHub permalink when recording a durable source claim.

Useful roots:

- Core public API: `/data/workspace/code/oss/effect-smol/packages/effect/src`
- Core tests: `/data/workspace/code/oss/effect-smol/packages/effect/test`
- Platform packages: `/data/workspace/code/oss/effect-smol/packages/platform-*`
- Vitest integration: `/data/workspace/code/oss/effect-smol/packages/vitest`
- OpenTelemetry integration: `/data/workspace/code/oss/effect-smol/packages/opentelemetry`

## Conflict rule

Treat repository architecture as the local design authority and the project's installed Effect package types or source as its API authority. Use the shared checkout as source truth only when its version matches the installed package; otherwise use it for discovery and confirm every selected API against the installed version. If a guide conflicts with the applicable source, source wins. If source-correct code conflicts with established repository structure, make the smallest coherent design change and explain it; do not add a compatibility path.
