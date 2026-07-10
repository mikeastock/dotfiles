---
name: effect-ts
description: Write, review, refactor, debug, or research TypeScript in repositories that use Effect. Apply this skill to Effect v4 code, including new files, services and layers, Schema, typed errors, observability, testing, runtime boundaries, and source-level API questions.
metadata:
  agents: amp, claude, codex, pi
---

# Effect TypeScript

Use the current repository for local architecture, this skill for house conventions, the project's installed Effect package for compatible API truth, and the shared checkout for source research.

## Start every Effect task

1. Ensure `/data/workspace/code/oss/effect-smol` exists before doing Effect-specific work:

   ```sh
   effect_source=/data/workspace/code/oss/effect-smol
   if [ ! -e "$effect_source" ]; then
     mkdir -p /data/workspace/code/oss
     git clone https://github.com/Effect-TS/effect-smol "$effect_source"
   elif [ ! -d "$effect_source" ]; then
     printf '%s\n' "Effect source path exists but is not a directory: $effect_source" >&2
     exit 1
   fi
   ```

   Treat an existing path as user state. Never fetch, pull, reset, replace, or otherwise update it unless the user explicitly asks. If its expected source files are absent, stop with the exact missing path and let the user repair it.

2. Inspect the repository's Effect imports, package versions, service/layer shapes, errors, tests, and local instructions. Follow local domain architecture unless it conflicts with the installed Effect API.

3. Read only the references that match the task. Verify project compatibility against its installed Effect package types or source first; use the shared checkout for broader source research and when it matches the installed version. The task is grounded when every changed Effect pattern agrees with the repository and every API claim agrees with the project's installed version.

## Resolve guidance in this order

1. Obey repository instructions and preserve coherent local architecture.
2. Apply the conventions below and the relevant guide.
3. Verify uncertain or version-sensitive behavior against the project's installed Effect package, then use `/data/workspace/code/oss/effect-smol` for source navigation when the versions agree.

When local precedent is stale or incompatible with the current API, prefer source-correct code and explain the deliberate deviation. Do not preserve a second compatibility path.

## Core conventions

- Model application work as `Effect<A, E, R>` and keep `Effect.run*` at runtime boundaries.
- Use `Effect.fn("Domain.group.operation")` for public business or service operations. Use unnamed `Effect.fn` for internal effectful helpers. Use `Effect.fnUntraced` only for a concrete low-level or measured performance reason.
- Keep generators linear and short. Use guard clauses for control flow, extract named helpers when a generator stops reading like a script, and reserve `pipe` chains for focused transformations.
- Adapt Promise, callback, and throwing APIs once at their owning edge. Return Effect values above that adapter instead of repeating `tryPromise`, `callback`, or runtime calls.
- Prefer `Context.Service` for application services. Use another tag form only when the repository or an Effect API requires it. Build with layers, compose subsystem dependencies locally, and provide the completed graph at an application, subsystem, or test boundary.
- Prefer `Schema.TaggedErrorClass` for schema-friendly domain errors and anything crossing serialization. Use `Data.TaggedError` for intentionally local, in-memory errors with payloads that do not benefit from Schema.
- Inside generators, yield yieldable tagged errors directly. Use `Effect.fail` where there is no generator to yield from, including combinator and callback positions. Recover by tag and use `Effect.mapError` to translate an already-typed error channel.
- Preserve foreign failures in a typed `cause` field. Do not leak raw exceptions or use `any`, casts, assertions, or namespaces to escape the type system.
- For new simple lookup interfaces, prefer the two-state shape `A | undefined`. Keep `Option` when the repository already uses it coherently or its combinators express a real domain need.
- Prefer Effect-native integrations and `@effect/vitest` when the repository uses those packages. Keep all installed Effect packages version-aligned; confirm the current package/version shape rather than relying on remembered release status.

## References

- Read [examples.md](references/examples.md) when writing or reviewing module anatomy, public APIs, control flow, typed errors, Promise adapters, runtime boundaries, or absence handling. Its source links are pinned examples, not substitutes for checking the repository's installed API.
- Read [source-research.md](references/source-research.md) for feature discovery, source navigation, and version-sensitive verification against the shared checkout.
- Read [guide-effect.md](references/guide-effect.md) for core constructors, composition, resource ownership, and runtime boundaries.
- Read [guide-error-handling.md](references/guide-error-handling.md) for failures, defects, interrupts, foreign-error wrapping, and boundary normalization.
- Read [guide-layers.md](references/guide-layers.md) for services, layer construction, memoization, composition, and provisioning.
- Read [guide-observability.md](references/guide-observability.md) for `Effect.fn`, spans, logs, metrics, and OpenTelemetry layers.
- Read [guide-retries.md](references/guide-retries.md) for retry conditions, schedules, and `ExecutionPlan` provider fallback.
- Read [guide-schedule.md](references/guide-schedule.md) for retries, repeats, polling, backoff, jitter, and cron.
- Read [guide-schema.md](references/guide-schema.md) for named schemas, transformations, optionality, unions, recursion, and boundary decoding.
- Read [guide-sql.md](references/guide-sql.md) for Effect SQL, transactions, resolvers, models, and migrations.
- Read [guide-testing.md](references/guide-testing.md) for `@effect/vitest`, test services, layered setup, property tests, and scoped resources.
- Read [features.md](references/features.md) only when discovering whether Effect already provides a module or package for a capability.
