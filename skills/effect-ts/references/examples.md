# Worked examples

Use these house-style examples when the task reaches their branch. They are distilled from production Effect v4 codebases — [opencode](https://github.com/anomalyco/opencode), [executor](https://github.com/UsefulSoftwareCo/executor), and [effect-smol](https://github.com/Effect-TS/effect-smol). Every source link is a pinned permalink. Where an example combines or simplifies sources, its framing says so explicitly.

## Contents

- [Module anatomy](#module-anatomy)
- [Public methods](#public-methods-effectfn-with-dotted-span-names)
- [Control flow](#control-flow-inside-generators)
- [Errors](#errors)
- [SDK adapters](#adapt-the-sdk-once)
- [Promise boundaries](#the-promise-boundary)
- [Absence](#absence-a--undefined-two-states)
- [Small hygiene](#small-hygiene)

| Agent default | House style |
| --- | --- |
| Inline `Effect.tryPromise` at every call site | Adapt the SDK once — a helper per edge, call sites are one-liners |
| `Effect.fail(new SomeError({...}))` | `return yield* new SomeError({...})` — tagged errors are yieldable |
| `instanceof` checks on caught errors | `Effect.catchTag("Domain.Error", ...)` |
| `Option<A>` or `null`/`undefined` tri-state at interfaces | Two-state `A \| undefined` |
| Annotated return types on service methods | Infer from the Interface; don't annotate |
| Flat method names (`getProviderModel`) | Nested API groups (`provider.get`, `model.get`) |
| Anonymous `Effect.gen` service methods | `Effect.fn("Domain.group.method")` — span names mirror the Interface |
| `Effect.runPromise` sprinkled through domain code | One `ManagedRuntime` boundary at the edge |
| One giant `Effect.gen` body | Gen bodies ~10 lines; split into named helpers |
| `pipe(...)` chains for sequencing effects | `Effect.gen` with guard clauses; `pipe` only for pure data transforms |
| Anonymous options bags | Options objects with `readonly` fields and explicit `\| undefined` |

## Module anatomy

One domain per file, in a fixed order: self-export, types, errors, `Interface`, tag, private layer, exported layers. A reader gets the whole public API from the `Interface` block without scrolling into the implementation. Skeleton condensed from opencode's [`catalog.ts`](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/catalog.ts#L1-L76) (301 lines, the model single-domain module) — the errors block is grafted in from [`git.ts`](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/git.ts#L26-L42) to show the full order (catalog.ts itself defines no errors), and the layer exports are simplified:

```ts
export * as Catalog from "./catalog"   // consumers write Catalog.Service, Catalog.OperationError

import { Array, Context, Effect, Layer, pipe, Schema } from "effect"

// -- types ------------------------------------------------------------------
export type DefaultModel = { providerID: ProviderID; modelID: ModelID }

// -- errors -----------------------------------------------------------------
export class OperationError extends Schema.TaggedErrorClass<OperationError>()("Catalog.OperationError", {
  message: Schema.String,
  cause: Schema.optional(Schema.Defect()),
}) {}

// -- interface --------------------------------------------------------------
export interface Interface {
  readonly provider: {
    readonly get: (providerID: ProviderID) => Effect.Effect<ProviderInfo | undefined>
    readonly all: () => Effect.Effect<ProviderInfo[]>
    readonly available: () => Effect.Effect<ProviderInfo[]>
  }
  readonly model: {
    readonly get: (providerID: ProviderID, modelID: ModelID) => Effect.Effect<ModelInfo | undefined>
    readonly default: () => Effect.Effect<ModelInfo | undefined>
  }
}

export class Service extends Context.Service<Service, Interface>()("app/Catalog") {}

// -- implementation ---------------------------------------------------------
const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    // deps first, private helpers next, then the returned API object
    return Service.of(result)
  }),
)

// -- layers -----------------------------------------------------------------
export const live = layer.pipe(Layer.provideMerge(Integration.live))
```

Notes on the shape:

- The `export * as Catalog from "./catalog"` self-export on line 1 gives every consumer the namespaced form for free — `Catalog.Service`, `Catalog.OperationError` — without a barrel file. (This is an ES module re-export, not a TypeScript `namespace`.)
- `Context.Service` is v4's service-definition form of the `Context.Tag` pattern: one class that is both the tag and the service type.
- Group the API in nested objects (`provider.*`, `model.*`), not flat names. The Interface then reads like a table of contents.
- Return types on methods are declared once, in the `Interface`. Implementations never re-annotate them.
- Start files that carry invariants with a banner comment stating purpose and the invariants — not what the code does line by line. Real example (executor's [`blob-store.ts:1-16`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/hosts/cloudflare/src/blob-store.ts#L1-L16)):

```ts
// ---------------------------------------------------------------------------
// BlobStore over a Cloudflare R2 bucket — the object-store backend for the
// SDK's blob seam on the Cloudflare hosts.
//
// Object name: `${namespace}/${key}`. Unambiguous because a namespace is
// always `partition/pluginId` (exactly one slash), so the first two segments
// always recover the namespace and the rest is the key.
//
// Writes do NOT participate in FumaDB transactions — a rolled-back
// transaction leaves the blob behind. Callers should use idempotent
// (content-derived) keys so orphaned writes are harmless.
// ---------------------------------------------------------------------------
```

## Public methods: `Effect.fn` with dotted span names

Every public service method is an `Effect.fn("Domain.group.method")` generator. The span name is the dotted API path — traces then read like the Interface. Parameter types are inferred from the Interface; return types are never annotated. From opencode's [`catalog.ts:176-189`](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/catalog.ts#L176-L189):

```ts
provider: {
  get: Effect.fn("Catalog.provider.get")(function* (providerID) {
    return state.get().providers.get(providerID)?.provider
  }),

  available: Effect.fn("Catalog.provider.available")(function* () {
    const active = new Map((yield* integrations.list()).map((i) => [i.id, i]))
    return (yield* result.provider.all()).filter((p) => available(p, active.get(p.integrationID)))
  }),
},
```

Named spans are for public entry points. Pure helpers are plain functions or arrows; an internal effectful helper takes `Effect.fn` with no span name. The reference repos routinely use `Effect.fnUntraced` for internal generators (effect-smol 350+ uses), but don't reach for it by default — unnamed `Effect.fn` keeps the trace tree intact, and `fnUntraced` wants a concrete reason such as a measured hot path.

## Control flow inside generators

Guard clauses and early returns carry the branching; `pipe(...)` appears only when the work is a pure data transform. The two halves stay visibly separate. How the house style writes opencode's [`model.small` (`catalog.ts:234-286`)](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/catalog.ts#L234-L286) — the guards-then-pipe split is verbatim from the source; the source keeps its picker inline in a ~50-line gen, which is exactly what the helper rule below fixes:

```ts
small: Effect.fn("Catalog.model.small")(function* (providerID) {
  const record = state.get().providers.get(providerID)
  if (!record) return                                       // guards: plain ifs, early return
  if (providerID === ProviderID.azure) return               // provider carve-out, another plain if

  const candidates = pipe(                                  // pure transform: pipe
    Array.fromIterable(record.models.values()),
    Array.filter((model) => model.enabled && model.status === "active"),
    Array.map((model) => ({ model, cost: totalCost(model), age: ageInMonths(model) })),
    Array.filter((item) => item.cost > 0 && item.age <= 18),
  )
  return pickCheapest(candidates, record.provider)          // named helper past ~10 lines
}),
```

Keep gen bodies to roughly ten lines. When one grows past that, split the pure parts into named helpers (`projectModel`, `pickCheapest`) hoisted above the API object — the generator stays a readable script.

## Errors

Default to `Schema.TaggedErrorClass` with a domain-prefixed tag and an optional defect-typed cause. The prefix makes `catchTag` unambiguous across the app; the `cause` keeps the original throwable attached. From opencode's [`git.ts:26-42`](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/git.ts#L26-L42):

```ts
export class OperationError extends Schema.TaggedErrorClass<OperationError>()("Git.OperationError", {
  operation: Schema.Literals(["clone", "fetch", "checkout", "diff"]),
  message: Schema.String,
  directory: Schema.optional(AbsolutePath),
  cause: Schema.optional(Schema.Defect()),
}) {}
```

(`Data.TaggedError` is fine for purely internal errors that never cross a schema boundary; anything that crosses HTTP or serialization gets the Schema form — extra annotations like an HTTP status live on the class declaration, see executor's [`errors.ts:5-18`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/plugins/openapi/src/sdk/errors.ts#L5-L18) and the header comment explaining why.)

Inside a generator, raise failures by yielding the error — tagged errors are Effects, so `Effect.fail` is ceremony there. (`Effect.fail` still belongs in non-generator positions — combinator callbacks, `Effect.callback` resume — where there is nothing to yield.) Pattern from executor's [`invoke.ts:87-93`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/plugins/openapi/src/sdk/invoke.ts#L87-L93), error name and fields simplified:

```ts
if (value === undefined && param.required) {
  return yield* new InvocationError({ message: `Missing required path parameter: ${param.name}` })
}
```

Handle by tag, never by `instanceof` — recover, or remap into your own error. From opencode's [`ripgrep.ts:185`](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/ripgrep.ts#L185):

```ts
Effect.catchTag("Ripgrep.InvalidPatternError", (cause) => Effect.fail(failure(cause.message, cause)))
```

Three more rules from the wild:

- Errors live in their own file per domain (`errors.ts` next to the module) once there's more than one.
- A wrapper module gets ONE flat error type carrying `method`, `message`, optional `key`, optional `cause` — not an error class per operation. This is also the `Data.TaggedError` exception in action: a library wrapper whose error never crosses serialization takes the plain form and a bare tag; app-level errors keep the Schema form and dotted prefix. From effect-smol's [`KeyValueStore.ts:183-195`](https://github.com/Effect-TS/effect-smol/blob/f11ce73af60823754dc24194f4ffc561b9ea1c2d/packages/effect/src/unstable/persistence/KeyValueStore.ts#L183-L195):

```ts
export class KeyValueStoreError extends Data.TaggedError("KeyValueStoreError")<{
  message: string
  method: string
  key?: string
  cause?: unknown
}> {}
```

- Re-wrap already-typed effects with `Effect.mapError`, not try/catch or a second tryPromise ([`KeyValueStore.ts:390-400`](https://github.com/Effect-TS/effect-smol/blob/f11ce73af60823754dc24194f4ffc561b9ea1c2d/packages/effect/src/unstable/persistence/KeyValueStore.ts#L390-L400)):

```ts
set: (key: string, value: string) =>
  Effect.mapError(
    fs.writeFileString(keyPath(key), value),
    (cause) => new KeyValueStoreError({ method: "set", key, message: `Unable to set item with key ${key}`, cause }),
  ),
```

## Adapt the SDK once

The single biggest ceremony killer. Never write `Effect.tryPromise({ try: ..., catch: (cause) => new SomeError({...}) })` at every call site — define the adapter once per edge, and every call site collapses to a one-liner.

A curried error mapper makes each `catch:` one call. This module IS the edge — the one place this SDK's `tryPromise` appears; everything above it calls `blobStore.get(...)` and never sees a Promise. From executor's [`blob-store.ts:25-70`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/hosts/cloudflare/src/blob-store.ts#L25-L70):

```ts
const storeError = (op: string) => (cause: unknown) =>
  new StorageError({ message: `R2 blob ${op} failed`, cause });

export const makeR2BlobStore = (bucket: R2Bucket): BlobStore => ({
  get: (namespace, key) =>
    Effect.tryPromise({
      try: async () => {
        const object = await bucket.get(objectName(namespace, key));
        return object == null ? null : await object.text();
      },
      catch: storeError("get"),
    }),
  delete: (namespace, key) =>
    Effect.tryPromise({
      try: () => bucket.delete(objectName(namespace, key)),
      catch: storeError("delete"),
    }),
});
```

(The `null` return in `get` is the source's `BlobStore` contract; a fresh interface would return `A | undefined` — see Absence below.)

One step further: a labeled tryPromise factory, so call sites don't even spell `tryPromise`. From executor's [`fuma-runtime.ts:81-88`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/core/sdk/src/fuma-runtime.ts#L81-L88):

```ts
export const fumaEffect = <A>(label: string, run: () => Promise<A>): Effect.Effect<A, StorageFailure> =>
  Effect.tryPromise({ try: run, catch: (cause) => fumaFailureFromCause(label, cause) });

// call sites then look like (illustrative):
const row = yield* fumaEffect("plans.find", () => db.plans.find(id))
```

The same move works for callback APIs — effect-smol hand-rolls an `idbRequest` helper once, and every IndexedDB operation becomes a one-liner ([`BrowserKeyValueStore.ts:153-172`](https://github.com/Effect-TS/effect-smol/blob/f11ce73af60823754dc24194f4ffc561b9ea1c2d/packages/platform-browser/src/BrowserKeyValueStore.ts#L153-L172), call site [`:104-111`](https://github.com/Effect-TS/effect-smol/blob/f11ce73af60823754dc24194f4ffc561b9ea1c2d/packages/platform-browser/src/BrowserKeyValueStore.ts#L104-L111)):

```ts
const idbRequest = <A>(
  failArgs: { method: string; message: string; key?: string },
  evaluate: () => IDBRequest<A>,
): Effect.Effect<A, KeyValueStoreError> =>
  Effect.callback((resume) => {
    const request = evaluate()
    request.onsuccess = () => resume(Effect.succeed(request.result))
    request.onerror = () => resume(Effect.fail(new KeyValueStoreError({ ...failArgs, cause: request.error })))
  })

// call sites (store acquisition elided):
set: (key, value) => idbRequest({ method: "set", message: "Failed to set value", key }, () => store.put({ key, value })),
```

Name a failure union once and give it a predicate, so signatures stay short and boundary code can narrow ([`fuma-runtime.ts:14`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/core/sdk/src/fuma-runtime.ts#L14), [`:69-70`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/core/sdk/src/fuma-runtime.ts#L69-L70)):

```ts
export type StorageFailure = StorageError | UniqueViolationError;

export const isStorageFailure = (error: unknown): error is StorageFailure =>
  Predicate.isTagged(error, "StorageError") || Predicate.isTagged(error, "UniqueViolationError");
```

## The Promise boundary

Domain logic never calls `Effect.runPromise`. There is one blessed edge — a `ManagedRuntime` built once — and everything Promise-shaped goes through it. From opencode's [`effect/runtime.ts:5-21`](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/effect/runtime.ts#L5-L21):

```ts
export function makeRuntime<I, S, E>(service: Context.Service<I, S>, layer: Layer.Layer<I, E>) {
  let rt: ManagedRuntime.ManagedRuntime<I, E> | undefined
  const getRuntime = () => (rt ??= ManagedRuntime.make(layer))

  return {
    runPromise: <A, Err>(fn: (svc: S) => Effect.Effect<A, Err, I>) => getRuntime().runPromise(service.use(fn)),
    runFork: <A, Err>(fn: (svc: S) => Effect.Effect<A, Err, I>) => getRuntime().runFork(service.use(fn)),
  }
}
```

When a Promise-based plugin/caller needs to invoke Effect code, write one adapter seam that captures the context and exposes Promise functions — the conversion happens there, nowhere else (opencode's [`plugin/promise.ts:20-44`](https://github.com/anomalyco/opencode/blob/3a95d56144dbac6286cb7d2e890235cc89c7a35d/packages/core/src/plugin/promise.ts#L20-L44)).

**v4 trap:** v3 folklore says `runPromise` rejects with a `FiberFailure` wrapper. In v4 the rejection is `Cause.squash` — the raw error itself ([`internal/effect.ts:5311-5316`](https://github.com/Effect-TS/effect-smol/blob/f11ce73af60823754dc24194f4ffc561b9ea1c2d/packages/effect/src/internal/effect.ts#L5311-L5316): `throw causeSquash(exit.cause)`). Code written from v3 instincts that unwraps rejections will double-unwrap. Verify v3 habits against the source before encoding them.

## Absence: `A | undefined`, two states

Interfaces return `A | undefined`, not `Option<A>` and not a `null`/`undefined` mix. Absorb expected not-found at the wrapper so callers never see it as an error. From effect-smol's [`KeyValueStore.ts:362-375`](https://github.com/Effect-TS/effect-smol/blob/f11ce73af60823754dc24194f4ffc561b9ea1c2d/packages/effect/src/unstable/persistence/KeyValueStore.ts#L362-L375):

```ts
get: (key: string) =>
  Effect.catchTag(fs.readFileString(keyPath(key)), "PlatformError", (cause) =>
    cause.reason._tag === "NotFound"
      ? Effect.undefined
      : Effect.fail(new KeyValueStoreError({ method: "get", key, message: `Unable to get item with key ${key}`, cause })),
  ),
```

Inside a generator the same rule makes lookups read like plain code: `if (!record) return` — the method's `Effect<A | undefined>` type comes from the Interface.

## Small hygiene

- Options objects: `readonly` fields, explicit `| undefined` over clever optionality — `{ readonly timeout: Duration | undefined }`.
- Below the service layer, data-access seams are plain factory functions returning a typed interface — `makeR2BlobStore(bucket): BlobStore` — no `Context.Tag` ceremony for something a constructor argument already injects.
- Pure helpers (key builders, name mappers) are hoisted above the factory/API object that uses them, not defined inline ([`blob-store.ts:23-28`](https://github.com/UsefulSoftwareCo/executor/blob/24bccd671205d7acbe78e46c507973b5d15a7808/packages/hosts/cloudflare/src/blob-store.ts#L23-L28)):

```ts
const objectName = (namespace: string, key: string): string => `${namespace}/${key}`;

export const makeR2BlobStore = (bucket: R2Bucket): BlobStore => ({ ... });
```
