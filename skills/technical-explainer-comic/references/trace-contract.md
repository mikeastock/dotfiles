# Technical trace contract

Use this contract to turn implementation evidence into two distinct traces:

- **Establishment:** how the system creates context that later work depends on.
- **Normal operation:** how one request, job, event, command, or batch uses that context.

Some systems have no separate establishment path. State that plainly and begin with normal
operation instead of inventing setup steps.

## Source hierarchy

Prefer sources in this order:

1. current application code and configuration
2. installed dependency code used at runtime
3. focused tests that prove behavior
4. current authoritative platform documentation
5. repository documentation
6. older notes or memory, labeled as potentially stale

Do not use a public health check or successful entry response as proof that protected,
asynchronous, or downstream behavior works.

## Boundary inventory

Name each actor and what it owns:

- caller, producer, client, or scheduler
- browser or user agent, when present
- gateway, worker process, function, daemon, or consumer being explained
- identity or authorization service, when present
- queue, scheduler, or event transport, when present
- backing store
- trusted execution host
- sandbox or other restricted runtime, when present
- downstream system of record

For every credential or sensitive value, state where plaintext exists, where only a hash or
encrypted form exists, and which process can recover or use it.

## Establishment trace

When later work depends on earlier setup, answer in order:

1. How does the caller, producer, or job discover the entry point or capability?
2. How is it identified or correlated?
3. What starts establishment?
4. Which inputs are validated before the first handoff?
5. Which temporary state is written, under what key or ID, and for how long?
6. What crosses each process or trust boundary?
7. What callback, delivery, exchange, or lookup follows?
8. Which durable context or record is created?
9. What does the caller, producer, or scheduler receive or retain?
10. What makes the establishment complete, one-time, renewable, or invalid?

Use protocol-specific terms only when the implementation does. For nested authorization
protocols, trace each handshake separately and identify which verifier, code, token, and state
belong to which boundary.

## Normal-operation trace

Answer in order:

1. Exact entry point: method and path, function, queue and message, event, command, or schedule
2. Input shape and how the caller or work item proves it is valid
3. Correlation, routing, partition, idempotency, or lookup-key derivation
4. Persistent and in-memory state reads
5. expiry, ownership, scope, version, duplication, and other validity checks
6. decryption, deserialization, or request-context construction
7. handler, tool, operation, or work selection
8. restricted or privileged execution boundary, when one exists
9. downstream calls, writes, emitted events, or other side effects
10. response or acknowledgement, limits, cleanup, and disposal

State which operations avoid the expensive path. Health checks, capability listing, rejected
inputs, cache hits, or duplicate deliveries may skip sandbox creation, downstream calls, or
persistent writes.

## Lifecycle trace

Include the applicable mechanics:

- credential, lease, cache, or record lifetime
- renewal, rotation, or lease extension
- retry and idempotency behavior
- request-local changes that do not persist
- durable changes that later work observes
- cancellation, revocation, expiry, or dead-letter behavior
- cleanup after success
- behavior after upstream invalidation or downstream failure

## State map

For each state family record:

- key, identity, partition, or record shape
- creation event
- stored fields at a conceptual level
- plaintext, hashed, encrypted, or otherwise protected status
- TTL, retention rule, acknowledgement, or deletion event
- read and write frequency on the normal path

Call a store a cache only when eviction can hurt performance without breaking correctness. If
losing a record breaks protocol or workflow state, it is backing state even when its product or
binding is branded as a cache.

## Scaling statement

Distinguish:

- configured or registered entities
- idle connections, sessions, subscriptions, or queued items
- arrival rate or requests per second
- concurrent expensive operations
- downstream calls or fan-out per operation

Describe the scaling shape supported by code and configuration. A throughput number requires
load evidence. List missing controls such as admission limits, queues, rate limits, bounded
concurrency, or backpressure instead of assuming the platform supplies them.

## Writing rules

- Make the visible title a claim, not a topic label.
- Put the simple causal explanation in the visible panel.
- Put exact mechanics in the expandable trace, in the same order.
- Define a domain term once, then use it precisely.
- Prefer an explicit entry point, identifier, lifetime, or state transition over “the system
  remembers it.”
- Keep caveats beside the claim they constrain.
