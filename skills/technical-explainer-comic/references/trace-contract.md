# Technical trace contract

Use this contract to turn implementation evidence into a trace.

## Source hierarchy

Prefer sources in this order:

1. current application code and configuration
2. installed dependency code used at runtime
3. focused tests that prove behavior
4. current authoritative platform documentation
5. repository documentation
6. older notes or memory, labeled as potentially stale

Do not use a public endpoint returning 200 as proof that the authenticated flow behind it works.

## Boundary inventory

Name each actor and what it owns:

- caller or client
- browser or user agent
- gateway, Worker, or service being explained
- upstream identity or authorization server
- backing store
- trusted execution host
- sandbox, worker, queue consumer, or other restricted runtime
- downstream system of record

For every credential, state where plaintext exists, where only a hash exists, where encrypted
data exists, and which process can decrypt it.

## Authorization or setup trace

When present, answer in order:

1. How does the client discover endpoints or capabilities?
2. How does the client register or identify itself?
3. What begins authorization?
4. Which request fields are validated before redirect or handoff?
5. Which temporary state is written, under what key, for how long?
6. What is stored in the browser?
7. What returns in the callback?
8. Which upstream exchange occurs?
9. Which identity or scope lookup follows?
10. What durable grant or credential record is created?
11. What does the client receive?

Separate nested OAuth or PKCE handshakes. Never call two independent code verifiers one
handshake.

## Normal request trace

Answer in order:

1. Exact entry method and path
2. Credential presentation format
3. Lookup-key derivation
4. Persistent state read
5. expiry, audience, scope, and ownership checks
6. decryption or context construction
7. request handler or tool selection
8. restricted execution boundary
9. trusted downstream call
10. response limits, cleanup, and disposal

State which request types do not create expensive work. For example, initialization or tool
listing may avoid sandbox creation.

## Lifecycle trace

Include:

- access lifetime
- refresh or lease lifetime
- rotation semantics
- retry tolerance
- local retry paths that do not persist
- durable refresh paths that do persist
- revocation breadth
- cleanup after success
- behavior after upstream invalidation

## Persistence map

For each state family record:

- key shape
- creation event
- stored fields at a conceptual level
- plaintext, hashed, or encrypted status
- TTL or deletion event
- read and write frequency on the normal path

Call a store a cache only when eviction can lose performance without losing required protocol
state. OAuth grants, client registrations, and token lookup records are backing state, even when
the binding is named KV.

## Scaling statement

Distinguish:

- registered clients
- idle connections or sessions
- requests per second
- concurrent expensive operations
- downstream calls per request

Describe the scaling shape supported by the code. A throughput number requires load evidence.
List missing controls such as admission limits, queues, rate limits, or backpressure instead of
assuming the platform supplies them.

## Writing rules

- Put the simple claim in the visible panel.
- Put exact mechanics in the expandable trace.
- Define a domain term once, then use it precisely.
- Prefer an explicit key, TTL, or endpoint over “the system remembers it.”
- Keep caveats beside the claim they constrain.
