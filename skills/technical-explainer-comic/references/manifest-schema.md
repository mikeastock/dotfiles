# Explainer manifest

`scripts/render_explainer.py` reads one JSON object. Text supports two inline constructs:

- backticks render `<code>`
- double asterisks render `<strong>`

Raw HTML is escaped.

## Required top-level fields

```json
{
  "title": "System name, from setup to request.",
  "eyebrow": "A six-panel technical comic",
  "summary": "One plain-language paragraph.",
  "read_note": {
    "title": "Read the pictures first.",
    "body": "Open each technical trace for exact mechanics."
  },
  "panels": [],
  "footer": {
    "note": "Evidence and freshness note.",
    "sources": ["src/index.ts", "src/auth.ts"]
  }
}
```

The renderer provides the orange, blue, and red legend used by the editorial images.

## Panel object

Use three to nine panels. Number them in display order.

```json
{
  "number": "01",
  "nav": "Boundary",
  "title": "The service is a bridge.",
  "summary": "One short visible explanation.",
  "callout": {
    "title": "Why persistence exists",
    "body": "A later request may land in another process."
  },
  "image": "assets/system-illustrations/01-boundary.png",
  "alt": "Xiaohei operates a bridge between the client and system of record.",
  "caption": "Panel 01 · system boundary",
  "caption_note": "Bridge, not database",
  "trace_title": "Technical trace",
  "trace_ordered": false,
  "trace": [
    "The service routes `POST /api` to the authenticated handler.",
    "Persistent state lives under `grant:<id>`."
  ],
  "trace_note": "Optional caveat kept beside the trace."
}
```

Required panel fields:

- `number`
- `nav`
- `title`
- `summary`
- `callout.title`
- `callout.body`
- `image`
- `alt`
- `caption`
- `caption_note`
- `trace`: three to eight non-empty items

Optional fields:

- `trace_title`, default `Technical trace`
- `trace_ordered`, default `true`
- `trace_note`

Image paths must be relative, stay inside the artifact directory, and point to PNG files.

## Appendix

Use an appendix when persistence or alternate paths need a compact reference.

```json
{
  "appendix": {
    "title": "The state map",
    "intro": "Record families behind the story.",
    "records": [
      {
        "key": "grant:<user>:<id>",
        "created": "Authorization callback",
        "contains": "Encrypted credential props and hashed token IDs",
        "lifetime": "30 days"
      }
    ],
    "cards": [
      {
        "tone": "blue",
        "title": "Why this survives process changes",
        "body": "Any process can derive the same lookup and read shared state."
      },
      {
        "tone": "red",
        "title": "Important exception",
        "body": "This alternate path uses only in-memory caching."
      }
    ]
  }
}
```

`tone` is `blue`, `red`, or `orange`. The appendix itself is optional. When present, `title`,
`intro`, and at least one record or card are required.

## Output

The renderer writes only `<artifact-dir>/index.html`. Create and populate panel images before
rendering. Re-rendering an existing index requires `--force`.
