# Explainer manifest

`scripts/render_explainer.py` reads one JSON object. Text supports two inline constructs:

- backticks render `<code>`
- double asterisks render `<strong>`

Raw HTML is escaped.

## Required top-level fields

```json
{
  "title": "Job runner, from enqueue to acknowledgement.",
  "eyebrow": "A six-panel technical comic",
  "summary": "One plain-language paragraph describing the component and its job.",
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

The renderer provides this generic color legend:

- orange — input or work movement
- blue — state or trusted processing
- red — constraint or failure

Override the labels when the panels use the colors differently:

```json
{
  "legend": [
    {"tone": "orange", "label": "message movement"},
    {"tone": "blue", "label": "queue and worker state"},
    {"tone": "red", "label": "retry or dead letter"}
  ]
}
```

`legend` is optional. When present, it must contain exactly one non-empty label for each tone:
`orange`, `blue`, and `red`.

## Panel object

Use three to nine panels. Number them in display order.

```json
{
  "number": "01",
  "nav": "Boundary",
  "title": "The queue separates intake from execution.",
  "summary": "Producers can submit work without waiting for a worker to finish it.",
  "callout": {
    "title": "Why the job persists",
    "body": "A worker can restart after delivery and recover the same job."
  },
  "image": "assets/job-runner-illustrations/01-boundary.png",
  "alt": "A character places one job into a durable queue between a producer and worker.",
  "caption": "Panel 01 · intake boundary",
  "caption_note": "Submit now, process later",
  "trace_title": "Technical trace",
  "trace_ordered": true,
  "trace": [
    "The producer sends `POST /jobs` with the work payload.",
    "The service validates the payload and writes `job:<id>`.",
    "The queue publishes the new job ID for a worker to claim."
  ],
  "trace_note": "The exact queue and retention policy come from the inspected implementation."
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
        "key": "job:<queue>:<id>",
        "created": "On enqueue",
        "contains": "Validated work payload, attempt count, and status",
        "lifetime": "Until acknowledgement plus seven days"
      }
    ],
    "cards": [
      {
        "tone": "blue",
        "title": "Why another worker can continue",
        "body": "Any eligible worker can claim the durable job after a process restart."
      },
      {
        "tone": "red",
        "title": "Important exception",
        "body": "Repeated failure sends the job to a dead-letter queue."
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
