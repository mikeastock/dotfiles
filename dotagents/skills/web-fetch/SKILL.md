---
name: web-fetch
description: Fetch and extract readable content from any webpage as markdown. Use when you have a specific URL and need its content. Lightweight, no browser required.
---

# Web Fetch

Fetch a URL and extract readable content as clean markdown. No browser or setup required.

## Requirements

- [uv](https://docs.astral.sh/uv/) (dependencies managed automatically via inline metadata)

## Usage

```bash
{baseDir}/content.py https://example.com/article
```

## Output

Prints the page title as an H1 heading followed by the extracted content as clean markdown.

## When to Use

- Fetching content from a specific URL
- Reading articles, documentation pages, or blog posts
- Extracting readable text from any webpage

## When NOT to Use

- **Searching the web** — use the `web-search` skill instead
- **GitHub URLs** — use the `gh` CLI instead (e.g., `gh api`, `gh repo view`, `gh issue view`)
- **`.md` file URLs** — use `curl` to fetch the raw file content directly
