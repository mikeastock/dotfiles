---
name: web-search
description: Web search via Brave Search API. Use for searching documentation, facts, or any web content. Lightweight, no browser required.
---

# Web Search

Search the web using Brave Search API. No browser or setup required.

## Requirements

- [uv](https://docs.astral.sh/uv/) (dependencies managed automatically via inline metadata)
- `BRAVE_API_KEY` environment variable

## Usage

```bash
{baseDir}/search.py "query"                    # Basic search (5 results)
{baseDir}/search.py "query" -n 10              # More results
```

## Output Format

```
--- Result 1 ---
Title: Page Title
Link: https://example.com/page
Snippet: Description from search results

--- Result 2 ---
...
```

## When to Use

- Searching for documentation or API references
- Looking up facts or current information
- Any task requiring web search without interactive browsing

## When NOT to Use

- **Fetching content from a specific URL** — use the `web-fetch` skill instead
- **GitHub URLs** — use the `gh` CLI instead (e.g., `gh api`, `gh repo view`, `gh issue view`)
- **`.md` file URLs** — use `curl` to fetch the raw file content directly
