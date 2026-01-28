---
name: brave-search
description: Web search and content extraction via Brave Search API. Use for searching documentation, facts, or any web content. Lightweight, no browser required.
---

# Brave Search

Headless web search and content extraction using Brave Search API. No browser or setup required.

## Requirements

- [uv](https://docs.astral.sh/uv/) (dependencies managed automatically via inline metadata)
- `BRAVE_API_KEY` environment variable

## Search

```bash
{baseDir}/search.py "query"                    # Basic search (5 results)
{baseDir}/search.py "query" -n 10              # More results
{baseDir}/search.py "query" --content          # Include page content as markdown
{baseDir}/search.py "query" -n 3 --content     # Combined
```

## Extract Page Content

```bash
{baseDir}/content.py https://example.com/article
```

Fetches a URL and extracts readable content as markdown.

## Output Format

```
--- Result 1 ---
Title: Page Title
Link: https://example.com/page
Snippet: Description from search results
Content: (if --content flag used)
  Markdown content extracted from the page...

--- Result 2 ---
...
```

## Special URL Handling (CRITICAL)

**DO NOT use Brave Search for these URLs. Use the correct tool instead:**

- **GitHub URLs**: **ALWAYS** use the `gh` CLI instead (e.g., `gh api`, `gh repo view`, `gh issue view`, etc.)
- **`.md` file URLs**: **ALWAYS** use `curl` to fetch the raw file content directly (e.g., `curl -sL https://example.com/docs/guide.md`)

## When to Use

- Searching for documentation or API references
- Looking up facts or current information
- Fetching content from specific URLs (except GitHub URLs or `.md` files — see above)
- Any task requiring web search without interactive browsing
