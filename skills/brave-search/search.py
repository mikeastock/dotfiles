#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "httpx>=0.27.0",
#     "readability-lxml>=0.8.1",
#     "markdownify>=0.13.1",
#     "lxml[html_clean]>=5.0.0",
# ]
# ///
"""
Brave Search - search the web and optionally fetch page content as markdown.

Usage:
    search.py <query> [-n <num>] [--content]

Examples:
    search.py "javascript async await"
    search.py "rust programming" -n 10
    search.py "climate change" --content

Requires: BRAVE_API_KEY environment variable
"""

import argparse
import os
import re
import sys

import httpx
from markdownify import markdownify
from readability import Document

BRAVE_API_URL = "https://api.search.brave.com/res/v1/web/search"


def fetch_page_content(url: str, timeout: float = 10.0) -> str:
    """Fetch a URL and extract readable content as markdown."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        response = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
        response.raise_for_status()

        doc = Document(response.text)
        html_content = doc.summary()

        # Convert to markdown
        md = markdownify(html_content, heading_style="ATX", code_language="")
        # Clean up
        md = re.sub(r"\n{3,}", "\n\n", md)
        md = re.sub(r" +", " ", md)
        return md.strip()[:5000]
    except Exception as e:
        return f"(Error: {e})"


def search_brave(query: str, count: int, api_key: str) -> list[dict]:
    """Search Brave and return results."""
    headers = {
        "Accept": "application/json",
        "X-Subscription-Token": api_key,
    }
    params = {
        "q": query,
        "count": count,
    }

    response = httpx.get(BRAVE_API_URL, headers=headers, params=params, timeout=15.0)
    response.raise_for_status()

    data = response.json()
    results = []

    if "web" in data and "results" in data["web"]:
        for item in data["web"]["results"]:
            results.append(
                {
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "description": item.get("description", ""),
                }
            )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Search the web using Brave Search API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "javascript async await"
  %(prog)s "rust programming" -n 10
  %(prog)s "climate change" --content
        """,
    )
    parser.add_argument("query", nargs="+", help="Search query")
    parser.add_argument("-n", type=int, default=5, help="Number of results (default: 5)")
    parser.add_argument("--content", action="store_true", help="Fetch readable content as markdown")
    args = parser.parse_args()

    query = " ".join(args.query)
    api_key = os.environ.get("BRAVE_API_KEY")

    if not api_key:
        print("Error: BRAVE_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    try:
        results = search_brave(query, args.n, api_key)

        if not results:
            print("No results found.", file=sys.stderr)
            sys.exit(0)

        for i, result in enumerate(results, 1):
            print(f"--- Result {i} ---")
            print(f"Title: {result['title']}")
            print(f"Link: {result['url']}")
            print(f"Snippet: {result['description']}")

            if args.content:
                content = fetch_page_content(result["url"])
                print(f"Content:\n{content}")

            print()

    except httpx.HTTPStatusError as e:
        print(f"HTTP Error {e.response.status_code}: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
