#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "httpx>=0.27.0",
# ]
# ///
"""
Brave Search - search the web for results.

Usage:
    search.py <query> [-n <num>]

Examples:
    search.py "javascript async await"
    search.py "rust programming" -n 10

Requires: BRAVE_API_KEY environment variable
"""

import argparse
import os
import sys

import httpx

BRAVE_API_URL = "https://api.search.brave.com/res/v1/web/search"


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
        """,
    )
    parser.add_argument("query", nargs="+", help="Search query")
    parser.add_argument("-n", type=int, default=5, help="Number of results (default: 5)")
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
            print()

    except httpx.HTTPStatusError as e:
        print(f"HTTP Error {e.response.status_code}: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
