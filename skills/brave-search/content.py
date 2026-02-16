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
Extract readable content from a webpage as markdown.

Usage:
    content.py <url>

Examples:
    content.py https://example.com/article
    content.py https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html
"""

import re
import sys

import httpx
from markdownify import markdownify
from readability import Document


def html_to_markdown(html: str) -> str:
    """Convert HTML to clean markdown."""
    md = markdownify(html, heading_style="ATX", code_language="")
    # Clean up excessive whitespace
    md = re.sub(r"\n{3,}", "\n\n", md)
    md = re.sub(r" +", " ", md)
    md = re.sub(r"\s+,", ",", md)
    md = re.sub(r"\s+\.", ".", md)
    return md.strip()


def main():
    if len(sys.argv) < 2:
        print("Usage: content.py <url>")
        print()
        print("Extracts readable content from a webpage as markdown.")
        print()
        print("Examples:")
        print("  content.py https://example.com/article")
        print("  content.py https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html")
        sys.exit(1)

    url = sys.argv[1]

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        response = httpx.get(url, headers=headers, timeout=15.0, follow_redirects=True)
        response.raise_for_status()

        doc = Document(response.text)
        title = doc.title()
        html_content = doc.summary()

        if title:
            print(f"# {title}\n")

        markdown = html_to_markdown(html_content)

        if len(markdown) > 100:
            print(markdown)
        else:
            print("Could not extract readable content from this page.", file=sys.stderr)
            sys.exit(1)

    except httpx.HTTPStatusError as e:
        print(f"HTTP {e.response.status_code}: {e.response.reason_phrase}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
