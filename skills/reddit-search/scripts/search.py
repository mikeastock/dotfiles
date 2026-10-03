#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Search Reddit through Gemini's Google Search grounding using only stdlib."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


API = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-3.8-flash"
TIMEOUT = 300


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_prompt(question, subreddits):
    hints = (
        "Relevant subreddits: " + ", ".join(f"r/{name}" for name in subreddits) + ". "
        if subreddits
        else "Choose and name relevant subreddits for this question. "
    )
    return (
        "Use Google Search and look ONLY at reddit.com threads. "
        + hints
        + "Report what Reddit users actually said, with short quotes and the subreddit "
        "plus approximate date of each thread. Include negative experiences, not just "
        "praise. If you cannot find Reddit threads for a point, say so explicitly instead "
        "of filling in from general knowledge. Compare options neutrally. Attribute "
        "quotes as 'per Gemini's summary of <thread>', not as verified verbatim. "
        "Include thread links for each supported claim.\n\nQuestion: "
        + question
    )


def api_request(path, key, body=None):
    headers = {"x-goog-api-key": key}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    request = Request(f"{API}/{path}", data=data, headers=headers)
    # Never forward the credential to a redirect destination.
    with build_opener(NoRedirect()).open(request, timeout=TIMEOUT) as response:
        return json.load(response)


def ask(question, subreddits, model, key):
    return api_request(
        f"models/{model}:generateContent",
        key,
        {
            "contents": [{"role": "user", "parts": [{"text": make_prompt(question, subreddits)}]}],
            "tools": [{"google_search": {}}],
        },
    )


def save_raw(response):
    # mkstemp creates a private (0600) file; only the API response is stored.
    fd, path = tempfile.mkstemp(prefix="gemini-reddit-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(response, output, ensure_ascii=False, indent=2)
        output.write("\n")
    return Path(path)


def reddit_thread_url(uri):
    """Normalize thread URLs for deduplication, dropping tracking and comment IDs."""
    parts = urlsplit(uri)
    if parts.scheme not in {"http", "https"} or parts.hostname not in {
        "reddit.com", "www.reddit.com", "old.reddit.com", "new.reddit.com", "np.reddit.com",
    }:
        return None
    match = re.match(r"^/r/[^/]+/comments/[a-zA-Z0-9]+(?:/([^/]+))?(?:/.*)?$", parts.path)
    if not match:
        return None
    # Preserve the thread slug so agents can compare it with the claim.
    path = parts.path.split("/")[:6]
    return urlunsplit(("https", "www.reddit.com", "/".join(path).rstrip("/") + "/", "", ""))


def resolve_thread(uri):
    direct = reddit_thread_url(uri)
    if direct:
        return direct
    parts = urlsplit(uri)
    if (
        parts.scheme != "https"
        or parts.hostname != "vertexaisearch.cloud.google.com"
        or not parts.path.startswith("/grounding-api-redirect/")
    ):
        return None
    # Grounding URLs need no API key. Stop at Location; do not fetch Reddit.
    request = Request(uri, headers={"User-Agent": "gemini-reddit-search/1.0"})
    try:
        with build_opener(NoRedirect()).open(request, timeout=TIMEOUT) as response:
            location = response.headers.get("Location")
    except HTTPError as error:
        try:
            if error.code not in {301, 302, 303, 307, 308}:
                raise
            location = error.headers.get("Location")
        finally:
            error.close()
    return reddit_thread_url(urljoin(uri, location)) if location else None


def collect_threads(metadata):
    threads = []
    seen_uris = set()
    seen_threads = set()
    unresolved = 0
    for chunk in metadata.get("groundingChunks", []):
        uri = chunk.get("web", {}).get("uri")
        if not uri or uri in seen_uris:
            continue
        seen_uris.add(uri)
        try:
            thread = resolve_thread(uri)
        except (HTTPError, URLError, TimeoutError, ValueError):
            thread = None
        if thread is None:
            unresolved += 1
        else:
            thread_id = urlsplit(thread).path.split("/")[4].lower()
            if thread_id not in seen_threads:
                seen_threads.add(thread_id)
                threads.append(thread)
    return threads, unresolved


def render_result(question, response):
    candidates = response.get("candidates", [])
    candidate = candidates[0] if candidates else {}
    answer = "".join(
        part.get("text", "") for part in candidate.get("content", {}).get("parts", [])
        if not part.get("thought")
    ).strip()
    metadata = candidate.get("groundingMetadata", {})
    threads, unresolved = collect_threads(metadata)
    lines = [f"## {question}", "", answer or "Gemini returned no answer.", "",
             "### Resolved Reddit threads", ""]
    lines.extend(f"- [{url}]({url})" for url in threads)
    if not threads:
        lines.append("No grounded Reddit thread URLs resolved; treat the answer as unsupported.")
    if unresolved:
        lines.extend(["", f"{unresolved} source(s) could not be resolved to Reddit threads."])
    lines.extend(["", "### Search queries", ""])
    queries = list(dict.fromkeys(metadata.get("webSearchQueries", [])))
    lines.extend(f"- {query}" for query in queries)
    if not queries:
        lines.append("Gemini returned no search queries.")
    lines.extend(["", "Quotes are per Gemini's summary of the linked threads, not verified verbatim."])
    return "\n".join(lines), bool(answer and threads)


def list_models(key):
    token = None
    while True:
        path = "models" + ("?" + urlencode({"pageToken": token}) if token else "")
        response = api_request(path, key)
        print(f"Raw JSON: {save_raw(response)}", file=sys.stderr)
        for model in response.get("models", []):
            if "generateContent" in model.get("supportedGenerationMethods", []):
                print(f"- `{model['name'].removeprefix('models/')}`")
        token = response.get("nextPageToken")
        if not token:
            return


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("questions", nargs="*", help="one or more quoted questions")
    parser.add_argument("--file", type=Path, help="UTF-8 questions, one per nonempty line; - for stdin")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Gemini model (default: {DEFAULT_MODEL})")
    parser.add_argument("--subreddit", action="append", default=[], help="subreddit hint; repeat as needed")
    parser.add_argument("--list-models", action="store_true", help="list models supporting generateContent")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", args.model):
        parser.error("--model must be a model ID, such as gemini-3.8-flash")
    args.subreddit = [name.removeprefix("r/") for name in args.subreddit]
    if any(not re.fullmatch(r"[a-zA-Z0-9_]+", name) for name in args.subreddit):
        parser.error("--subreddit must be a name such as homelab or r/homelab")
    if args.list_models:
        if args.questions or args.file:
            parser.error("--list-models cannot be combined with questions or --file")
        return args
    try:
        if args.file:
            content = sys.stdin.read() if str(args.file) == "-" else args.file.read_text(encoding="utf-8")
            args.questions.extend(content.splitlines())
        elif not args.questions and not sys.stdin.isatty():
            args.questions.extend(sys.stdin.read().splitlines())
    except (OSError, UnicodeError):
        parser.error("could not read the UTF-8 question file")
    args.questions = [question.strip() for question in args.questions if question.strip()]
    if not args.questions:
        parser.error("provide a question, --file PATH, or questions on stdin")
    return args


def main(argv=None):
    args = parse_args(argv)
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        print("Set GEMINI_API_KEY in the environment before running this script.", file=sys.stderr)
        return 1
    try:
        if args.list_models:
            list_models(key)
            return 0
        supported = True
        for question in args.questions:
            response = ask(question, args.subreddit, quote(args.model, safe=""), key)
            print(f"Raw JSON: {save_raw(response)}", file=sys.stderr)
            markdown, grounded = render_result(question, response)
            print(markdown, end="\n\n", flush=True)
            supported = supported and grounded
        return 0 if supported else 2
    except HTTPError as error:
        # Do not print request headers, error bodies, or credentials.
        print(f"Gemini API returned HTTP {error.code}. Check access, quota, and --list-models.", file=sys.stderr)
        error.close()
    except (URLError, TimeoutError):
        print("Gemini API request failed or timed out (300 seconds).", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError):
        print("Could not read or save the Gemini response.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
