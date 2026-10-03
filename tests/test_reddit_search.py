"""Offline contract tests; Gemini grounding is checked separately with a live query."""

import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/reddit-search/scripts/search.py"
spec = importlib.util.spec_from_file_location("reddit_search", SCRIPT)
search = importlib.util.module_from_spec(spec)
spec.loader.exec_module(search)


class RedditSearchTests(unittest.TestCase):
    def test_cli_reads_arguments_files_and_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "questions.txt"
            path.write_text("File question?\n\nAnother question?\n", encoding="utf-8")
            args = search.parse_args([
                "Argument question?", "--file", str(path), "--model", "custom-model",
                "--subreddit", "r/homelab", "--subreddit", "selfhosted",
            ])
            self.assertEqual(args.questions, ["Argument question?", "File question?", "Another question?"])
            self.assertEqual(args.subreddit, ["homelab", "selfhosted"])
            self.assertEqual(args.model, "custom-model")
        for arguments in ([], ["--file", "-"]):
            result = subprocess.run(
                [sys.executable, str(SCRIPT), *arguments], input="Stdin question?\n\n",
                text=True, capture_output=True,
                env={name: value for name, value in os.environ.items() if name != "GEMINI_API_KEY"},
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("Set GEMINI_API_KEY", result.stderr)
            self.assertNotIn("provide a question", result.stderr)

    def test_invalid_inputs_fail_before_request(self):
        for arguments in (["--list-models", "Question?"], ["--model", "models/id", "Question?"],
                          ["--subreddit", "reddit.com/r/homelab", "Question?"], [" "]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    search.parse_args(arguments)
                self.assertEqual(error.exception.code, 2)

    def test_thread_urls_normalize_and_exclude_other_sources(self):
        canonical = "https://www.reddit.com/r/homelab/comments/abc123/ups_noise/"
        for uri in (
            canonical,
            "https://old.reddit.com/r/homelab/comments/abc123/ups_noise/comment456/?utm_source=test#top",
            "https://reddit.com/r/homelab/comments/abc123/ups_noise?share_id=123",
        ):
            self.assertEqual(search.reddit_thread_url(uri), canonical)
        for uri in ("https://reddit.com.evil.example/r/x/comments/abc/title/",
                    "https://example.com/r/x/comments/abc/title/", "https://reddit.com/r/homelab/",
                    "https://reddit.com/search?q=ups", "ftp://reddit.com/r/x/comments/abc/title/"):
            self.assertIsNone(search.reddit_thread_url(uri))

    def test_real_http_redirect_stops_at_location_without_key(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, self.headers.get("x-goog-api-key")))
                self.send_response(302)
                self.send_header("Location", "https://www.reddit.com/r/homelab/comments/abc123/ups_noise/")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            uri = f"http://127.0.0.1:{server.server_port}/redirect"
            with self.assertRaises(HTTPError) as error:
                build_opener(search.NoRedirect()).open(Request(uri), timeout=5)
            try:
                self.assertEqual(error.exception.code, 302)
                self.assertEqual(search.reddit_thread_url(error.exception.headers["Location"]),
                                 "https://www.reddit.com/r/homelab/comments/abc123/ups_noise/")
                self.assertEqual(requests, [("/redirect", None)])
            finally:
                error.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_markdown_deduplicates_sources_and_reports_evidence_gaps(self):
        thread = "https://www.reddit.com/r/homelab/comments/abc123/ups_noise/"
        response = {"candidates": [{
            "content": {"parts": [{"text": "Internal thought", "thought": True}, {"text": "Noise varies."}]},
            "groundingMetadata": {
                "groundingChunks": [{"web": {"uri": uri}} for uri in (
                    thread, thread + "?utm_source=test", thread,
                    "https://old.reddit.com/r/homelab/comments/abc123/alternate_slug/comment/",
                    "https://example.com/ups",
                )],
                "webSearchQueries": ["site:reddit.com UPS noise", "site:reddit.com UPS noise"],
            },
        }]}
        markdown, supported = search.render_result("UPS experiences?", response)
        self.assertTrue(supported)
        self.assertIn("Noise varies.", markdown)
        self.assertNotIn("Internal thought", markdown)
        self.assertEqual(markdown.count(f"]({thread})"), 1)
        self.assertEqual(markdown.count("- site:reddit.com UPS noise"), 1)
        self.assertIn("1 source(s) could not be resolved", markdown)
        unsupported, supported = search.render_result("Question?", {"candidates": [{
            "content": {"parts": [{"text": "Ungrounded answer."}]},
        }]})
        self.assertFalse(supported)
        self.assertIn("treat the answer as unsupported", unsupported)
        empty, supported = search.render_result("Question?", {"promptFeedback": {"blockReason": "SAFETY"}})
        self.assertFalse(supported)
        self.assertIn("Gemini returned no answer", empty)

    def test_raw_json_is_private_and_matches_response(self):
        response = {"candidates": [], "promptFeedback": {"blockReason": "SAFETY"}}
        path = search.save_raw(response)
        try:
            self.assertEqual(json.loads(path.read_text()), response)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        finally:
            path.unlink()

    def test_real_build_and_install_copy_skill_for_claude_and_codex(self):
        build_spec = importlib.util.spec_from_file_location("dotfiles_build", ROOT / "scripts/build.py")
        build = importlib.util.module_from_spec(build_spec)
        sys.modules[build_spec.name] = build
        build_spec.loader.exec_module(build)
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            temporary = Path(directory)
            build.BUILD_DIR = temporary / "build"
            build.STATE_DIR = temporary / "state"
            build.INSTALL_MANIFEST = build.STATE_DIR / "agent-install-manifest.json"
            # Use the actual target layout, rooted in a temporary installation.
            build.INSTALL_PATHS = {
                agent: {"skills": temporary / "installed" / paths["skills"].relative_to(Path.home())}
                for agent, paths in build.INSTALL_PATHS.items()
            }
            for agent in build.INSTALL_PATHS:
                self.assertTrue(build.build_skill("reddit-search", SCRIPT.parent.parent, agent))
            build.install_skills()
            for paths in build.INSTALL_PATHS.values():
                installed = paths["skills"] / "reddit-search"
                self.assertFalse(installed.is_symlink())
                self.assertEqual((installed / "scripts/search.py").read_bytes(), SCRIPT.read_bytes())
                instructions = (installed / "SKILL.md").read_text()
                self.assertIn("name: reddit-search", instructions)
                self.assertNotIn("agents: [", instructions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
