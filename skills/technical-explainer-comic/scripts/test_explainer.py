#!/usr/bin/env python3

import copy
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.dont_write_bytecode = True

from validate_explainer import validate_artifact, validate_manifest_data


SCRIPT_DIR = Path(__file__).resolve().parent
RENDERER = SCRIPT_DIR / "render_explainer.py"
VALIDATOR = SCRIPT_DIR / "validate_explainer.py"


def png_chunk(kind, data):
    payload = kind + data
    return (
        struct.pack(">I", len(data))
        + payload
        + struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
    )


def write_png(path, width=160, height=90):
    path.parent.mkdir(parents=True, exist_ok=True)
    row = b"\x00" + (b"\xff\xff\xff" * width)
    image_data = row * height
    png = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0),
        )
        + png_chunk(b"IDAT", zlib.compress(image_data))
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(png)


def fixture_manifest():
    panels = []
    for index, nav in enumerate(("Boundary", "Request", "Failure"), start=1):
        number = f"{index:02d}"
        panels.append(
            {
                "number": number,
                "nav": nav,
                "title": f"Panel {number} explains <unsafe>.",
                "summary": "The visible layer stays **plain** and concise.",
                "callout": {
                    "title": "Key idea",
                    "body": "Persistent state lives under `job:<id>`.",
                },
                "image": f"assets/fixture-illustrations/{number}-panel.png",
                "alt": f"A character demonstrates fixture panel {number}.",
                "caption": f"Panel {number} · fixture",
                "caption_note": "One cognitive turn",
                "trace": [
                    "Producer calls `POST /jobs`.",
                    "Worker reads `job:<id>`.",
                    "Service returns the bounded result.",
                ],
                "trace_note": "This is test-only evidence.",
            }
        )

    return {
        "title": "Fixture system, from enqueue to result.",
        "eyebrow": "A three-panel technical comic",
        "summary": "A deterministic fixture for the explainer renderer.",
        "read_note": {
            "title": "Read the pictures first.",
            "body": "Open the technical trace for exact mechanics.",
        },
        "panels": panels,
        "appendix": {
            "title": "The state map",
            "intro": "One record family behind the fixture.",
            "records": [
                {
                    "key": "job:<id>",
                    "created": "Enqueue",
                    "contains": "Validated work and attempt count",
                    "lifetime": "One hour",
                }
            ],
            "cards": [
                {
                    "tone": "blue",
                    "title": "Why it persists",
                    "body": "Another process can read the record.",
                }
            ],
        },
        "footer": {
            "note": "Generated from a deterministic test fixture.",
            "sources": ["src/example.py"],
        },
    }


class ExplainerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "artifact"
        self.manifest_path = self.root / "manifest.json"
        self.manifest = fixture_manifest()
        for panel in self.manifest["panels"]:
            write_png(self.artifact / panel["image"])
        self.write_manifest()

    def write_manifest(self):
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2) + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def run_script(self, *arguments):
        return subprocess.run(
            [sys.executable, *map(str, arguments)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_renderer_and_validator_accept_complete_artifact(self):
        render = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(render.returncode, 0, render.stderr)
        self.assertIn("PASS: rendered 3 panels", render.stdout)

        validate = self.run_script(
            VALIDATOR,
            "--manifest",
            self.manifest_path,
            "--artifact",
            self.artifact,
        )
        self.assertEqual(validate.returncode, 0, validate.stderr)
        self.assertIn("PASS: valid manifest and artifact", validate.stdout)

        html = (self.artifact / "index.html").read_text(encoding="utf-8")
        self.assertEqual(html.count("<details>"), 3)
        self.assertIn("&lt;unsafe&gt;", html)
        self.assertNotIn("<unsafe>", html)
        self.assertIn("<code>job:&lt;id&gt;</code>", html)
        self.assertIn("input or work movement", html)

    def test_renderer_substitutes_only_template_tokens(self):
        self.manifest["title"] = "Literal {{PANELS}} and **bold**"
        self.manifest["summary"] = "Keep {{FOOTER_NOTE}} literal."
        self.write_manifest()

        render = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(render.returncode, 0, render.stderr)

        html = (self.artifact / "index.html").read_text(encoding="utf-8")
        self.assertIn("<title>Literal {{PANELS}} and bold</title>", html)
        self.assertIn(
            "<h1>Literal {{PANELS}} and <strong>bold</strong></h1>",
            html,
        )
        self.assertIn(
            '<meta name="description" content="Keep {{FOOTER_NOTE}} literal." />',
            html,
        )
        self.assertEqual(validate_artifact(self.manifest, self.artifact), [])

    def test_custom_legend_renders_all_three_tones(self):
        self.manifest["legend"] = [
            {"tone": "orange", "label": "message movement"},
            {"tone": "blue", "label": "worker state"},
            {"tone": "red", "label": "retry & dead letter"},
        ]
        self.write_manifest()

        render = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(render.returncode, 0, render.stderr)

        html = (self.artifact / "index.html").read_text(encoding="utf-8")
        self.assertIn("message movement", html)
        self.assertIn("worker state", html)
        self.assertIn("retry &amp; dead letter", html)

    def test_manifest_rejects_incomplete_or_duplicate_legend(self):
        invalid = copy.deepcopy(self.manifest)
        invalid["legend"] = [
            {"tone": "orange", "label": "movement"},
            {"tone": "orange", "label": "more movement"},
        ]
        errors = validate_manifest_data(invalid)
        self.assertIn("legend must contain exactly 3 items", errors)

        invalid["legend"].append({"tone": "red", "label": "failure"})
        errors = validate_manifest_data(invalid)
        self.assertIn("legend must use each tone exactly once", errors)

    def test_renderer_and_validator_accept_escaped_image_path(self):
        image = "assets/fixture-illustrations/01-a&b.png"
        self.manifest["panels"][0]["image"] = image
        write_png(self.artifact / image)
        self.write_manifest()

        render = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(render.returncode, 0, render.stderr)
        errors = validate_artifact(self.manifest, self.artifact)
        self.assertEqual(errors, [])

    def test_renderer_accepts_unordered_trace_without_appendix(self):
        self.manifest.pop("appendix")
        self.manifest["panels"][0]["trace_ordered"] = False
        self.write_manifest()

        render = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(render.returncode, 0, render.stderr)

        html = (self.artifact / "index.html").read_text(encoding="utf-8")
        self.assertIn("<ul>", html)
        self.assertNotIn('<section class="appendix">', html)
        self.assertNotIn("{{APPENDIX}}", html)

    def test_renderer_requires_force_for_existing_index(self):
        first = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(first.returncode, 0, first.stderr)

        second = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("pass --force", second.stderr)

        forced = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
            "--force",
        )
        self.assertEqual(forced.returncode, 0, forced.stderr)

    def test_manifest_rejects_parent_traversal(self):
        invalid = copy.deepcopy(self.manifest)
        invalid["panels"][0]["image"] = "../escape.png"
        errors = validate_manifest_data(invalid)
        self.assertTrue(
            any("parent traversal" in error for error in errors),
            errors,
        )

    def test_artifact_rejects_non_widescreen_image(self):
        render = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(render.returncode, 0, render.stderr)
        write_png(self.artifact / self.manifest["panels"][0]["image"], 100, 100)
        errors = validate_artifact(self.manifest, self.artifact)
        self.assertTrue(any("approximately 16:9" in error for error in errors), errors)

    def test_artifact_rejects_zero_dimension_image(self):
        render = self.run_script(
            RENDERER,
            "--manifest",
            self.manifest_path,
            "--output",
            self.artifact,
        )
        self.assertEqual(render.returncode, 0, render.stderr)
        write_png(self.artifact / self.manifest["panels"][0]["image"], 160, 0)
        errors = validate_artifact(self.manifest, self.artifact)
        self.assertTrue(any("dimensions must be non-zero" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
