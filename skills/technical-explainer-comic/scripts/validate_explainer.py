#!/usr/bin/env python3

import argparse
import html as html_module
import json
import struct
import sys
from pathlib import Path, PurePosixPath


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def nonempty_string(value):
    return isinstance(value, str) and bool(value.strip())


def safe_image_path(value):
    if not nonempty_string(value):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and path.suffix.lower() == ".png"
    )


def validate_manifest_data(data):
    errors = []
    if not isinstance(data, dict):
        return ["manifest root must be an object"]

    for field in ("title", "eyebrow", "summary"):
        if not nonempty_string(data.get(field)):
            errors.append(f"{field} must be a non-empty string")

    read_note = data.get("read_note")
    if not isinstance(read_note, dict):
        errors.append("read_note must be an object")
    else:
        for field in ("title", "body"):
            if not nonempty_string(read_note.get(field)):
                errors.append(f"read_note.{field} must be a non-empty string")

    panels = data.get("panels")
    if not isinstance(panels, list):
        errors.append("panels must be an array")
        panels = []
    elif not 3 <= len(panels) <= 9:
        errors.append("panels must contain between 3 and 9 items")

    seen_numbers = set()
    seen_images = set()
    for index, panel in enumerate(panels, start=1):
        prefix = f"panels[{index - 1}]"
        if not isinstance(panel, dict):
            errors.append(f"{prefix} must be an object")
            continue

        expected_number = f"{index:02d}"
        if panel.get("number") != expected_number:
            errors.append(f"{prefix}.number must be {expected_number!r}")
        elif expected_number in seen_numbers:
            errors.append(f"{prefix}.number must be unique")
        seen_numbers.add(panel.get("number"))

        for field in (
            "nav",
            "title",
            "summary",
            "alt",
            "caption",
            "caption_note",
        ):
            if not nonempty_string(panel.get(field)):
                errors.append(f"{prefix}.{field} must be a non-empty string")

        callout = panel.get("callout")
        if not isinstance(callout, dict):
            errors.append(f"{prefix}.callout must be an object")
        else:
            for field in ("title", "body"):
                if not nonempty_string(callout.get(field)):
                    errors.append(
                        f"{prefix}.callout.{field} must be a non-empty string"
                    )

        image = panel.get("image")
        if not safe_image_path(image):
            errors.append(
                f"{prefix}.image must be a relative PNG path without parent traversal"
            )
        elif image in seen_images:
            errors.append(f"{prefix}.image must be unique")
        seen_images.add(image)

        trace = panel.get("trace")
        if not isinstance(trace, list) or not 3 <= len(trace) <= 8:
            errors.append(f"{prefix}.trace must contain between 3 and 8 items")
        elif any(not nonempty_string(item) for item in trace):
            errors.append(f"{prefix}.trace items must be non-empty strings")

        if "trace_ordered" in panel and not isinstance(
            panel["trace_ordered"], bool
        ):
            errors.append(f"{prefix}.trace_ordered must be a boolean")
        if "trace_note" in panel and not nonempty_string(panel["trace_note"]):
            errors.append(f"{prefix}.trace_note must be a non-empty string")

    footer = data.get("footer")
    if not isinstance(footer, dict):
        errors.append("footer must be an object")
    else:
        if not nonempty_string(footer.get("note")):
            errors.append("footer.note must be a non-empty string")
        sources = footer.get("sources")
        if (
            not isinstance(sources, list)
            or not sources
            or any(not nonempty_string(item) for item in sources)
        ):
            errors.append("footer.sources must contain non-empty strings")

    appendix = data.get("appendix")
    if appendix is not None:
        if not isinstance(appendix, dict):
            errors.append("appendix must be an object")
        else:
            for field in ("title", "intro"):
                if not nonempty_string(appendix.get(field)):
                    errors.append(f"appendix.{field} must be a non-empty string")

            records = appendix.get("records", [])
            cards = appendix.get("cards", [])
            if not isinstance(records, list):
                errors.append("appendix.records must be an array")
                records = []
            if not isinstance(cards, list):
                errors.append("appendix.cards must be an array")
                cards = []
            if not records and not cards:
                errors.append("appendix must contain at least one record or card")

            for index, record in enumerate(records):
                prefix = f"appendix.records[{index}]"
                if not isinstance(record, dict):
                    errors.append(f"{prefix} must be an object")
                    continue
                for field in ("key", "created", "contains", "lifetime"):
                    if not nonempty_string(record.get(field)):
                        errors.append(f"{prefix}.{field} must be a non-empty string")

            for index, card in enumerate(cards):
                prefix = f"appendix.cards[{index}]"
                if not isinstance(card, dict):
                    errors.append(f"{prefix} must be an object")
                    continue
                if card.get("tone", "blue") not in ("blue", "red", "orange"):
                    errors.append(f"{prefix}.tone must be blue, red, or orange")
                for field in ("title", "body"):
                    if not nonempty_string(card.get(field)):
                        errors.append(f"{prefix}.{field} must be a non-empty string")

    return errors


def png_dimensions(path):
    with path.open("rb") as file:
        header = file.read(24)
    if len(header) != 24 or header[:8] != PNG_SIGNATURE or header[12:16] != b"IHDR":
        raise ValueError("not a valid PNG header")
    return struct.unpack(">II", header[16:24])


def validate_artifact(data, artifact):
    errors = []
    artifact = artifact.resolve()
    index_path = artifact / "index.html"
    if not index_path.is_file():
        return [f"missing artifact index: {index_path}"]
    if index_path.is_symlink():
        errors.append("index.html must not be a symlink")

    document = index_path.read_text(encoding="utf-8")
    if html_module.escape(data["title"]) not in document:
        errors.append("index.html does not contain the manifest title")
    if document.count("<details>") != len(data["panels"]):
        errors.append("index.html must contain one details element per panel")
    if 'src="http://' in document or 'src="https://' in document:
        errors.append("index.html must not load external image or script assets")
    if "<link rel=\"stylesheet\"" in document or "<script src=" in document:
        errors.append("index.html must inline CSS and JavaScript")

    for panel in data["panels"]:
        relative_image = PurePosixPath(panel["image"])
        image_path = artifact / relative_image
        current_path = artifact
        symlink_component = False
        for component in relative_image.parts:
            current_path = current_path / component
            if current_path.is_symlink():
                symlink_component = True
                break
        if symlink_component:
            errors.append(f"panel image must not use symlinks: {panel['image']}")
            continue
        try:
            resolved = image_path.resolve(strict=True)
        except FileNotFoundError:
            errors.append(f"missing panel image: {panel['image']}")
            continue
        if artifact not in resolved.parents:
            errors.append(f"panel image escapes artifact directory: {panel['image']}")
            continue
        try:
            width, height = png_dimensions(resolved)
        except (OSError, ValueError) as error:
            errors.append(f"invalid panel image {panel['image']}: {error}")
            continue
        ratio = width / height
        if not 1.70 <= ratio <= 1.86:
            errors.append(
                f"panel image must be approximately 16:9: {panel['image']} "
                f"is {width}x{height}"
            )
        if f'src="{panel["image"]}"' not in document:
            errors.append(f"index.html does not reference {panel['image']}")

    return errors


def load_manifest(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"manifest not found: {path}") from None
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid manifest JSON: {error}") from None


def main():
    parser = argparse.ArgumentParser(
        description="Validate a technical explainer manifest and rendered artifact."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path)
    args = parser.parse_args()

    try:
        data = load_manifest(args.manifest)
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    errors = validate_manifest_data(data)
    if not errors and args.artifact:
        errors.extend(validate_artifact(data, args.artifact))

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    scope = "manifest and artifact" if args.artifact else "manifest"
    print(f"PASS: valid {scope} with {len(data['panels'])} panels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
