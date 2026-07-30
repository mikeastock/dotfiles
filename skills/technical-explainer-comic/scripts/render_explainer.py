#!/usr/bin/env python3

import argparse
import html
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from validate_explainer import load_manifest, validate_manifest_data


SKILL_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = SKILL_DIR / "assets" / "page-template.html"
INLINE_PATTERN = re.compile(r"(`[^`\n]+`|\*\*[^*\n]+\*\*)")


def inline_markup(value):
    parts = []
    cursor = 0
    for match in INLINE_PATTERN.finditer(value):
        parts.append(html.escape(value[cursor : match.start()]))
        token = match.group(0)
        if token.startswith("`"):
            parts.append(f"<code>{html.escape(token[1:-1])}</code>")
        else:
            parts.append(f"<strong>{html.escape(token[2:-2])}</strong>")
        cursor = match.end()
    parts.append(html.escape(value[cursor:]))
    return "".join(parts)


def render_nav(panels):
    items = []
    for panel in panels:
        items.append(
            '<li><a href="#scene-{number}">{number} {nav}</a></li>'.format(
                number=html.escape(panel["number"]),
                nav=html.escape(panel["nav"]),
            )
        )
    return "\n".join(items)


def render_panel(panel):
    list_tag = "ol" if panel.get("trace_ordered", True) else "ul"
    trace_items = "\n".join(
        f"<li>{inline_markup(item)}</li>" for item in panel["trace"]
    )
    trace_note = ""
    if panel.get("trace_note"):
        trace_note = (
            f'<p class="trace-note">{inline_markup(panel["trace_note"])}</p>'
        )
    return f"""
<section class="strip" id="scene-{html.escape(panel["number"])}">
  <figure class="art">
    <div class="art-frame">
      <img loading="lazy" src="{html.escape(panel["image"])}" alt="{html.escape(panel["alt"])}" />
    </div>
    <figcaption>
      <span>{inline_markup(panel["caption"])}</span>
      <span>{inline_markup(panel["caption_note"])}</span>
    </figcaption>
  </figure>
  <div class="story">
    <span class="panel-no">{html.escape(panel["number"])}</span>
    <h2>{inline_markup(panel["title"])}</h2>
    <p>{inline_markup(panel["summary"])}</p>
    <div class="plain">
      <strong>{inline_markup(panel["callout"]["title"])}</strong>
      {inline_markup(panel["callout"]["body"])}
    </div>
    <details>
      <summary>{html.escape(panel.get("trace_title", "Technical trace"))}</summary>
      <div class="trace">
        <{list_tag}>{trace_items}</{list_tag}>
        {trace_note}
      </div>
    </details>
  </div>
</section>""".strip()


def render_appendix(appendix):
    if not appendix:
        return ""

    records = appendix.get("records", [])
    table = ""
    if records:
        rows = "\n".join(
            """
<tr>
  <td><code>{key}</code></td>
  <td>{created}</td>
  <td>{contains}</td>
  <td>{lifetime}</td>
</tr>
""".strip().format(
                key=html.escape(record["key"]),
                created=inline_markup(record["created"]),
                contains=inline_markup(record["contains"]),
                lifetime=inline_markup(record["lifetime"]),
            )
            for record in records
        )
        table = f"""
<div class="record-map" role="region" aria-label="Persistent state map" tabindex="0">
  <table>
    <thead>
      <tr>
        <th>Key family</th>
        <th>Created when</th>
        <th>Contains</th>
        <th>Lifetime</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>""".strip()

    cards_data = appendix.get("cards", [])
    cards = ""
    if cards_data:
        rendered_cards = "\n".join(
            """
<article class="card {tone}">
  <h3>{title}</h3>
  <p>{body}</p>
</article>
""".strip().format(
                tone=html.escape(card.get("tone", "blue")),
                title=inline_markup(card["title"]),
                body=inline_markup(card["body"]),
            )
            for card in cards_data
        )
        cards = f'<div class="cards">{rendered_cards}</div>'

    return f"""
<section class="appendix">
  <div class="appendix-head">
    <h2>{inline_markup(appendix["title"])}</h2>
    <p>{inline_markup(appendix["intro"])}</p>
  </div>
  {table}
  {cards}
</section>""".strip()


def render_document(data):
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    replacements = {
        "META_DESCRIPTION": html.escape(data["summary"]),
        "HEAD_TITLE": html.escape(data["title"]),
        "HERO_EYEBROW": html.escape(data["eyebrow"]),
        "HERO_TITLE": inline_markup(data["title"]),
        "HERO_SUMMARY": inline_markup(data["summary"]),
        "READ_NOTE_TITLE": inline_markup(data["read_note"]["title"]),
        "READ_NOTE_BODY": inline_markup(data["read_note"]["body"]),
        "NAV_ITEMS": render_nav(data["panels"]),
        "PANELS": "\n".join(render_panel(panel) for panel in data["panels"]),
        "APPENDIX": render_appendix(data.get("appendix")),
        "FOOTER_NOTE": inline_markup(data["footer"]["note"]),
        "SOURCES": "\n".join(
            f"<code>{html.escape(source)}</code>"
            for source in data["footer"]["sources"]
        ),
    }
    for token, value in replacements.items():
        template = template.replace(f"{{{{{token}}}}}", value)
    unresolved = re.findall(r"\{\{[A-Z_]+\}\}", template)
    if unresolved:
        raise ValueError(f"unresolved template tokens: {', '.join(unresolved)}")
    return template


def main():
    parser = argparse.ArgumentParser(
        description="Render a technical explainer comic from a JSON manifest."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        data = load_manifest(args.manifest)
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    errors = validate_manifest_data(data)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    args.output.mkdir(parents=True, exist_ok=True)
    index_path = args.output / "index.html"
    if index_path.exists() and not args.force:
        print(
            f"FAIL: {index_path} already exists; pass --force to replace it",
            file=sys.stderr,
        )
        return 1

    try:
        document = render_document(data)
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    temporary_path = args.output / ".index.html.tmp"
    temporary_path.write_text(document, encoding="utf-8")
    temporary_path.replace(index_path)
    print(f"PASS: rendered {len(data['panels'])} panels to {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
