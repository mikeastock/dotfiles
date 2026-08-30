#!/usr/bin/env python3
"""Render a skill-doctor report.json into one self-contained report.html.

Usage: render_report.py REPORT_JSON [--out PATH] [--open]

Stdlib only. No external assets; diffs render as plain <pre> blocks.
"""

import argparse
import html
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

CSS = """
:root { --bg:#0f1115; --panel:#171a21; --fg:#e6e6e6; --muted:#9aa3ad; --line:#2a2f3a; --accent:#c8f56b; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; }
main { max-width:960px; margin:0 auto; padding:32px 20px 64px; }
h1 { font-size:26px; margin:0 0 4px; }
h2 { font-size:18px; margin:32px 0 12px; border-bottom:1px solid var(--line); padding-bottom:6px; }
.sub { color:var(--muted); font-size:13px; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:20px 0; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
.card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
.card .grade { font-size:30px; font-weight:700; color:var(--accent); }
.card .pct { color:var(--muted); font-size:13px; }
.stats { display:flex; flex-wrap:wrap; gap:16px; color:var(--muted); font-size:13px; }
ol.findings li { margin:8px 0; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
.fail { color:#ff7b7b; }
details { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:10px 14px; margin:10px 0; }
summary { cursor:pointer; font-weight:600; }
.evidence { color:var(--muted); font-size:13px; margin:6px 0 10px; }
pre { background:#0b0d11; border:1px solid var(--line); border-radius:6px; padding:12px; overflow:auto; font-size:12px; line-height:1.45; }
.add { color:#8fe388; } .del { color:#ff7b7b; } .hunk { color:#7fb3ff; }
code { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
@media (max-width:700px) { .grid { grid-template-columns:repeat(2,1fr); } }
"""


def grade_for(score: float) -> str:
    if score >= 0.9:
        return "A"
    if score >= 0.8:
        return "B"
    if score >= 0.7:
        return "C"
    if score >= 0.6:
        return "D"
    return "F"


def pct(score) -> int:
    try:
        return int(round(float(score) * 100))
    except (TypeError, ValueError):
        return 0


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def format_generated_at(value) -> str:
    if not value:
        return datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M %Z").strip()
    except ValueError:
        return str(value)


def render_diff(diff_text: str) -> str:
    if not diff_text:
        return ""
    out = []
    for line in diff_text.splitlines():
        cls = ""
        if line.startswith("+") and not line.startswith("+++"):
            cls = "add"
        elif line.startswith("-") and not line.startswith("---"):
            cls = "del"
        elif line.startswith("@@"):
            cls = "hunk"
        text = esc(line)
        out.append(f'<span class="{cls}">{text}</span>' if cls else text)
    return "<pre><code>" + "\n".join(out) + "</code></pre>"


def score_card(label: str, score) -> str:
    return (
        f'<div class="card"><div class="label">{esc(label)}</div>'
        f'<div class="grade">{grade_for(float(score or 0))}</div>'
        f'<div class="pct">{pct(score)}%</div></div>'
    )


def render_page(r: dict) -> str:
    scores = r.get("scores") or {}
    stats = r.get("stats") or {}
    sources = r.get("sources") or ([r["harness"]] if r.get("harness") else [])
    findings = r.get("top_findings") or []
    sessions = r.get("sessions") or []
    suggestions = r.get("suggestions") or []

    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        f"<title>{esc(r.get('title') or 'Agent Skill Report')}</title>",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"<style>{CSS}</style></head><body><main>",
        f"<h1>{esc(r.get('title') or 'Agent Skill Report')}</h1>",
        f"<div class=\"sub\">{esc(r.get('handle') or '')} · {esc(', '.join(sources) or 'unknown sources')} · {esc(format_generated_at(r.get('generated_at')))}</div>",
        "<div class=\"grid\">",
        score_card("Overall", scores.get("overall", 0)),
        score_card("Efficiency", scores.get("efficiency", 0)),
        score_card("Code quality", scores.get("code_quality", 0)),
        score_card("Skill coverage", scores.get("skill_coverage", 0)),
        "</div>",
        "<div class=\"stats\">",
        f"<span>{esc(stats.get('sessions_analyzed', 0))} sessions scored</span>",
        f"<span>{esc(stats.get('sessions_scanned', 0))} scanned</span>",
        f"<span>{esc(stats.get('skills_found', 0))} skills installed</span>",
        f"<span>{esc(stats.get('skills_used', 0))} used</span>",
        f"<span>last {esc(stats.get('window_days', 45))} days</span>",
        "</div>",
        "<h2>Top findings</h2><ol class=\"findings\">",
    ]
    parts.extend(f"<li>{esc(f)}</li>" for f in findings)
    parts.append("</ol>")

    if sessions:
        parts.append("<h2>Sessions</h2><table><thead><tr><th>Session</th><th>Source</th><th>Efficiency</th><th>Code quality</th><th>Skills</th><th>Note</th></tr></thead><tbody>")
        for s in sessions:
            eff = s.get("efficiency")
            cq = s.get("code_quality")
            eff_cls = " class=\"fail\"" if isinstance(eff, (int, float)) and eff < 0.5 else ""
            cq_cls = " class=\"fail\"" if isinstance(cq, (int, float)) and cq < 0.5 else ""
            skills = s.get("skills") or []
            parts.append(
                f"<tr><td><code>{esc(s.get('id'))}</code></td><td>{esc(s.get('source'))}</td>"
                f"<td{eff_cls}>{esc(eff if eff is not None else '—')}</td>"
                f"<td{cq_cls}>{esc(cq if cq is not None else '—')}</td>"
                f"<td>{esc(', '.join(skills) if skills else '—')}</td><td>{esc(s.get('note') or '')}</td></tr>"
            )
        parts.append("</tbody></table>")

    parts.append("<h2>Suggested skill edits</h2>")
    if not suggestions:
        parts.append("<p class=\"sub\">No skill edits met the evidence bar.</p>")
    for sg in suggestions:
        parts.append("<details open>")
        parts.append(f"<summary>{esc(sg.get('skill'))}: {esc(sg.get('change'))}</summary>")
        if sg.get("evidence"):
            parts.append(f"<div class=\"evidence\">Evidence: {esc(sg['evidence'])}</div>")
        if sg.get("proposed_path"):
            parts.append(f"<div class=\"evidence\">Proposed file: <code>{esc(sg['proposed_path'])}</code></div>")
        parts.append(render_diff(sg.get("diff") or ""))
        parts.append("</details>")

    parts.append("</main></body></html>")
    return "\n".join(parts)


def open_report(path: Path) -> bool:
    for cmd in (["xdg-open", str(path)], ["open", str(path)]):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (FileNotFoundError, OSError):
            continue
    return False


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("report_json")
    p.add_argument("--out", help="output HTML path (default: report.html beside report.json)")
    p.add_argument("--open", action="store_true", help="open the report in the default browser")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    src = Path(args.report_json).expanduser().resolve()
    try:
        report = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {src}: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out).expanduser().resolve() if args.out else src.with_name("report.html")
    out.write_text(render_page(report), encoding="utf-8")
    print(f"report: {out}")
    if args.open and not open_report(out):
        print("could not open a browser; open the file manually", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
