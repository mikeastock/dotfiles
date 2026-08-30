#!/usr/bin/env python3
"""Collect normalized Letta trajectory sessions and installed skills for scoring.

Reads the local trajectory pipeline (state/history.jsonl + normalized/<source>/*.json),
filters sessions by project and recency, discovers installed skills, detects which
sessions used which skills, samples sessions, and emits:

  <out>/inventory.json        - skills, per-session stats, sampling decisions
  <out>/transcripts/<id>.md   - condensed transcripts for sampled sessions

Everything runs locally; nothing is uploaded. Python 3.9+, stdlib only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_DOTFILES_ROOT = os.environ.get("DOTFILES_ROOT", "/data/workspace/code/personal/dotfiles")

MAX_MSG_CHARS = 1500
MAX_TOOL_ARGS_CHARS = 500
MAX_TOOL_RESULT_CHARS = 500
MAX_REASONING_CHARS = 300
MAX_TRANSCRIPT_ENTRIES = 160
TRANSCRIPT_HEAD = 100
TRANSCRIPT_TAIL = 40

PROJECT_SKILL_DIRS = (".agents/skills", ".claude/skills", ".codex/skills", ".opencode/skills", ".pi/skills")
GLOBAL_SKILL_DIRS = (
    "~/.agents/skills",
    "~/.claude/skills",
    "~/.codex/skills",
    "~/.grok/skills",
    "~/.pi/agent/skills",
    "~/.config/agents/skills",
    "~/.config/opencode/skills",
)

CODE_EDIT_TOOLS = {
    "Edit", "MultiEdit", "NotebookEdit", "Write",
    "edit", "write", "apply_patch", "search_replace", "StrReplace",
    "str_replace_editor", "str_replace_based_edit_tool", "create_file", "edit_file", "write_file",
    "replace_string_in_file", "insert_edit_into_file",
}
CODE_EDIT_HINTS = ("*** Begin Patch", "<<<<<<< SEARCH")
SKILL_TOOLS = {"Skill", "skill", "use_skill", "load_skill"}

SKILL_PATH_RE = re.compile(r"skills/([A-Za-z0-9][A-Za-z0-9._-]*)/(?:SKILL\.md|[A-Za-z0-9._-]+)", re.IGNORECASE)
SKILL_TAG_RE = re.compile(r"<skill\s+name=\"([A-Za-z0-9][A-Za-z0-9._-]*)\"")
SKILL_BASEDIR_RE = re.compile(r"Base directory for this skill:\s*\S*/([A-Za-z0-9][A-Za-z0-9._-]*)\s*$", re.MULTILINE)
SLASH_INVOKE_RE = re.compile(r"^\s*[/$]([A-Za-z0-9][A-Za-z0-9._-]*)\b")
USER_QUERY_RE = re.compile(r"<user_query>([\s\S]*?)</user_query>", re.IGNORECASE)
INJECTED_RE = re.compile(
    r"<system-reminder>|<skill_information>|<environment_context>|<skills_instructions>|<permissions instructions>|<recommended_plugins>"
)
HELPER_PROMPT_RE = re.compile(
    r"^(?:you are (?:the )?(?:trusted|senior|a |an )|read the frozen work order|you are taking (?:a )?handoff|# handoff|your task is|implement the following"
    r"|the following is the codex agent history)",
    re.IGNORECASE,
)
INJECTED_BLOCK_RE = re.compile(
    r"<(recommended_plugins|environment_context|permission_profile|system_instructions|user_info|skill_information|system-reminder|skills_instructions)\b[^>]*>[\s\S]*?</\1>",
    re.IGNORECASE,
)
DROP_USER_PREFIXES = ("# AGENTS.md instructions", "<skill-dir>")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--trajectories-root", required=True,
                   help="data root built by ingest.sh for this run")
    p.add_argument("--source", action="append", default=[],
                   help="normalized source to include, e.g. claude-code, codex, pi (repeatable; default: all)")
    p.add_argument("--repo", action="append", default=[],
                   help="project to include (repeatable; default: git root of cwd, else cwd)")
    p.add_argument("--all-conversations", action="store_true",
                   help="score sessions from every project represented in the history")
    p.add_argument("--include-global-skills", action="store_true",
                   help="also discover skills outside the repo (~/.agents/skills, ~/.claude/skills, ...)")
    p.add_argument("--dotfiles-root", default=DEFAULT_DOTFILES_ROOT,
                   help="dotfiles repo whose skills/<name>/SKILL.md is the source of installed skills")
    p.add_argument("--days", type=int, default=45, help="only consider sessions updated in the last N days")
    p.add_argument("--max-sessions", type=int, default=12, help="max sessions to sample for scoring")
    p.add_argument("--per-skill", type=int, default=3, help="max sampled sessions per skill")
    p.add_argument("--no-skill", type=int, default=4, help="max sampled sessions that used no skill")
    p.add_argument("--min-assistant-turns", type=int, default=3, help="skip sessions with fewer assistant records")
    p.add_argument("--skills-dir", action="append", default=[], help="extra skills directory to scan (repeatable)")
    p.add_argument("--include-subagents", action="store_true",
                   help="include subagent/child sessions and helper-prompt sessions (reviewers, work orders)")
    p.add_argument("--out", default="./skill-doctor-report")
    return p.parse_args(argv)


# --- repos -------------------------------------------------------------------

def git_toplevel(path: Path):
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True).stdout.strip()
        return Path(out).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def git_worktrees(repo: Path):
    paths = {repo}
    try:
        out = subprocess.run(["git", "-C", str(repo), "worktree", "list", "--porcelain"],
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return paths
    for line in out.splitlines():
        if line.startswith("worktree "):
            paths.add(Path(line[len("worktree "):]).resolve())
    return paths


def resolve_repos(repo_args):
    if not repo_args:
        top = git_toplevel(Path.cwd())
        return [top or Path.cwd().resolve()]
    repos = []
    for arg in repo_args:
        path = Path(arg).expanduser().resolve()
        if not path.is_dir():
            sys.exit(f"error: --repo {arg} is not a directory")
        top = git_toplevel(path)
        if top is None:
            sys.exit(f"error: --repo {arg} is not inside a git repository")
        if top not in repos:
            repos.append(top)
    return repos


def path_within(child, parents) -> bool:
    if not child:
        return False
    try:
        c = Path(child).resolve()
    except OSError:
        c = Path(child)
    for parent in parents:
        if c == parent or parent in c.parents:
            return True
    return False


# --- skills ------------------------------------------------------------------

def read_frontmatter_description(skill_md: Path) -> str:
    try:
        text = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return ""
    fm = m.group(1)
    dm = re.search(r"^description:\s*(.*)$", fm, re.MULTILINE)
    if not dm:
        return ""
    desc = dm.group(1).strip().strip("\"'")
    if desc in (">-", ">", "|", "|-"):
        lines = []
        after = fm[dm.end():].lstrip("\n").splitlines()
        for line in after:
            if line.startswith((" ", "\t")):
                lines.append(line.strip())
            else:
                break
        desc = " ".join(lines)
    return desc


def scan_skill_dir(directory: Path, scope: str, skills: dict, skill_home: str):
    if not directory.is_dir():
        return
    for child in sorted(directory.iterdir()):
        skill_md = child / "SKILL.md"
        if not child.is_dir() or not skill_md.is_file():
            continue
        name = child.name
        entry = skills.setdefault(name, {
            "name": name,
            "path": str(skill_md),
            "paths": [],
            "scope": scope,
            "homes": [],
            "description": read_frontmatter_description(skill_md),
            "source_path": None,
        })
        if str(skill_md) not in entry["paths"]:
            entry["paths"].append(str(skill_md))
        if skill_home not in entry["homes"]:
            entry["homes"].append(skill_home)
        if scope == "project" and entry["scope"] == "global":
            entry["scope"] = "project"
            entry["path"] = str(skill_md)


def discover_skills(repos, extra_dirs, include_global: bool, dotfiles_root: Path):
    skills = {}
    for repo in repos:
        for rel in PROJECT_SKILL_DIRS:
            scan_skill_dir(repo / rel, "project", skills, f"{repo}/{rel}")
    for extra in extra_dirs:
        scan_skill_dir(Path(extra).expanduser().resolve(), "project", skills, str(extra))
    if include_global:
        for pattern in GLOBAL_SKILL_DIRS:
            scan_skill_dir(Path(pattern).expanduser(), "global", skills, pattern)
    if dotfiles_root.is_dir() and (dotfiles_root / "plugins.toml").is_file():
        for name, entry in skills.items():
            src = dotfiles_root / "skills" / name / "SKILL.md"
            if src.is_file():
                entry["source_path"] = str(src)
    return skills


# --- sessions ----------------------------------------------------------------

def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_history(root: Path):
    path = root / "state" / "history.jsonl"
    if not path.is_file():
        sys.exit(
            f"error: {path} not found. Run scripts/ingest.sh --root {root} "
            "(see references/trajectory-sources.md)."
        )
    rows = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def is_subagent_source(row) -> bool:
    src = row.get("sourcePath") or ""
    base = os.path.basename(src)
    return base.startswith("agent-") or "/subagents/" in src or "/sidechain" in src


def truncate(text: str, limit: int) -> str:
    text = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + f" …[+{len(text) - limit} chars]"


def clean_user_content(content: str) -> str:
    matches = USER_QUERY_RE.findall(content)
    if matches:
        content = "\n".join(m.strip() for m in matches)
    content = re.sub(r"<skill\s+name=\"[^\"]+\"[^>]*>[\s\S]*?</skill>", "[skill injected]", content, flags=re.IGNORECASE)
    content = INJECTED_BLOCK_RE.sub(" ", content).strip()
    if content.startswith(DROP_USER_PREFIXES):
        return ""
    return content


def content_text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("content") or ""))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return json.dumps(content, ensure_ascii=False)


def detect_skills(records, known_names):
    detected, unknown = set(), set()

    def note(name):
        if not name:
            return
        if name in known_names:
            detected.add(name)
        else:
            unknown.add(name)

    for rec in records:
        role = rec.get("role")
        text = content_text(rec.get("content"))
        for call in rec.get("tool_calls") or []:
            name = call.get("name") or ""
            args = call.get("args") or ""
            if not isinstance(args, str):
                args = json.dumps(args, ensure_ascii=False)
            if name in SKILL_TOOLS:
                try:
                    parsed = json.loads(args)
                except (json.JSONDecodeError, TypeError):
                    parsed = {}
                if isinstance(parsed, dict):
                    note(parsed.get("skill") or parsed.get("name") or parsed.get("skill_name"))
            for m in SKILL_PATH_RE.finditer(args):
                if m.group(1) in known_names or "SKILL.md" in m.group(0):
                    note(m.group(1))
        if role == "user":
            for m in SKILL_TAG_RE.finditer(text):
                note(m.group(1))
            for m in SKILL_BASEDIR_RE.finditer(text):
                note(m.group(1))
            for m in SKILL_PATH_RE.finditer(text):
                if "SKILL.md" in m.group(0):
                    note(m.group(1))
            cleaned = clean_user_content(text)
            m = SLASH_INVOKE_RE.match(cleaned)
            if m and m.group(1) in known_names:
                detected.add(m.group(1))
        elif role == "assistant" and text:
            for m in SKILL_PATH_RE.finditer(text):
                if "SKILL.md" in m.group(0):
                    note(m.group(1))
    return sorted(detected), sorted(unknown)


def has_code_edits(records) -> bool:
    for rec in records:
        for call in rec.get("tool_calls") or []:
            if call.get("name") in CODE_EDIT_TOOLS:
                return True
            args = call.get("args") or ""
            if isinstance(args, str) and any(h in args for h in CODE_EDIT_HINTS):
                return True
    return False


def first_user_prompt(records) -> str:
    for rec in records:
        if rec.get("role") == "user":
            cleaned = clean_user_content(content_text(rec.get("content")))
            if cleaned:
                return cleaned
    return ""


def build_entries(records):
    """Condense normalized records into transcript entries."""
    entries = []
    call_names = {}
    for rec in records:
        role = rec.get("role")
        ts = rec.get("timestamp") or ""
        if role == "meta":
            continue
        if role == "user":
            text = clean_user_content(content_text(rec.get("content")))
            if not text:
                continue
            tag = "user"
            if INJECTED_RE.search(content_text(rec.get("content"))):
                tag = "user (injected context stripped)"
            entries.append((tag, ts, truncate(text, MAX_MSG_CHARS)))
        elif role == "reasoning":
            text = content_text(rec.get("content"))
            if text.strip():
                entries.append(("reasoning", ts, truncate(text, MAX_REASONING_CHARS)))
        elif role == "assistant":
            text = content_text(rec.get("content"))
            if text.strip():
                entries.append(("assistant", ts, truncate(text, MAX_MSG_CHARS)))
            for call in rec.get("tool_calls") or []:
                name = call.get("name") or "tool"
                call_names[call.get("id")] = name
                args = call.get("args") or ""
                if not isinstance(args, str):
                    args = json.dumps(args, ensure_ascii=False)
                entries.append((f"tool_call {name}", ts, truncate(args, MAX_TOOL_ARGS_CHARS)))
        elif role == "tool":
            name = call_names.get(rec.get("tool_call_id"), "tool")
            ok = rec.get("ok")
            status = "" if ok is None else (" ok" if ok else " ERROR")
            text = content_text(rec.get("content"))
            entries.append((f"tool_result {name}{status}", ts, truncate(text, MAX_TOOL_RESULT_CHARS)))
    return entries


def render_transcript(meta: dict, entries) -> str:
    lines = [f"# Session {meta['id']} ({meta['source']})", ""]
    for key in ("cwd", "git_branch", "model", "started", "ended", "duration_min",
                "user_turns", "assistant_turns", "tool_calls", "tool_errors",
                "code_edits", "skills_used", "skills_unknown"):
        value = meta.get(key)
        if isinstance(value, list):
            value = ", ".join(value) if value else "none"
        elif isinstance(value, bool):
            value = "yes" if value else "no"
        lines.append(f"- {key}: {value}")
    lines.append("")
    total = len(entries)
    if total > MAX_TRANSCRIPT_ENTRIES:
        shown = entries[:TRANSCRIPT_HEAD] + [("…", "", f"[{total - TRANSCRIPT_HEAD - TRANSCRIPT_TAIL} entries omitted]")] + entries[-TRANSCRIPT_TAIL:]
    else:
        shown = entries
    for tag, ts, text in shown:
        stamp = f" @ {ts}" if ts else ""
        lines.append(f"## {tag}{stamp}")
        lines.append("")
        lines.append(text)
        lines.append("")
    return "\n".join(lines)


def load_session(row, known_names, include_subagents: bool):
    path = Path(row.get("file") or "")
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    records = doc.get("records") or []
    prompt = first_user_prompt(records)
    helper = bool(HELPER_PROMPT_RE.match(prompt))
    if helper and not include_subagents:
        return None
    skills_used, skills_unknown = detect_skills(records, known_names)
    tool_calls = sum(len(r.get("tool_calls") or []) for r in records)
    tool_errors = sum(1 for r in records if r.get("role") == "tool" and r.get("ok") is False)
    start = parse_ts(row.get("firstTimestamp"))
    end = parse_ts(row.get("lastTimestamp"))
    duration = round((end - start).total_seconds() / 60, 1) if start and end else None
    counts = row.get("roleCounts") or {}
    meta = {
        "id": row.get("id"),
        "source": row.get("source"),
        "file": str(path),
        "cwd": row.get("cwd"),
        "git_branch": row.get("gitBranch"),
        "model": row.get("model"),
        "started": row.get("firstTimestamp"),
        "ended": row.get("lastTimestamp"),
        "duration_min": duration,
        "user_turns": counts.get("user", 0),
        "assistant_turns": counts.get("assistant", 0),
        "tool_calls": tool_calls,
        "tool_errors": tool_errors,
        "code_edits": has_code_edits(records),
        "skills_used": skills_used,
        "skills_unknown": skills_unknown,
        "helper_prompt": helper,
        "first_prompt": truncate(prompt, 200),
    }
    return meta, records


def sample_sessions(sessions, max_sessions, per_skill, no_skill):
    """Newest-first sampling: cap per skill, cap skill-less, fill remaining."""
    sessions = sorted(sessions, key=lambda s: s["ended"] or "", reverse=True)
    per_skill_count = {}
    no_skill_count = 0
    chosen = []
    deferred = []
    for s in sessions:
        if len(chosen) >= max_sessions:
            break
        if s["skills_used"]:
            slots = [n for n in s["skills_used"] if per_skill_count.get(n, 0) < per_skill]
            if slots:
                for n in s["skills_used"]:
                    per_skill_count[n] = per_skill_count.get(n, 0) + 1
                chosen.append(s)
                continue
        elif no_skill_count < no_skill:
            no_skill_count += 1
            chosen.append(s)
            continue
        deferred.append(s)
    for s in deferred:
        if len(chosen) >= max_sessions:
            break
        chosen.append(s)
    return chosen


def main(argv=None):
    args = parse_args(argv)
    root = Path(args.trajectories_root).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    transcripts_dir = out / "transcripts"
    transcripts_dir.mkdir(parents=True, exist_ok=True)

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    history = load_history(root)
    sources = set(args.source)

    recent = []
    for row in history:
        if sources and row.get("source") not in sources:
            continue
        ts = parse_ts(row.get("sourceUpdatedAt") or row.get("lastTimestamp"))
        if ts is None or ts < cutoff:
            continue
        if not args.include_subagents and is_subagent_source(row):
            continue
        counts = row.get("roleCounts") or {}
        if counts.get("assistant", 0) < args.min_assistant_turns or counts.get("user", 0) < 1:
            continue
        recent.append(row)

    if args.all_conversations:
        repos = []
        seen = set()
        for row in recent:
            cwd = row.get("cwd")
            if not cwd or not Path(cwd).is_dir():
                continue
            top = git_toplevel(Path(cwd))
            if top and top not in seen:
                seen.add(top)
                repos.append(top)
        scoped = recent
    else:
        repos = resolve_repos(args.repo)
        allowed = set()
        for repo in repos:
            allowed |= git_worktrees(repo)
        scoped = [row for row in recent if path_within(row.get("cwd"), allowed)]

    skills = discover_skills(repos, args.skills_dir, args.include_global_skills, Path(args.dotfiles_root).expanduser())
    known_names = set(skills)

    sessions = []
    loaded = {}
    for row in scoped:
        result = load_session(row, known_names, args.include_subagents)
        if result is None:
            continue
        meta, records = result
        sessions.append(meta)
        loaded[meta["file"]] = records

    sampled = sample_sessions(sessions, args.max_sessions, args.per_skill, args.no_skill)
    sampled_files = {s["file"] for s in sampled}
    for meta in sampled:
        entries = build_entries(loaded[meta["file"]])
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(meta["id"]))[:120]
        transcript_path = transcripts_dir / f"{meta['source']}--{safe_id}.md"
        transcript_path.write_text(render_transcript(meta, entries), encoding="utf-8")
        meta["transcript"] = str(transcript_path)

    skills_used = sorted({n for s in sampled for n in s["skills_used"]})
    sources_seen = sorted({s["source"] for s in sampled})
    inventory = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trajectories_root": str(root),
        "harness": sources_seen[0] if len(sources_seen) == 1 else "mixed",
        "sources": sources_seen,
        "repo_name": repos[0].name if len(repos) == 1 else ("all" if args.all_conversations else "multiple"),
        "repos": [str(r) for r in repos],
        "window_days": args.days,
        "sessions_in_history": len(history),
        "sessions_recent": len(recent),
        "sessions_scanned": len(sessions),
        "sessions_sampled": len(sampled),
        "skills_found": len(skills),
        "skills_used": len(skills_used),
        "skills_used_names": skills_used,
        "skills": sorted(skills.values(), key=lambda s: s["name"]),
        "sessions": [dict(s, sampled=s["file"] in sampled_files) for s in
                     sorted(sessions, key=lambda s: s["ended"] or "", reverse=True)],
    }
    (out / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")

    print(f"history rows: {len(history)}  recent: {len(recent)}  in scope: {len(sessions)}  sampled: {len(sampled)}")
    print(f"skills found: {len(skills)}  used in sample: {len(skills_used)}  sources: {', '.join(sources_seen) or 'none'}")
    print(f"inventory: {out / 'inventory.json'}")
    print(f"transcripts: {transcripts_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
