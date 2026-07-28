#!/usr/bin/env python3
"""
Bridge the Vercel skills CLI (npx skills) with this repo's skills/ tree.

The skills CLI installs project skills into .agents/skills/ and records them in
skills-lock.json. This script vendors those staged copies into skills/ so the
existing build/install pipeline can distribute them to agent home directories.

Commands:
  vendor  Copy locked skills from .agents/skills/ into skills/
  add     Run npx skills add, then vendor
  update  Run npx skills update (project scope), then vendor
  sync    Restore from skills-lock.json via experimental_install, then vendor

Environment:
  SKILL_LOCK_ROOT  Override repo root (tests / sandboxes)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ.get("SKILL_LOCK_ROOT") or Path(__file__).resolve().parent.parent)
LOCK_FILE = ROOT / "skills-lock.json"
STAGING_DIR = ROOT / ".agents" / "skills"
SKILLS_DIR = ROOT / "skills"
LOCK_VERSION = 1


def die(message: str, code: int = 1) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(code)


def load_lock() -> dict:
    if not LOCK_FILE.exists():
        return {"version": LOCK_VERSION, "skills": {}}
    try:
        data = json.loads(LOCK_FILE.read_text())
    except json.JSONDecodeError as exc:
        die(f"invalid skills-lock.json: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("skills"), dict):
        die("skills-lock.json must be an object with a skills map")
    return data


def skill_names(lock: dict) -> list[str]:
    return sorted(lock.get("skills", {}))


def validate_skill_name(name: str) -> str:
    if (
        not name
        or name in (".", "..")
        or Path(name).name != name
        or "/" in name
        or "\\" in name
    ):
        die(f"unsafe skill name in lockfile: {name!r}")
    return name


def run_skills(args: list[str]) -> None:
    cmd = ["npx", "--yes", "skills", *args]
    print(f"+ {' '.join(cmd)}", flush=True)
    try:
        subprocess.run(cmd, cwd=ROOT, check=True)
    except FileNotFoundError:
        die("npx not found; install Node.js to use the skills CLI")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def vendor_skill(name: str) -> bool:
    """Copy one staged skill into skills/. Returns True if vendored."""
    name = validate_skill_name(name)
    source = STAGING_DIR / name
    dest = SKILLS_DIR / name

    if not source.is_dir():
        print(f"  skip {name}: not staged at {source.relative_to(ROOT)}")
        return False

    skill_md = source / "SKILL.md"
    if not skill_md.is_file():
        # Some skills nest SKILL.md one level deeper; accept any SKILL.md.
        if not any(source.rglob("SKILL.md")):
            print(f"  skip {name}: no SKILL.md under staging copy")
            return False

    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    shutil.copytree(source, dest, symlinks=False)
    print(f"  vendored {name} -> skills/{name}/")
    return True


def cmd_vendor(_args: argparse.Namespace) -> None:
    lock = load_lock()
    names = skill_names(lock)
    if not names:
        print("No skills in skills-lock.json")
        print("Add one with: make skill-add SOURCE=owner/repo")
        return

    print(f"Vendoring {len(names)} locked skill(s) from .agents/skills/ -> skills/")
    vendored = 0
    for name in names:
        if vendor_skill(name):
            vendored += 1

    if vendored == 0:
        die(
            "no staged skills found under .agents/skills/. "
            "Run: make skill-sync   # or make skill-add SOURCE=..."
        )
    print(f"Done: vendored {vendored}/{len(names)} skill(s)")


def cmd_add(args: argparse.Namespace) -> None:
    if not args.source:
        die("SOURCE is required (e.g. github/gh-stack or owner/repo)")

    add_args = [
        "add",
        args.source,
        "--agent",
        "universal",
        "--copy",
        "-y",
    ]
    if args.skill:
        for skill in args.skill:
            add_args.extend(["--skill", skill])
    elif args.all_skills:
        add_args.extend(["--skill", "*"])

    run_skills(add_args)
    cmd_vendor(args)


def cmd_update(args: argparse.Namespace) -> None:
    lock = load_lock()
    if not skill_names(lock):
        die("skills-lock.json has no skills to update")

    update_args = ["update", "-p", "-y"]
    if args.skill:
        update_args.extend(args.skill)
    run_skills(update_args)
    cmd_vendor(args)


def cmd_sync(args: argparse.Namespace) -> None:
    lock = load_lock()
    if not skill_names(lock):
        die("skills-lock.json has no skills to restore")

    run_skills(["experimental_install"])
    cmd_vendor(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Vendor skills-CLI packages into skills/ for this repo's install pipeline",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_vendor = sub.add_parser(
        "vendor",
        help="Copy locked skills from .agents/skills/ into skills/",
    )
    p_vendor.set_defaults(func=cmd_vendor)

    p_add = sub.add_parser(
        "add",
        help="npx skills add <source>, then vendor into skills/",
    )
    p_add.add_argument("source", help="Package source (e.g. github/gh-stack)")
    p_add.add_argument(
        "--skill",
        action="append",
        default=[],
        help="Skill name to install (repeatable). Omit to let the CLI choose.",
    )
    p_add.add_argument(
        "--all-skills",
        action="store_true",
        help="Install all skills from the source package",
    )
    p_add.set_defaults(func=cmd_add)

    p_update = sub.add_parser(
        "update",
        help="npx skills update (project), then re-vendor",
    )
    p_update.add_argument(
        "skill",
        nargs="*",
        help="Optional skill names to update (default: all project skills)",
    )
    p_update.set_defaults(func=cmd_update)

    p_sync = sub.add_parser(
        "sync",
        help="Restore from skills-lock.json, then vendor into skills/",
    )
    p_sync.set_defaults(func=cmd_sync)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
