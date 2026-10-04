#!/usr/bin/env python3
"""Merge upstream pstack changes into the Pi port with per-file three-way merges.

The Pi port lives in skills/<name>/ and pi-extensions/pstack/agents/. The upstream commit it was
last synced to is recorded in pi-extensions/pstack/UPSTREAM. For every vendored file this merges
upstream's change between that commit and the new ref into our copy (`git merge-file`), leaving
conflict markers where both sides changed the same lines. It never touches files we don't vendor,
and only lists new upstream skills instead of adding them.

Usage: scripts/pstack_upstream.py <new-ref> [--repo <cursor/plugins clone>]
"""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM_FILE = ROOT / "pi-extensions" / "pstack" / "UPSTREAM"
UPSTREAM_URL = "https://github.com/cursor/plugins"
# Upstream skills this repo deliberately does not vendor (collisions or Cursor-only).
NOT_VENDORED = {"bro", "unslop", "teach", "make-bot-ui"}
# Text that has no meaning in Pi. New upstream prose containing it needs a Pi rewrite.
CURSORISMS = re.compile(
    r"subagent_type|run_in_background|generalPurpose|AskQuestion|TodoWrite|cursor-team-kit|\.cursor/|"
    r"agent-transcripts|environment: \"cloud\"|`/loop`|\bTask\b(?! as)|"
    r"claude-opus-[\w.-]+-(?:max|xhigh|high|medium)\b|gpt-[\d.]+-\w+-(?:max|xhigh|high|medium)\b|grok-[\d.]+-\w+-fast\b"
)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def tree(repo: Path, ref: str, prefix: str) -> set[str]:
    out = git(repo, "ls-tree", "-r", "--name-only", ref, "--", prefix)
    return {line[len(prefix) :] for line in out.splitlines()}


def blob(repo: Path, ref: str, path: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "show", f"{ref}:{path}"], check=True, capture_output=True).stdout


def mappings(repo: Path, base: str) -> list[tuple[str, Path]]:
    """(upstream directory prefix, our directory) pairs for everything we vendor."""
    skills = {path.split("/", 1)[0] for path in tree(repo, base, "pstack/skills/")}
    pairs = [
        (f"pstack/skills/{name}/", ROOT / "skills" / name)
        for name in sorted(skills - NOT_VENDORED)
        if (ROOT / "skills" / name).is_dir()
    ]
    pairs.append(("pstack/agents/", ROOT / "pi-extensions" / "pstack" / "agents"))
    return pairs


def merge(repo: Path, base: str, new: str) -> int:
    conflicts: list[Path] = []
    changed: list[Path] = []
    notes: list[str] = []

    for prefix, ours_dir in mappings(repo, base):
        before, after = tree(repo, base, prefix), tree(repo, new, prefix)
        for rel in sorted(before | after):
            ours = ours_dir / rel
            if rel in before and rel in after:
                old_blob, new_blob = blob(repo, base, prefix + rel), blob(repo, new, prefix + rel)
                if old_blob == new_blob:
                    continue
                if not ours.exists():
                    notes.append(f"skipped {ours.relative_to(ROOT)}: changed upstream but removed here")
                    continue
                with tempfile.TemporaryDirectory() as tmp:
                    base_file, new_file = Path(tmp, "base"), Path(tmp, "upstream")
                    base_file.write_bytes(old_blob)
                    new_file.write_bytes(new_blob)
                    result = subprocess.run(
                        ["git", "merge-file", "-L", "ours", "-L", "base", "-L", "upstream", str(ours), str(base_file), str(new_file)]
                    )
                changed.append(ours)
                if result.returncode != 0:
                    conflicts.append(ours)
            elif rel in after:
                if ours.exists():
                    conflicts.append(ours)
                    notes.append(f"conflict {ours.relative_to(ROOT)}: added upstream and exists here")
                    continue
                ours.parent.mkdir(parents=True, exist_ok=True)
                ours.write_bytes(blob(repo, new, prefix + rel))
                changed.append(ours)
                notes.append(f"added {ours.relative_to(ROOT)}")
            elif ours.exists():
                if ours.read_bytes() == blob(repo, base, prefix + rel):
                    ours.unlink()
                    notes.append(f"deleted {ours.relative_to(ROOT)}")
                else:
                    notes.append(f"kept {ours.relative_to(ROOT)}: deleted upstream but edited here")

    new_skills = {path.split("/", 1)[0] for path in tree(repo, new, "pstack/skills/")} - {
        path.split("/", 1)[0] for path in tree(repo, base, "pstack/skills/")
    }
    for name in sorted(new_skills - NOT_VENDORED):
        notes.append(f"new upstream skill not vendored: {name} (copy and port it by hand if wanted)")

    for note in notes:
        print(note)
    for path in changed:
        if path.suffix == ".md":
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if CURSORISMS.search(line):
                    print(f"needs Pi port {path.relative_to(ROOT)}:{number}: {line.strip()[:120]}")

    UPSTREAM_FILE.write_text(git(repo, "rev-parse", new).strip() + "\n")
    print(f"merged {len(changed)} file(s); {len(conflicts)} with conflicts")
    for path in conflicts:
        print(f"CONFLICT {path.relative_to(ROOT)}")
    return 1 if conflicts else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ref", help="upstream ref to merge, e.g. origin/main or a commit")
    parser.add_argument("--repo", type=Path, help="existing cursor/plugins clone (default: fresh clone)")
    args = parser.parse_args()
    base = UPSTREAM_FILE.read_text().strip()

    if args.repo:
        return merge(args.repo, base, args.ref)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", UPSTREAM_URL, tmp], check=True)
        return merge(Path(tmp), base, args.ref)


if __name__ == "__main__":
    sys.exit(main())
