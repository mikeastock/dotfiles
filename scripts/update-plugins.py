#!/usr/bin/env python3
"""
Update vendored plugins to their latest upstream commits.

Reads plugins.toml, clones each plugin at the latest commit,
replaces the vendored directory, and updates the commit SHA.

Requires Python 3.11+ (uses tomllib from stdlib).
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("Error: Python 3.11+ required (for tomllib)")

import tomllib

ROOT = Path(__file__).parent.parent
PLUGINS_DIR = ROOT / "plugins"
CONFIG_FILE = ROOT / "plugins.toml"


def plugin_dir_name(name: str) -> str:
    """Convert plugin name (owner/repo) to directory name (owner-repo)."""
    return name.replace("/", "-")


def get_latest_commit(url: str) -> str | None:
    """Get the latest commit SHA from a git remote."""
    try:
        result = subprocess.run(
            ["git", "ls-remote", url, "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            return result.stdout.strip().split()[0]
    except subprocess.CalledProcessError as e:
        print(f"  Warning: git ls-remote failed for {url}: {e.stderr.strip()}")
    return None


def update_plugin(name: str, url: str, current_commit: str | None) -> str | None:
    """
    Update a single vendored plugin.

    Returns the new commit SHA if updated, None if no update needed.
    """
    latest = get_latest_commit(url)
    if latest is None:
        print(f"  {name}: could not determine latest commit, skipping")
        return None

    if latest == current_commit:
        print(f"  {name}: up to date ({latest[:12]})")
        return None

    old = current_commit[:12] if current_commit else "none"
    print(f"  {name}: updating {old} -> {latest[:12]}")

    dir_name = plugin_dir_name(name)
    dest = PLUGINS_DIR / dir_name

    # Clone into temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        clone_dest = Path(tmpdir) / dir_name
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(clone_dest)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"    Error cloning: {result.stderr.strip()}")
            return None

        # Remove .git directory
        git_dir = clone_dest / ".git"
        if git_dir.exists():
            shutil.rmtree(git_dir)

        # Replace vendored directory
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(clone_dest, dest)

    return latest


def update_config_commit(plugin_name: str, new_commit: str) -> None:
    """Update the commit SHA for a plugin in plugins.toml."""
    content = CONFIG_FILE.read_text()

    # Escape the plugin name for regex (handle forward slashes)
    escaped_name = re.escape(plugin_name)

    # Find the plugin section and update or add commit field
    # Match: ["owner/repo"] ... commit = "sha" (within the section)
    section_pattern = rf'(\["{escaped_name}"\][^\[]*?)commit\s*=\s*"[a-f0-9]+"'
    if re.search(section_pattern, content, re.DOTALL):
        # Update existing commit
        new_content = re.sub(
            section_pattern,
            rf'\g<1>commit = "{new_commit}"',
            content,
            flags=re.DOTALL,
        )
    else:
        # Add commit after url line
        url_pattern = rf'(\["{escaped_name}"\]\nurl\s*=\s*"[^"]+"\n)'
        new_content = re.sub(
            url_pattern,
            rf'\g<1>commit = "{new_commit}"\n',
            content,
        )

    CONFIG_FILE.write_text(new_content)


def main():
    if not CONFIG_FILE.exists():
        sys.exit(f"Error: {CONFIG_FILE} not found")

    with open(CONFIG_FILE, "rb") as f:
        config = tomllib.load(f)

    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)

    print("Updating vendored plugins...")
    updated = 0

    for plugin_name, plugin_config in config.items():
        url = plugin_config["url"]
        current_commit = plugin_config.get("commit")

        new_commit = update_plugin(plugin_name, url, current_commit)
        if new_commit:
            update_config_commit(plugin_name, new_commit)
            updated += 1

    if updated:
        print(f"\n{updated} plugin(s) updated. Run 'make install' to rebuild.")
    else:
        print("\nAll plugins are up to date.")


if __name__ == "__main__":
    main()
