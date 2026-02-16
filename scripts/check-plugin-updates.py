#!/usr/bin/env python3
"""
Check vendored plugins for upstream updates.

Reads plugins.toml, compares pinned commit SHAs against the latest
commit on each upstream repo's default branch.

With --create-prs flag (for CI), creates individual pull requests
for each plugin that has updates available.

Requires Python 3.11+ (uses tomllib from stdlib).

Environment variables:
    GH_TOKEN - GitHub token for API authentication (optional for check, required for PRs)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import json
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("Error: Python 3.11+ required (for tomllib)")

import tomllib

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "plugins.toml"
PLUGINS_DIR = ROOT / "plugins"


def plugin_dir_name(name: str) -> str:
    return name.replace("/", "-")


def get_latest_commit(owner_repo: str, token: str | None = None) -> str | None:
    """Get the latest commit SHA on the default branch of a GitHub repo."""
    url = f"https://api.github.com/repos/{owner_repo}/commits?per_page=1"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            if data and isinstance(data, list):
                return data[0]["sha"]
    except urllib.error.HTTPError as e:
        print(f"  Warning: Failed to check {owner_repo}: HTTP {e.code}")
    except Exception as e:
        print(f"  Warning: Failed to check {owner_repo}: {e}")

    return None


def run(cmd: list[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kwargs)


def set_github_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def update_commit_in_toml(plugin_name: str, new_commit: str) -> None:
    """Update the commit SHA for a plugin in plugins.toml."""
    content = CONFIG_FILE.read_text()
    escaped = re.escape(plugin_name)
    pattern = rf'(\["{escaped}"\][^\[]*?commit\s*=\s*")[a-f0-9]+(")'
    new_content = re.sub(pattern, rf"\g<1>{new_commit}\2", content, flags=re.DOTALL)
    CONFIG_FILE.write_text(new_content)


def create_pr(plugin_name: str, old_commit: str, new_commit: str) -> None:
    """Create a PR to update a single plugin."""
    dir_name = plugin_dir_name(plugin_name)
    branch = f"plugin-update/{dir_name}"

    # Check if a PR already exists
    result = run(
        ["gh", "pr", "list", "--head", branch, "--state", "open", "--json", "number"],
        check=False,
    )
    if result.returncode == 0:
        prs = json.loads(result.stdout)
        if prs:
            print(f"  PR #{prs[0]['number']} already exists for {plugin_name}, skipping")
            return

    # Configure git
    run(["git", "config", "user.name", "github-actions[bot]"])
    run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"])

    # Create branch
    run(["git", "checkout", "-B", branch, "HEAD"])

    # Replace vendored plugin
    dest = PLUGINS_DIR / dir_name
    if dest.exists():
        shutil.rmtree(dest)

    run(["git", "clone", "--depth", "1", f"https://github.com/{plugin_name}.git", str(dest)])
    git_dir = dest / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)

    # Update commit in plugins.toml
    update_commit_in_toml(plugin_name, new_commit)

    # Commit and push
    run(["git", "add", str(dest), str(CONFIG_FILE)])
    run(["git", "commit", "-m", f"Update {plugin_name} plugin to {new_commit[:12]}"])
    run(["git", "push", "-u", "origin", branch, "--force"])

    # Create PR
    compare_url = f"https://github.com/{plugin_name}/compare/{old_commit[:12]}...{new_commit[:12]}"
    body = (
        f"Automated update for **{plugin_name}** plugin.\n\n"
        f"**New commit:** `{new_commit}`\n"
        f"**Compare:** [{old_commit[:12]}...{new_commit[:12]}]({compare_url})\n\n"
        f"---\n"
        f"*Created by the [plugin-updates](.github/workflows/plugin-updates.yml) workflow.*"
    )

    run([
        "gh", "pr", "create",
        "--title", f"Update plugin: {plugin_name}",
        "--body", body,
        "--head", branch,
        "--base", "main",
    ])

    print(f"  Created PR for {plugin_name}")

    # Return to original branch
    run(["git", "checkout", "-"])


def main():
    parser = argparse.ArgumentParser(description="Check plugins for upstream updates")
    parser.add_argument(
        "--create-prs",
        action="store_true",
        help="Create pull requests for available updates (CI mode)",
    )
    args = parser.parse_args()

    if not CONFIG_FILE.exists():
        sys.exit(f"Error: {CONFIG_FILE} not found")

    with open(CONFIG_FILE, "rb") as f:
        config = tomllib.load(f)

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    updates = []

    print("Checking plugins for upstream updates...")

    for plugin_name, plugin_config in config.items():
        pinned_commit = plugin_config.get("commit")
        if not pinned_commit:
            print(f"  {plugin_name}: no commit pinned, skipping")
            continue

        latest = get_latest_commit(plugin_name, token)
        if latest is None:
            continue

        if latest != pinned_commit:
            print(f"  {plugin_name}: update available {pinned_commit[:12]} -> {latest[:12]}")
            updates.append((plugin_name, pinned_commit, latest))
        else:
            print(f"  {plugin_name}: up to date ({pinned_commit[:12]})")

    if not updates:
        print("\nAll plugins are up to date")
        set_github_output("updates_available", "false")
        return

    print(f"\n{len(updates)} plugin(s) have updates available")
    set_github_output("updates_available", "true")

    if args.create_prs:
        print("\nCreating pull requests...")
        for plugin_name, old_commit, new_commit in updates:
            try:
                create_pr(plugin_name, old_commit, new_commit)
            except Exception as e:
                print(f"  Error creating PR for {plugin_name}: {e}")


if __name__ == "__main__":
    main()
