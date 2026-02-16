#!/usr/bin/env python3
"""
Build system for AI agent plugins.

Reads plugins.toml and builds/installs skills for
Claude Code, Codex CLI, OpenCode, and Pi Agent.

OpenCode, Pi, and Codex all read from ~/.agents/skills.
Claude Code reads from ~/.claude/skills.

Requires Python 3.11+ (uses tomllib from stdlib).
"""

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("Error: Python 3.11+ required (for tomllib)")

import tomllib

# Directories
ROOT = Path(__file__).parent.parent
PLUGINS_DIR = ROOT / "plugins"
SKILLS_DIR = ROOT / "skills"
BUILD_DIR = ROOT / "build"
CONFIG_FILE = ROOT / "plugins.toml"
CONFIGS_DIR = ROOT / "configs"
GLOBAL_AGENTS_MD = CONFIGS_DIR / "AGENTS.md"

# Installation paths
HOME = Path.home()
UNIFIED_SKILLS_PATH = HOME / ".agents" / "skills"

INSTALL_PATHS = {
    "claude": HOME / ".claude" / "skills",
    "unified": UNIFIED_SKILLS_PATH,  # opencode, pi, codex
}


def remove_path(path: Path) -> None:
    """Remove a path, handling both symlinks and directories."""
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def plugin_dir_name(name: str) -> str:
    """Convert plugin name (owner/repo) to directory name (owner-repo)."""
    return name.replace("/", "-")


@dataclass
class Plugin:
    """Configuration for a single plugin."""

    name: str  # Fully qualified name: owner/repo
    url: str
    skills_path: list[str] = field(default_factory=lambda: ["skills/*"])
    skills: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    alias: str | None = None

    @property
    def dir_name(self) -> str:
        """Directory name for this plugin (owner-repo format)."""
        return plugin_dir_name(self.name)

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "Plugin":
        """Create Plugin from TOML dictionary."""

        def normalize_path(p) -> list[str]:
            if p is None:
                return []
            if isinstance(p, str):
                return [p]
            return list(p)

        def normalize_items(items) -> list[str]:
            """Normalize item list: missing key -> empty list, string -> list."""
            if items is None:
                return []
            if isinstance(items, str):
                return [items]
            return list(items)

        return cls(
            name=name,
            url=data["url"],
            skills_path=normalize_path(data.get("skills_path", "skills/*")),
            skills=normalize_items(data.get("skills")),
            alias=data.get("alias"),
        )


def load_config() -> dict[str, Plugin]:
    """Load and parse plugins.toml."""
    if not CONFIG_FILE.exists():
        sys.exit(f"Error: {CONFIG_FILE} not found")

    with open(CONFIG_FILE, "rb") as f:
        data = tomllib.load(f)

    return {name: Plugin.from_dict(name, cfg) for name, cfg in data.items()}


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command."""
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def init_submodules():
    """Initialize git submodules."""
    print("Initializing git submodules...")
    run_cmd(["git", "submodule", "update", "--init", "--recursive"])
    print("  Done")


def glob_paths(base: Path, patterns: list[str]) -> list[Path]:
    """Find all paths matching glob patterns."""
    results = []
    for pattern in patterns:
        if pattern == ".":
            results.append(base)
        elif "**" in pattern:
            results.extend(base.glob(pattern))
        else:
            results.extend(base.glob(pattern))
    return sorted(set(results))


def discover_skills(plugin: Plugin) -> list[tuple[str, Path]]:
    """
    Discover skills from a plugin.

    Returns list of (skill_name, skill_path) tuples.
    """
    plugin_dir = PLUGINS_DIR / plugin.dir_name
    if not plugin_dir.exists():
        return []

    if len(plugin.skills) == 0:
        return []

    include_all = "*" in plugin.skills

    items = []
    for path in glob_paths(plugin_dir, plugin.skills_path):
        if not path.is_dir():
            continue

        name = path.name
        if not include_all and name not in plugin.skills:
            continue

        final_name = f"{plugin.alias}-{name}" if plugin.alias else name
        items.append((final_name, path))

    return items


def fix_skill_frontmatter_name(content: str, expected_name: str) -> str:
    """
    Fix the 'name' field in SKILL.md frontmatter to match the directory name.
    """
    import re

    frontmatter_pattern = r"^---\s*\n(.*?)\n---"
    match = re.match(frontmatter_pattern, content, re.DOTALL)
    if not match:
        return content

    frontmatter = match.group(1)

    name_pattern = r"^name:\s*(.+)$"
    name_match = re.search(name_pattern, frontmatter, re.MULTILINE)
    if not name_match:
        return content

    current_name = name_match.group(1).strip().strip("\"'")
    if current_name == expected_name:
        return content

    new_frontmatter = re.sub(
        name_pattern, f"name: {expected_name}", frontmatter, flags=re.MULTILINE
    )

    return content[: match.start(1)] + new_frontmatter + content[match.end(1) :]


def build_skill(name: str, source: Path) -> bool:
    """
    Build a skill.

    Returns:
        True if built successfully
        False if skipped due to missing SKILL.md
    """
    skill_md = source / "SKILL.md"
    if not skill_md.exists():
        print(f"    Warning: {source} has no SKILL.md, skipping")
        return False

    raw_content = skill_md.read_text()

    dest = BUILD_DIR / "skills" / name
    dest.mkdir(parents=True, exist_ok=True)

    dest_skill_md = dest / "SKILL.md"
    skill_content = fix_skill_frontmatter_name(raw_content, name)

    with open(dest_skill_md, "w") as out:
        out.write(skill_content)

    # Copy additional files
    for item in source.iterdir():
        if item.name != "SKILL.md":
            dest_item = dest / item.name
            if item.is_dir():
                shutil.copytree(item, dest_item, dirs_exist_ok=True)
            else:
                shutil.copy(item, dest_item)

    return True


def build_skills(plugins: dict[str, Plugin]):
    """Build all skills from plugins and custom skills directory."""
    print("Building skills...")

    # Clean build directory
    skills_build = BUILD_DIR / "skills"
    if skills_build.exists():
        shutil.rmtree(skills_build)
    skills_build.mkdir(parents=True)

    built = set()

    # Process plugins
    for plugin in plugins.values():
        for name, path in discover_skills(plugin):
            if name in built:
                print(
                    f"    Warning: Skill '{name}' already exists, skipping duplicate from {plugin.name}"
                )
                continue
            if build_skill(name, path):
                print(f"  {name} (from {plugin.name})")
                built.add(name)

    # Process custom skills
    if SKILLS_DIR.exists():
        for skill_dir in sorted(SKILLS_DIR.iterdir()):
            if skill_dir.is_dir():
                name = skill_dir.name
                if name in built:
                    print(
                        f"    Warning: Custom skill '{name}' conflicts with plugin skill"
                    )
                if build_skill(name, skill_dir):
                    print(f"  {name} (custom)")
                    built.add(name)

    print(f"  Built {len(built)} skills")


def install_skills():
    """Install built skills to agent directories."""
    print("Installing skills...")

    source = BUILD_DIR / "skills"
    if not source.exists():
        print("  No skills built, run 'make build' first")
        return

    for name, dest in INSTALL_PATHS.items():
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)

        count = 0
        for skill_dir in sorted(source.iterdir()):
            if skill_dir.is_dir():
                dest_skill = dest / skill_dir.name
                shutil.copytree(skill_dir, dest_skill)
                count += 1

        print(f"  {name}: {count} skills -> {dest}")


def install_global_agents_md():
    """Install global AGENTS.md for unified agents path."""
    print("Installing global AGENTS.md...")

    if not GLOBAL_AGENTS_MD.exists():
        print("  No AGENTS.md found in configs/, skipping")
        return

    dest = HOME / ".agents" / "AGENTS.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(GLOBAL_AGENTS_MD, dest)
    print(f"  Installed to {dest}")


def clean(plugins: dict[str, Plugin]):
    """Remove all installed artifacts."""
    print("Cleaning installed artifacts...")

    # Clean skills from all install paths
    for name, path in INSTALL_PATHS.items():
        if path.exists():
            shutil.rmtree(path)
            print(f"  Removed {path}")

    # Clean build directory
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
        print("  Removed build directory")

    # Clean global AGENTS.md
    agents_md_path = HOME / ".agents" / "AGENTS.md"
    if agents_md_path.exists():
        agents_md_path.unlink()
        print(f"  Removed {agents_md_path}")

    print("  Done")


def main():
    parser = argparse.ArgumentParser(description="Build and install AI agent plugins")
    parser.add_argument(
        "command",
        choices=[
            "build",
            "install",
            "install-skills",
            "clean",
            "submodule-init",
        ],
        help="Command to run",
    )
    args = parser.parse_args()

    plugins = load_config()

    if args.command == "submodule-init":
        init_submodules()
    elif args.command == "build":
        build_skills(plugins)
    elif args.command == "install":
        init_submodules()
        build_skills(plugins)
        install_skills()
        install_global_agents_md()
        print("\nAll done!")
    elif args.command == "install-skills":
        build_skills(plugins)
        install_skills()
    elif args.command == "clean":
        clean(plugins)


if __name__ == "__main__":
    main()
