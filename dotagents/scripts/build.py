#!/usr/bin/env python3
"""
Build system for AI agent plugins.

Reads plugins.toml and builds/installs skills and extensions for
Claude Code, Codex CLI, and Pi Agent.

Requires Python 3.11+ (uses tomllib from stdlib).
"""

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path


def remove_path(path: Path) -> None:
    """Remove a path, handling both symlinks and directories."""
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)

if sys.version_info < (3, 11):
    sys.exit("Error: Python 3.11+ required (for tomllib)")

import tomllib

# Directories
ROOT = Path(__file__).parent.parent
PLUGINS_DIR = ROOT / "plugins"
SKILLS_DIR = ROOT / "skills"
COMMANDS_DIR = ROOT / "commands"
EXTENSIONS_DIR = ROOT / "extensions"
OVERRIDES_DIR = ROOT / "skill-overrides"
BUILD_DIR = ROOT / "build"
CONFIG_FILE = ROOT / "plugins.toml"

# Installation paths
HOME = Path.home()
INSTALL_PATHS = {
    "claude": {
        "skills": HOME / ".claude" / "skills",
        "commands": HOME / ".claude" / "commands",
    },
    "codex": {
        "skills": HOME / ".codex" / "skills",
        "commands": HOME / ".codex" / "commands",
    },
    "pi": {
        "skills": HOME / ".pi" / "agent" / "skills",
        "prompts": HOME / ".pi" / "agent" / "prompts",
        "extensions": HOME / ".pi" / "agent" / "extensions",
    },
}

AGENTS = ["claude", "codex", "pi"]  # Agents that get skill builds


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
    extensions_path: list[str] = field(default_factory=lambda: ["extensions/*.ts"])
    extensions: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
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
            extensions_path=normalize_path(data.get("extensions_path", "extensions/*.ts")),
            extensions=normalize_items(data.get("extensions")),
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
        # Special case: "." means the base directory itself (for root-level extensions)
        if pattern == ".":
            results.append(base)
        # Handle ** patterns
        elif "**" in pattern:
            results.extend(base.glob(pattern))
        else:
            # For patterns like "skills/*", we want directories
            results.extend(base.glob(pattern))
    return sorted(set(results))


def discover_items(plugin: Plugin, item_type: str) -> list[tuple[str, Path]]:
    """
    Discover skills/extensions from a plugin.

    Returns list of (item_name, item_path) tuples.

    The enabled list controls which items are included:
    - Empty list [] = no items
    - ["*"] = all items (wildcard)
    - ["item1", "item2"] = only specified items
    """
    plugin_dir = PLUGINS_DIR / plugin.dir_name
    if not plugin_dir.exists():
        return []

    if item_type == "skills":
        patterns = plugin.skills_path
        enabled = plugin.skills
    elif item_type == "extensions":
        patterns = plugin.extensions_path
        enabled = plugin.extensions
    else:
        raise ValueError(f"Unknown item type: {item_type}")

    # Empty list means nothing enabled
    if len(enabled) == 0:
        return []

    # Check for wildcard (all items)
    include_all = "*" in enabled

    items = []
    for path in glob_paths(plugin_dir, patterns):
        if path.is_dir():
            name = path.name
        elif path.is_file() and path.suffix == ".ts":
            name = path.stem
        else:
            continue

        # Apply filter: include if wildcard or name is in enabled list
        if not include_all and name not in enabled:
            continue

        # Apply alias prefix if specified
        final_name = f"{plugin.alias}-{name}" if plugin.alias else name
        items.append((final_name, path))

    return items


def build_skill(name: str, source: Path, agent: str):
    """Build a skill for a specific agent."""
    dest = BUILD_DIR / agent / name
    dest.mkdir(parents=True, exist_ok=True)

    # Find SKILL.md
    skill_md = source / "SKILL.md"
    if not skill_md.exists():
        print(f"    Warning: {source} has no SKILL.md, skipping")
        return False

    # Check for override
    override = OVERRIDES_DIR / f"{name}-{agent}.md"
    dest_skill_md = dest / "SKILL.md"

    if override.exists():
        # Concatenate original + override
        with open(dest_skill_md, "w") as out:
            out.write(skill_md.read_text())
            out.write("\n")
            out.write(override.read_text())
    else:
        shutil.copy(skill_md, dest_skill_md)

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
    for agent in AGENTS:
        agent_dir = BUILD_DIR / agent
        if agent_dir.exists():
            shutil.rmtree(agent_dir)
        agent_dir.mkdir(parents=True)

    built = set()

    # Process plugins
    for plugin in plugins.values():
        for name, path in discover_items(plugin, "skills"):
            if name in built:
                print(f"    Warning: Skill '{name}' already exists, skipping duplicate from {plugin.name}")
                continue
            for agent in AGENTS:
                if build_skill(name, path, agent):
                    if agent == AGENTS[0]:  # Only print once
                        print(f"  {name} (from {plugin.name})")
                    built.add(name)

    # Process custom skills
    if SKILLS_DIR.exists():
        for skill_dir in sorted(SKILLS_DIR.iterdir()):
            if skill_dir.is_dir():
                name = skill_dir.name
                if name in built:
                    print(f"    Warning: Custom skill '{name}' conflicts with plugin skill")
                for agent in AGENTS:
                    if build_skill(name, skill_dir, agent):
                        if agent == AGENTS[0]:
                            print(f"  {name} (custom)")
                        built.add(name)

    print(f"  Built {len(built)} skills")


def install_skills():
    """Install built skills to agent directories."""
    print("Installing skills...")

    for agent, paths in INSTALL_PATHS.items():
        if "skills" not in paths:
            continue

        # Each agent uses its own build directory
        source = BUILD_DIR / agent

        if not source.exists():
            continue

        dest = paths["skills"]
        dest.mkdir(parents=True, exist_ok=True)

        count = 0
        for skill_dir in sorted(source.iterdir()):
            if skill_dir.is_dir():
                dest_skill = dest / skill_dir.name
                remove_path(dest_skill)
                shutil.copytree(skill_dir, dest_skill)
                count += 1

        print(f"  {agent}: {count} skills -> {dest}")


def install_commands():
    """Install slash commands to agent directories."""
    print("Installing commands...")

    if not COMMANDS_DIR.exists():
        print("  No commands directory found, skipping")
        return

    for agent, paths in INSTALL_PATHS.items():
        # Claude/Codex use "commands", Pi uses "prompts" (same format)
        dest_key = "commands" if "commands" in paths else "prompts" if "prompts" in paths else None
        if not dest_key:
            continue

        dest = paths[dest_key]
        dest.mkdir(parents=True, exist_ok=True)

        count = 0
        for cmd_file in sorted(COMMANDS_DIR.iterdir()):
            if cmd_file.is_file() and cmd_file.suffix == ".md":
                dest_cmd = dest / cmd_file.name
                shutil.copy(cmd_file, dest_cmd)
                count += 1

        print(f"  {agent}: {count} commands -> {dest}")


def install_extensions(plugins: dict[str, Plugin]):
    """Install extensions from plugins and custom extensions directory."""
    print("Installing extensions...")

    dest = INSTALL_PATHS["pi"]["extensions"]
    dest.mkdir(parents=True, exist_ok=True)

    installed = set()

    # Extensions from plugins
    for plugin in plugins.values():
        for name, path in discover_items(plugin, "extensions"):
            if name in installed:
                print(f"    Warning: Extension '{name}' already exists, skipping duplicate from {plugin.name}")
                continue

            dest_ext = dest / name
            remove_path(dest_ext)
            dest_ext.mkdir(parents=True)

            # Extensions are .ts files, need to be wrapped in directory with index.ts
            if path.is_file():
                shutil.copy(path, dest_ext / "index.ts")
            else:
                shutil.copytree(path, dest_ext, dirs_exist_ok=True)

            print(f"  {name} (from {plugin.name})")
            installed.add(name)

    # Custom extensions
    custom_extensions = EXTENSIONS_DIR / "pi"
    if custom_extensions.exists():
        for ext_dir in sorted(custom_extensions.iterdir()):
            if ext_dir.is_dir():
                name = ext_dir.name
                if name in installed:
                    print(f"    Warning: Custom extension '{name}' conflicts with plugin extension")

                dest_ext = dest / name
                remove_path(dest_ext)
                shutil.copytree(ext_dir, dest_ext)

                print(f"  {name} (custom)")
                installed.add(name)

    print(f"  Installed {len(installed)} extensions to {dest}")


def clean(plugins: dict[str, Plugin]):
    """Remove all installed artifacts."""
    print("Cleaning installed artifacts...")

    # Clean skills from all agents
    for agent, paths in INSTALL_PATHS.items():
        if "skills" in paths:
            source = BUILD_DIR / agent
            if source.exists():
                for skill_dir in source.iterdir():
                    if skill_dir.is_dir():
                        installed = paths["skills"] / skill_dir.name
                        if installed.exists() or installed.is_symlink():
                            remove_path(installed)
                            print(f"  Removed skill: {skill_dir.name} from {agent}")

    # Clean commands from all agents (commands for Claude/Codex, prompts for Pi)
    if COMMANDS_DIR.exists():
        for agent, paths in INSTALL_PATHS.items():
            dest_key = "commands" if "commands" in paths else "prompts" if "prompts" in paths else None
            if not dest_key:
                continue
            for cmd_file in COMMANDS_DIR.iterdir():
                if cmd_file.is_file() and cmd_file.suffix == ".md":
                    installed = paths[dest_key] / cmd_file.name
                    if installed.exists():
                        installed.unlink()
                        print(f"  Removed command: {cmd_file.name} from {agent}")

    # Clean extensions
    ext_dest = INSTALL_PATHS["pi"]["extensions"]
    for plugin in plugins.values():
        for name, _ in discover_items(plugin, "extensions"):
            installed = ext_dest / name
            if installed.exists() or installed.is_symlink():
                remove_path(installed)
                print(f"  Removed extension: {name}")

    # Custom extensions
    custom_extensions = EXTENSIONS_DIR / "pi"
    if custom_extensions.exists():
        for ext_dir in custom_extensions.iterdir():
            if ext_dir.is_dir():
                installed = ext_dest / ext_dir.name
                if installed.exists() or installed.is_symlink():
                    remove_path(installed)
                    print(f"  Removed extension: {ext_dir.name}")

    # Clean build directory
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
        print(f"  Removed build directory")

    print("  Done")


def main():
    parser = argparse.ArgumentParser(description="Build and install AI agent plugins")
    parser.add_argument("command", choices=["build", "install", "install-skills", "install-commands", "install-extensions", "clean", "submodule-init"],
                        help="Command to run")
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
        install_commands()
        install_extensions(plugins)
        print("\nAll done!")
    elif args.command == "install-skills":
        build_skills(plugins)
        install_skills()
    elif args.command == "install-commands":
        install_commands()
    elif args.command == "install-extensions":
        install_extensions(plugins)
    elif args.command == "clean":
        clean(plugins)


if __name__ == "__main__":
    main()
