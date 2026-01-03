#!/usr/bin/env python3
"""
Build system for AI agent plugins.

Reads plugins.toml and builds/installs skills, hooks, and tools for
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

if sys.version_info < (3, 11):
    sys.exit("Error: Python 3.11+ required (for tomllib)")

import tomllib

# Directories
ROOT = Path(__file__).parent.parent
PLUGINS_DIR = ROOT / "plugins"
SKILLS_DIR = ROOT / "skills"
TOOLS_DIR = ROOT / "tools"
HOOKS_DIR = ROOT / "hooks"
OVERRIDES_DIR = ROOT / "skill-overrides"
BUILD_DIR = ROOT / "build"
CONFIG_FILE = ROOT / "plugins.toml"

# Installation paths
HOME = Path.home()
INSTALL_PATHS = {
    "claude": {
        "skills": HOME / ".claude" / "skills",
    },
    "codex": {
        "skills": HOME / ".codex" / "skills",
    },
    "pi": {
        "skills": HOME / ".pi" / "agent" / "skills",
        "tools": HOME / ".pi" / "agent" / "tools",
        "hooks": HOME / ".pi" / "agent" / "hooks",
    },
}

AGENTS = ["claude", "pi"]  # Agents that get skill builds


@dataclass
class Plugin:
    """Configuration for a single plugin."""
    name: str
    url: str
    skills_path: list[str] = field(default_factory=lambda: ["skills/*"])
    skills: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    hooks_path: list[str] = field(default_factory=lambda: ["pi-hooks/*.ts"])
    hooks: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    tools_path: list[str] = field(default_factory=lambda: ["tools/*"])
    tools: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    alias: str | None = None

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
            hooks_path=normalize_path(data.get("hooks_path", "pi-hooks/*.ts")),
            hooks=normalize_items(data.get("hooks")),
            tools_path=normalize_path(data.get("tools_path", "tools/*")),
            tools=normalize_items(data.get("tools")),
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
        # Special case: "." means the base directory itself (for root-level tools)
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
    Discover skills/hooks/tools from a plugin.

    Returns list of (item_name, item_path) tuples.

    The enabled list controls which items are included:
    - Empty list [] = no items
    - ["*"] = all items (wildcard)
    - ["item1", "item2"] = only specified items
    """
    plugin_dir = PLUGINS_DIR / plugin.name
    if not plugin_dir.exists():
        return []

    if item_type == "skills":
        patterns = plugin.skills_path
        enabled = plugin.skills
    elif item_type == "hooks":
        patterns = plugin.hooks_path
        enabled = plugin.hooks
    elif item_type == "tools":
        patterns = plugin.tools_path
        enabled = plugin.tools
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

        # Determine source: claude uses claude build, others use pi build
        source_agent = "claude" if agent == "claude" else "pi"
        source = BUILD_DIR / source_agent

        if not source.exists():
            continue

        dest = paths["skills"]
        dest.mkdir(parents=True, exist_ok=True)

        count = 0
        for skill_dir in sorted(source.iterdir()):
            if skill_dir.is_dir():
                dest_skill = dest / skill_dir.name
                if dest_skill.exists():
                    shutil.rmtree(dest_skill)
                shutil.copytree(skill_dir, dest_skill)
                count += 1

        print(f"  {agent}: {count} skills -> {dest}")


def install_hooks(plugins: dict[str, Plugin]):
    """Install hooks from plugins and custom hooks directory."""
    print("Installing hooks...")

    dest = INSTALL_PATHS["pi"]["hooks"]
    dest.mkdir(parents=True, exist_ok=True)

    installed = set()

    # Hooks from plugins
    for plugin in plugins.values():
        for name, path in discover_items(plugin, "hooks"):
            if name in installed:
                print(f"    Warning: Hook '{name}' already exists, skipping duplicate from {plugin.name}")
                continue

            dest_hook = dest / name
            if dest_hook.exists():
                shutil.rmtree(dest_hook)
            dest_hook.mkdir(parents=True)

            # Hooks are .ts files, need to be wrapped in directory with index.ts
            if path.is_file():
                shutil.copy(path, dest_hook / "index.ts")
            else:
                shutil.copytree(path, dest_hook, dirs_exist_ok=True)

            print(f"  {name} (from {plugin.name})")
            installed.add(name)

    # Custom hooks
    custom_hooks = HOOKS_DIR / "pi"
    if custom_hooks.exists():
        for hook_dir in sorted(custom_hooks.iterdir()):
            if hook_dir.is_dir():
                name = hook_dir.name
                if name in installed:
                    print(f"    Warning: Custom hook '{name}' conflicts with plugin hook")

                dest_hook = dest / name
                if dest_hook.exists():
                    shutil.rmtree(dest_hook)
                shutil.copytree(hook_dir, dest_hook)

                print(f"  {name} (custom)")
                installed.add(name)

    print(f"  Installed {len(installed)} hooks to {dest}")


def install_tools(plugins: dict[str, Plugin]):
    """Install tools from plugins and custom tools directory."""
    print("Installing tools...")

    dest = INSTALL_PATHS["pi"]["tools"]
    dest.mkdir(parents=True, exist_ok=True)

    installed = set()

    # Tools from plugins
    for plugin in plugins.values():
        for name, path in discover_items(plugin, "tools"):
            if name in installed:
                print(f"    Warning: Tool '{name}' already exists, skipping duplicate from {plugin.name}")
                continue

            dest_tool = dest / name
            if dest_tool.exists():
                shutil.rmtree(dest_tool)

            if path.is_dir():
                shutil.copytree(path, dest_tool)
            else:
                dest_tool.mkdir(parents=True)
                shutil.copy(path, dest_tool / "index.ts")

            print(f"  {name} (from {plugin.name})")
            installed.add(name)

    # Custom tools
    custom_tools = TOOLS_DIR / "pi"
    if custom_tools.exists():
        for tool_dir in sorted(custom_tools.iterdir()):
            if tool_dir.is_dir():
                name = tool_dir.name
                if name in installed:
                    print(f"    Warning: Custom tool '{name}' conflicts with plugin tool")

                dest_tool = dest / name
                if dest_tool.exists():
                    shutil.rmtree(dest_tool)
                shutil.copytree(tool_dir, dest_tool)

                print(f"  {name} (custom)")
                installed.add(name)

    print(f"  Installed {len(installed)} tools to {dest}")


def clean(plugins: dict[str, Plugin]):
    """Remove all installed artifacts."""
    print("Cleaning installed artifacts...")

    # Clean skills from all agents
    for agent, paths in INSTALL_PATHS.items():
        if "skills" in paths:
            source_agent = "claude" if agent == "claude" else "pi"
            source = BUILD_DIR / source_agent
            if source.exists():
                for skill_dir in source.iterdir():
                    if skill_dir.is_dir():
                        installed = paths["skills"] / skill_dir.name
                        if installed.exists():
                            shutil.rmtree(installed)
                            print(f"  Removed skill: {skill_dir.name} from {agent}")

    # Clean hooks
    hooks_dest = INSTALL_PATHS["pi"]["hooks"]
    for plugin in plugins.values():
        for name, _ in discover_items(plugin, "hooks"):
            installed = hooks_dest / name
            if installed.exists():
                shutil.rmtree(installed)
                print(f"  Removed hook: {name}")

    # Custom hooks
    custom_hooks = HOOKS_DIR / "pi"
    if custom_hooks.exists():
        for hook_dir in custom_hooks.iterdir():
            if hook_dir.is_dir():
                installed = hooks_dest / hook_dir.name
                if installed.exists():
                    shutil.rmtree(installed)
                    print(f"  Removed hook: {hook_dir.name}")

    # Clean tools
    tools_dest = INSTALL_PATHS["pi"]["tools"]
    for plugin in plugins.values():
        for name, _ in discover_items(plugin, "tools"):
            installed = tools_dest / name
            if installed.exists():
                shutil.rmtree(installed)
                print(f"  Removed tool: {name}")

    # Custom tools
    custom_tools = TOOLS_DIR / "pi"
    if custom_tools.exists():
        for tool_dir in custom_tools.iterdir():
            if tool_dir.is_dir():
                installed = tools_dest / tool_dir.name
                if installed.exists():
                    shutil.rmtree(installed)
                    print(f"  Removed tool: {tool_dir.name}")

    # Clean build directory
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
        print(f"  Removed build directory")

    print("  Done")


def main():
    parser = argparse.ArgumentParser(description="Build and install AI agent plugins")
    parser.add_argument("command", choices=["build", "install", "install-skills", "install-tools", "install-hooks", "clean", "submodule-init"],
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
        install_tools(plugins)
        install_hooks(plugins)
        print("\nAll done!")
    elif args.command == "install-skills":
        build_skills(plugins)
        install_skills()
    elif args.command == "install-tools":
        install_tools(plugins)
    elif args.command == "install-hooks":
        install_hooks(plugins)
    elif args.command == "clean":
        clean(plugins)


if __name__ == "__main__":
    main()
