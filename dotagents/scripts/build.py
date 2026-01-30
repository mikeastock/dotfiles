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

# Extensions that require user interaction and should be skipped in non-interactive mode
INTERACTIVE_EXTENSIONS = {
    "AskUserQuestion",
    "confirm-destructive",
}

# Plugins that require user interaction and should be skipped entirely in non-interactive mode
# Use fully qualified names (owner/repo)
INTERACTIVE_PLUGINS = {
    "nicobailon/pi-interview-tool",
}

# Skill override patterns that require user interaction (skill name patterns)
# Overrides matching these patterns are skipped in non-interactive mode
INTERACTIVE_OVERRIDE_PATTERNS = {
    "*-AskUserQuestion-*",  # Any override referencing AskUserQuestion
}

# Skill overrides that explicitly require interactivity
INTERACTIVE_OVERRIDES = {
    "ask-questions-if-underspecified-claude.md",
    "ask-questions-if-underspecified-pi.md",
    "brainstorming-claude.md",
    "brainstorming-pi.md",
}

# Global flag for non-interactive mode
NON_INTERACTIVE = False


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

EXTENSIONS_DIR = ROOT / "extensions"
OVERRIDES_DIR = ROOT / "skill-overrides"
BUILD_DIR = ROOT / "build"
CONFIG_FILE = ROOT / "plugins.toml"
CONFIGS_DIR = ROOT / "configs"
CODEX_CONFIG_FILE = CONFIGS_DIR / "codex-config.toml"
PI_SETTINGS_FILE = CONFIGS_DIR / "pi-settings.json"
GLOBAL_AGENTS_MD = CONFIGS_DIR / "AGENTS.md"

# Installation paths
HOME = Path.home()
INSTALL_PATHS = {
    "amp": {
        "skills": HOME / ".config" / "agents" / "skills",
    },
    "claude": {
        "skills": HOME / ".claude" / "skills",
    },
    "codex": {
        "skills": HOME / ".codex" / "skills",
    },
    "pi": {
        "skills": HOME / ".pi" / "agent" / "skills",
        "extensions": HOME / ".pi" / "agent" / "extensions",
    },
}

AGENTS = ["amp", "claude", "codex", "pi"]  # Agents that get skill builds


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
            extensions_path=normalize_path(
                data.get("extensions_path", "extensions/*.ts")
            ),
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
    # Skip entire plugin in non-interactive mode if it's marked as interactive
    if NON_INTERACTIVE and plugin.name in INTERACTIVE_PLUGINS:
        return []

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


def is_interactive_override(override_path: Path) -> bool:
    """Check if an override file is interactive-only."""
    filename = override_path.name
    # Check explicit list
    if filename in INTERACTIVE_OVERRIDES:
        return True
    # Check patterns
    for pattern in INTERACTIVE_OVERRIDE_PATTERNS:
        if fnmatch(filename, pattern):
            return True
    return False


def parse_skill_agents(content: str) -> list[str] | None:
    """
    Parse the 'agents' field from SKILL.md frontmatter.

    Supports two formats per Agent Skills spec:
    1. Top-level: agents: [claude, codex, pi]
    2. In metadata: metadata.agents: "codex, pi" (comma-separated string)

    Returns:
        List of agent names if specified, None if not specified (means all agents).
    """
    import re

    # Match YAML frontmatter
    frontmatter_pattern = r"^---\s*\n(.*?)\n---"
    match = re.match(frontmatter_pattern, content, re.DOTALL)
    if not match:
        return None

    frontmatter = match.group(1)

    # First try top-level agents field (YAML list format):
    # agents: [claude, codex] or agents: ["claude", "codex"]
    agents_pattern = r"^agents:\s*\[([^\]]*)\]"
    agents_match = re.search(agents_pattern, frontmatter, re.MULTILINE)
    if agents_match:
        agents_str = agents_match.group(1)
        if not agents_str.strip():
            return []
        agents = []
        for item in agents_str.split(","):
            item = item.strip().strip("\"'")
            if item:
                agents.append(item)
        return agents

    # Try metadata.agents field (comma-separated string per Agent Skills spec):
    # metadata:
    #   agents: codex, pi
    metadata_agents_pattern = r"^\s+agents:\s*(.+)$"
    # Only match if we're in a metadata block
    in_metadata = False
    for line in frontmatter.split("\n"):
        if line.startswith("metadata:"):
            in_metadata = True
            continue
        if in_metadata:
            # Check if we've left the metadata block (non-indented line)
            if line and not line.startswith(" ") and not line.startswith("\t"):
                in_metadata = False
                continue
            # Look for agents field
            metadata_match = re.match(metadata_agents_pattern, line)
            if metadata_match:
                agents_str = metadata_match.group(1).strip().strip("\"'")
                if not agents_str:
                    return []
                agents = []
                for item in agents_str.split(","):
                    item = item.strip().strip("\"'")
                    if item:
                        agents.append(item)
                return agents

    return None


def strip_agents_from_frontmatter(content: str) -> str:
    """
    Remove the 'agents' field from SKILL.md frontmatter.

    Handles both top-level agents field and metadata.agents field.
    The agents field is build-time configuration and should not appear
    in the installed skill.
    """
    import re

    # Match YAML frontmatter
    frontmatter_pattern = r"^---\s*\n(.*?)\n---"
    match = re.match(frontmatter_pattern, content, re.DOTALL)
    if not match:
        return content

    frontmatter = match.group(1)
    new_frontmatter = frontmatter

    # Remove top-level agents line (including the newline)
    agents_pattern = r"^agents:\s*\[[^\]]*\]\n?"
    new_frontmatter = re.sub(agents_pattern, "", new_frontmatter, flags=re.MULTILINE)

    # Remove metadata.agents line (indented agents: inside metadata block)
    # This pattern matches "  agents: value\n" where value can be anything
    metadata_agents_pattern = r"^[ \t]+agents:\s*.*\n?"
    new_frontmatter = re.sub(
        metadata_agents_pattern, "", new_frontmatter, flags=re.MULTILINE
    )

    # Clean up trailing whitespace (pattern expects \n before ---)
    new_frontmatter = new_frontmatter.rstrip()

    if new_frontmatter == frontmatter:
        return content

    return content[: match.start(1)] + new_frontmatter + content[match.end(1) :]


def fix_skill_frontmatter_name(content: str, expected_name: str) -> str:
    """
    Fix the 'name' field in SKILL.md frontmatter to match the directory name.

    Per the Agent Skills spec, the directory name is the source of truth.
    This fixes upstream skills that have mismatched frontmatter names.
    """
    import re

    # Match YAML frontmatter
    frontmatter_pattern = r"^---\s*\n(.*?)\n---"
    match = re.match(frontmatter_pattern, content, re.DOTALL)
    if not match:
        return content

    frontmatter = match.group(1)

    # Check if name field exists and differs from expected
    name_pattern = r"^name:\s*(.+)$"
    name_match = re.search(name_pattern, frontmatter, re.MULTILINE)
    if not name_match:
        return content

    current_name = name_match.group(1).strip().strip("\"'")
    if current_name == expected_name:
        return content

    # Replace the name in frontmatter
    new_frontmatter = re.sub(
        name_pattern, f"name: {expected_name}", frontmatter, flags=re.MULTILINE
    )

    return content[: match.start(1)] + new_frontmatter + content[match.end(1) :]


def build_skill(name: str, source: Path, agent: str) -> bool | None:
    """
    Build a skill for a specific agent.

    Returns:
        True if built successfully
        False if skipped due to missing SKILL.md
        None if skipped due to agent filtering
    """
    # Find SKILL.md
    skill_md = source / "SKILL.md"
    if not skill_md.exists():
        print(f"    Warning: {source} has no SKILL.md, skipping")
        return False

    # Read content and check agent filtering
    raw_content = skill_md.read_text()
    allowed_agents = parse_skill_agents(raw_content)

    # If agents field is specified and this agent is not in the list, skip
    if allowed_agents is not None and agent not in allowed_agents:
        return None

    dest = BUILD_DIR / agent / name
    dest.mkdir(parents=True, exist_ok=True)

    # Check for overrides: global or local per-skill
    override = OVERRIDES_DIR / f"{name}-{agent}.md"
    local_override = source / "overrides" / f"{agent}.md"
    dest_skill_md = dest / "SKILL.md"

    # Process content: fix name and strip agents field
    skill_content = fix_skill_frontmatter_name(raw_content, name)
    skill_content = strip_agents_from_frontmatter(skill_content)

    # In non-interactive mode, skip interactive overrides
    use_override = override.exists() and not (
        NON_INTERACTIVE and is_interactive_override(override)
    )
    use_local_override = local_override.exists() and not (
        NON_INTERACTIVE and is_interactive_override(local_override)
    )

    with open(dest_skill_md, "w") as out:
        out.write(skill_content)
        if use_override:
            out.write("\n")
            out.write(override.read_text())
        if use_local_override:
            out.write("\n")
            out.write(local_override.read_text())

    # Copy additional files
    for item in source.iterdir():
        if item.name not in {"SKILL.md", "overrides"}:
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
    skipped_plugins = []

    # Process plugins
    for plugin in plugins.values():
        # Track skipped interactive plugins
        if NON_INTERACTIVE and plugin.name in INTERACTIVE_PLUGINS:
            skipped_plugins.append(plugin.name)
            continue

        for name, path in discover_items(plugin, "skills"):
            if name in built:
                print(
                    f"    Warning: Skill '{name}' already exists, skipping duplicate from {plugin.name}"
                )
                continue
            built_for_agents = []
            for agent in AGENTS:
                result = build_skill(name, path, agent)
                if result is True:
                    built_for_agents.append(agent)
            if built_for_agents:
                if set(built_for_agents) == set(AGENTS):
                    print(f"  {name} (from {plugin.name})")
                else:
                    print(f"  {name} (from {plugin.name}) [{', '.join(built_for_agents)}]")
                built.add(name)

    if skipped_plugins:
        print(
            f"  Skipped {len(skipped_plugins)} interactive plugins: {', '.join(skipped_plugins)}"
        )

    # Process custom skills
    if SKILLS_DIR.exists():
        for skill_dir in sorted(SKILLS_DIR.iterdir()):
            if skill_dir.is_dir():
                name = skill_dir.name
                if name in built:
                    print(
                        f"    Warning: Custom skill '{name}' conflicts with plugin skill"
                    )
                built_for_agents = []
                for agent in AGENTS:
                    result = build_skill(name, skill_dir, agent)
                    if result is True:
                        built_for_agents.append(agent)
                if built_for_agents:
                    if set(built_for_agents) == set(AGENTS):
                        print(f"  {name} (custom)")
                    else:
                        print(f"  {name} (custom) [{', '.join(built_for_agents)}]")
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

        # Clear existing skills directory for a fresh install
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)

        count = 0
        for skill_dir in sorted(source.iterdir()):
            if skill_dir.is_dir():
                dest_skill = dest / skill_dir.name
                shutil.copytree(skill_dir, dest_skill)
                count += 1

        print(f"  {agent}: {count} skills -> {dest}")


def install_extensions(plugins: dict[str, Plugin]):
    """Install extensions from plugins and custom extensions directory."""
    print("Installing extensions...")

    if NON_INTERACTIVE:
        print("  (non-interactive mode: skipping interactive extensions and plugins)")

    dest = INSTALL_PATHS["pi"]["extensions"]

    # Clear existing extensions directory for a fresh install
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    installed = set()
    skipped_extensions = []
    skipped_plugins = []

    # Extensions from plugins
    for plugin in plugins.values():
        # Track skipped interactive plugins
        if NON_INTERACTIVE and plugin.name in INTERACTIVE_PLUGINS:
            skipped_plugins.append(plugin.name)
            continue

        for name, path in discover_items(plugin, "extensions"):
            if name in installed:
                print(
                    f"    Warning: Extension '{name}' already exists, skipping duplicate from {plugin.name}"
                )
                continue

            # Skip interactive extensions in non-interactive mode
            if NON_INTERACTIVE and name in INTERACTIVE_EXTENSIONS:
                skipped_extensions.append(name)
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

                # Skip interactive extensions in non-interactive mode
                if NON_INTERACTIVE and name in INTERACTIVE_EXTENSIONS:
                    skipped_extensions.append(name)
                    continue

                if name in installed:
                    print(
                        f"    Warning: Custom extension '{name}' conflicts with plugin extension"
                    )

                dest_ext = dest / name
                remove_path(dest_ext)
                shutil.copytree(ext_dir, dest_ext)

                print(f"  {name} (custom)")
                installed.add(name)

    if skipped_plugins:
        print(
            f"  Skipped {len(skipped_plugins)} interactive plugins: {', '.join(skipped_plugins)}"
        )
    if skipped_extensions:
        print(
            f"  Skipped {len(skipped_extensions)} interactive extensions: {', '.join(skipped_extensions)}"
        )
    print(f"  Installed {len(installed)} extensions to {dest}")


def install_amp_config():
    """Install Amp agent configuration."""
    import json

    print("Installing Amp config...")

    dest = HOME / ".config" / "amp" / "settings.json"
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Load existing settings or start with empty dict
    if dest.exists():
        with open(dest) as f:
            settings = json.load(f)
    else:
        settings = {}

    # Set skills path
    settings["amp.skills.path"] = "~/.config/agents/skills"

    with open(dest, "w") as f:
        json.dump(settings, f, indent=2)

    print(f"  Installed to {dest}")


def install_codex_config():
    """Install Codex CLI configuration."""
    print("Installing Codex config...")

    if not CODEX_CONFIG_FILE.exists():
        print("  No codex-config.toml found, skipping")
        return

    dest = HOME / ".codex" / "config.toml"
    dest.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy(CODEX_CONFIG_FILE, dest)
    print(f"  Installed to {dest}")


def install_pi_settings():
    """Install Pi agent settings."""
    print("Installing Pi settings...")

    if not PI_SETTINGS_FILE.exists():
        print("  No pi-settings.json found, skipping")
        return

    dest = HOME / ".pi" / "agent" / "settings.json"
    dest.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy(PI_SETTINGS_FILE, dest)
    print(f"  Installed to {dest}")


def install_global_agents_md():
    """Install global AGENTS.md for codex and pi."""
    print("Installing global AGENTS.md...")

    if not GLOBAL_AGENTS_MD.exists():
        print("  No AGENTS.md found in configs/, skipping")
        return

    # Install for codex and pi only
    destinations = {
        "codex": HOME / ".codex" / "AGENTS.md",
        "pi": HOME / ".pi" / "agent" / "AGENTS.md",
    }

    for agent, dest in destinations.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(GLOBAL_AGENTS_MD, dest)
        print(f"  {agent}: {dest}")


def install_configs():
    """Install all agent configurations."""
    install_amp_config()
    install_codex_config()
    install_pi_settings()
    install_global_agents_md()


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
        print("  Removed build directory")

    # Clean global AGENTS.md
    agents_md_paths = [
        HOME / ".codex" / "AGENTS.md",
        HOME / ".pi" / "agent" / "AGENTS.md",
    ]
    for path in agents_md_paths:
        if path.exists():
            path.unlink()
            print(f"  Removed {path}")

    print("  Done")


def main():
    global NON_INTERACTIVE

    parser = argparse.ArgumentParser(description="Build and install AI agent plugins")
    parser.add_argument(
        "command",
        choices=[
            "build",
            "install",
            "install-skills",
            "install-extensions",
            "install-configs",
            "clean",
            "submodule-init",
        ],
        help="Command to run",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip interactive extensions and overrides (for headless/automated environments)",
    )
    args = parser.parse_args()

    # Set global flag
    NON_INTERACTIVE = args.non_interactive

    plugins = load_config()

    if args.command == "submodule-init":
        init_submodules()
    elif args.command == "build":
        if NON_INTERACTIVE:
            print("Building in non-interactive mode...")
        build_skills(plugins)
    elif args.command == "install":
        if NON_INTERACTIVE:
            print("Installing in non-interactive mode...")
        init_submodules()
        build_skills(plugins)
        install_skills()
        install_extensions(plugins)
        install_configs()
        print("\nAll done!")
    elif args.command == "install-skills":
        build_skills(plugins)
        install_skills()
    elif args.command == "install-extensions":
        install_extensions(plugins)
    elif args.command == "install-configs":
        install_configs()
    elif args.command == "clean":
        clean(plugins)


if __name__ == "__main__":
    main()
