#!/usr/bin/env python3
"""
Build system for AI agent plugins.

Reads plugins.toml and builds/installs skills, prompt templates,
subagents, and extensions for Claude Code, Codex CLI, and Pi Agent.

Requires Python 3.11+ (uses tomllib from stdlib).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Extensions that require user interaction and should be skipped in non-interactive mode
INTERACTIVE_EXTENSIONS = {
    "confirm-destructive",
}

# Skill overrides that explicitly require interactivity
INTERACTIVE_OVERRIDES = {
    "brainstorming-claude.md",
}

# Global flag for non-interactive mode
NON_INTERACTIVE = False


def remove_path(path: Path) -> None:
    """Remove a path, handling symlinks, files, and directories."""
    if path.is_symlink() or path.is_file():
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
SUBAGENTS_DIR = ROOT / "subagents"
PROMPTS_DIR = ROOT / "prompts"

PI_EXTENSIONS_DIR = ROOT / "pi-extensions"
PI_THEMES_DIR = ROOT / "pi-themes"
OVERRIDES_DIR = ROOT / "skill-overrides"
BUILD_DIR = ROOT / "build"
CONFIG_FILE = ROOT / "plugins.toml"
CONFIGS_DIR = ROOT / "configs"
CODEX_CONFIG_FILE = CONFIGS_DIR / "codex-config.toml"
CODEX_MODEL_CATALOG_FILE = CONFIGS_DIR / "codex-model-catalog.json"
CODEX_PROFILE_CONFIGS_DIR = CONFIGS_DIR / "codex-profiles"
CODEX_HOOKS_FILE = CONFIGS_DIR / "codex" / "hooks.json"
CODEX_RULES_DIR = CONFIGS_DIR / "codex" / "rules"
PI_CONFIGS_DIR = ROOT / "pi-configs"
PI_SETTINGS_FILE = PI_CONFIGS_DIR / "pi-settings.json"
PI_MODELS_FILE = PI_CONFIGS_DIR / "pi-models.json"
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
        "skills": HOME / ".agents" / "skills",
        "extensions": HOME / ".pi" / "agent" / "extensions",
        "prompts": HOME / ".pi" / "agent" / "prompts",
        "subagents": HOME / ".pi" / "agent" / "agents",
        "themes": HOME / ".pi" / "agent" / "themes",
    },
}

STATE_DIR = Path(os.environ.get("XDG_STATE_HOME") or HOME / ".local" / "state") / "dotfiles"
INSTALL_MANIFEST = STATE_DIR / "agent-install-manifest.json"
INSTALL_MANIFEST_VERSION = 1

AGENTS = ["amp", "claude", "pi"]  # Agents that get broad skill builds


def empty_install_manifest() -> dict:
    return {"version": INSTALL_MANIFEST_VERSION, "targets": {}}


def validate_install_child_name(name: object) -> str:
    if not isinstance(name, str):
        sys.exit(f"Error: unsafe child name in install manifest: {name!r}")
    if (
        name in ("", ".", "..")
        or Path(name).is_absolute()
        or Path(name).name != name
        or "/" in name
        or "\\" in name
    ):
        sys.exit(f"Error: unsafe child name in install manifest: {name!r}")
    return name


def validate_manifest_targets(manifest: dict) -> None:
    targets = manifest.setdefault("targets", {})
    if not isinstance(targets, dict):
        sys.exit(f"Error: invalid install manifest targets at {INSTALL_MANIFEST}")

    for target_name, names in targets.items():
        if not isinstance(names, list):
            sys.exit(
                f"Error: invalid install manifest target {target_name!r} at {INSTALL_MANIFEST}"
            )
        targets[target_name] = [validate_install_child_name(name) for name in names]


def load_install_manifest() -> dict:
    if not INSTALL_MANIFEST.exists():
        return empty_install_manifest()

    try:
        manifest = json.loads(INSTALL_MANIFEST.read_text())
    except json.JSONDecodeError as error:
        sys.exit(f"Error: invalid install manifest JSON at {INSTALL_MANIFEST}: {error}")

    if manifest.get("version") != INSTALL_MANIFEST_VERSION:
        sys.exit(
            f"Error: unsupported install manifest version at {INSTALL_MANIFEST}. "
            "Remove it manually to reinitialize managed install state."
        )
    validate_manifest_targets(manifest)
    return manifest


def save_install_manifest(manifest: dict) -> None:
    INSTALL_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    INSTALL_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def source_child_names(source: Path, *, pattern: str = "*") -> list[str]:
    if not source.exists():
        return []
    return sorted(validate_install_child_name(path.name) for path in source.glob(pattern))


def copy_child(source_child: Path, dest_child: Path) -> None:
    remove_path(dest_child)
    if source_child.is_dir():
        shutil.copytree(source_child, dest_child)
    else:
        dest_child.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source_child, dest_child)


def unmanaged_install_conflicts(
    dest: Path,
    desired: set[str],
    previous: set[str],
    *,
    force: bool = False,
) -> list[Path]:
    if force:
        return []

    return [
        dest / name
        for name in sorted(desired - previous)
        if (dest / name).exists() or (dest / name).is_symlink()
    ]


def exit_for_unmanaged_conflicts(conflicts: list[Path]) -> None:
    if not conflicts:
        return

    conflict_list = "\n".join(f"  - {path}" for path in conflicts)
    sys.exit(
        "Error: refusing to overwrite unmanaged install path(s):\n"
        f"{conflict_list}\n"
        "Run the install command with --force to claim these paths."
    )


def sync_managed_children(
    target_name: str,
    source: Path,
    dest: Path,
    *,
    pattern: str = "*",
    force: bool = False,
) -> int:
    manifest = load_install_manifest()
    targets = manifest.setdefault("targets", {})
    previous = set(targets.get(target_name, []))
    desired = set(source_child_names(source, pattern=pattern))

    dest.mkdir(parents=True, exist_ok=True)
    exit_for_unmanaged_conflicts(
        unmanaged_install_conflicts(dest, desired, previous, force=force)
    )

    for name in sorted(previous - desired):
        installed = dest / name
        if installed.exists() or installed.is_symlink():
            remove_path(installed)

    for name in sorted(desired):
        source_child = source / name
        dest_child = dest / name
        if (dest_child.exists() or dest_child.is_symlink()) and name not in previous and not force:
            sys.exit(
                f"Error: refusing to overwrite unmanaged install path: {dest_child}\n"
                "Run the install command with --force to claim this path."
            )
        copy_child(source_child, dest_child)

    targets[target_name] = sorted(desired)
    save_install_manifest(manifest)
    return len(desired)


def clean_manifest_target(manifest: dict, target_name: str, dest: Path) -> None:
    targets = manifest.setdefault("targets", {})
    for name in sorted(targets.get(target_name, [])):
        installed = dest / name
        if installed.exists() or installed.is_symlink():
            remove_path(installed)
            print(f"  Removed {installed}")
    targets.pop(target_name, None)


def plugin_dir_name(name: str) -> str:
    """Convert plugin name (owner/repo) to directory name (owner-repo)."""
    return name.replace("/", "-")


@dataclass
class Plugin:
    """Configuration for a single plugin."""

    name: str  # Fully qualified name: owner/repo
    url: str
    skills_path: list[str] = field(default_factory=lambda: ["skills/*"])
    skills_path_by_agent: dict[str, list[str]] = field(default_factory=dict)
    skills: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    skills_skip_agents: list[str] = field(default_factory=list)
    extensions_path: list[str] = field(default_factory=lambda: ["extensions/*.ts"])
    extensions: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    prompts_path: list[str] = field(default_factory=lambda: ["prompts/*.md"])
    prompts: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    subagents_path: list[str] = field(default_factory=lambda: ["agents/*.md"])
    subagents: list[str] = field(default_factory=list)  # Empty = none, ["*"] = all
    extension_dependency_packages: dict[str, str] = field(default_factory=dict)
    alias: str | None = None

    @property
    def dir_name(self) -> str:
        """Directory name for this plugin (owner-repo format)."""
        return plugin_dir_name(self.name)

    def skill_paths_for(self, agent: str | None) -> list[str]:
        """Return agent-specific skill paths when configured."""
        if agent is not None and agent in self.skills_path_by_agent:
            return self.skills_path_by_agent[agent]
        return self.skills_path

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "Plugin":
        """Create Plugin from TOML dictionary."""

        def normalize_path(p) -> list[str]:
            if p is None:
                return []
            if isinstance(p, str):
                return [p]
            return list(p)

        def normalize_path_map(paths_by_agent) -> dict[str, list[str]]:
            if paths_by_agent is None:
                return {}
            if not isinstance(paths_by_agent, dict):
                raise TypeError("skills_path_by_agent must be a table")
            return {
                str(agent): normalize_path(paths)
                for agent, paths in paths_by_agent.items()
            }

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
            skills_path_by_agent=normalize_path_map(data.get("skills_path_by_agent")),
            skills=normalize_items(data.get("skills")),
            skills_skip_agents=normalize_items(data.get("skills_skip_agents")),
            extensions_path=normalize_path(
                data.get("extensions_path", "extensions/*.ts")
            ),
            extensions=normalize_items(data.get("extensions")),
            prompts_path=normalize_path(data.get("prompts_path", "prompts/*.md")),
            prompts=normalize_items(data.get("prompts")),
            subagents_path=normalize_path(data.get("subagents_path", "agents/*.md")),
            subagents=normalize_items(data.get("subagents")),
            extension_dependency_packages=dict(
                data.get("extension_dependency_packages", {})
            ),
            alias=data.get("alias"),
        )


def load_config() -> dict[str, Plugin]:
    """Load and parse plugins.toml."""
    if not CONFIG_FILE.exists():
        sys.exit(f"Error: {CONFIG_FILE} not found")

    with open(CONFIG_FILE, "rb") as f:
        data = tomllib.load(f)

    return {name: Plugin.from_dict(name, cfg) for name, cfg in data.items()}


def run_cmd(
    cmd: list[str], check: bool = True, cwd: Path | None = None
) -> subprocess.CompletedProcess:
    """Run a shell command."""
    return subprocess.run(cmd, check=check, capture_output=True, text=True, cwd=cwd)


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


def discover_items(
    plugin: Plugin, item_type: str, agent: str | None = None
) -> list[tuple[str, Path]]:
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
        patterns = plugin.skill_paths_for(agent)
        enabled = plugin.skills
    elif item_type == "extensions":
        patterns = plugin.extensions_path
        enabled = plugin.extensions
    elif item_type == "prompts":
        patterns = plugin.prompts_path
        enabled = plugin.prompts
    elif item_type == "subagents":
        patterns = plugin.subagents_path
        enabled = plugin.subagents
    else:
        raise ValueError(f"Unknown item type: {item_type}")

    # Empty list means nothing enabled
    if len(enabled) == 0:
        return []

    # Check for wildcard (all items)
    include_all = "*" in enabled

    items = []
    for path in glob_paths(plugin_dir, patterns):
        if item_type == "skills" and path.is_dir():
            name = path.name
        elif item_type == "extensions":
            if path.is_dir() and (path / "index.ts").exists():
                name = path.name
            elif path.is_file() and path.suffix == ".ts":
                if path.name == "index.ts" and path.parent != plugin_dir:
                    path = path.parent
                    name = path.name
                else:
                    name = path.stem
            elif path.is_dir():
                # Directory without index.ts: scan for .ts extension files
                for ts_file in sorted(path.glob("*.ts")):
                    if not ts_file.is_file():
                        continue
                    ts_name = ts_file.stem
                    if not include_all and ts_name not in enabled:
                        continue
                    final_name = (
                        f"{plugin.alias}-{ts_name}" if plugin.alias else ts_name
                    )
                    items.append((final_name, ts_file))
                continue
            else:
                continue
        elif item_type == "prompts" and path.is_file() and path.suffix == ".md":
            name = path.stem
        elif item_type == "subagents" and path.is_file() and path.suffix == ".md":
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


def custom_extension_dirs() -> list[Path]:
    """Return custom extension directories under pi-extensions/."""
    if not PI_EXTENSIONS_DIR.exists():
        return []

    return [
        path
        for path in sorted(PI_EXTENSIONS_DIR.iterdir())
        if path.is_dir() and (path / "index.ts").exists()
    ]


def is_interactive_override(override_path: Path) -> bool:
    """Check if an override file is interactive-only."""
    return override_path.name in INTERACTIVE_OVERRIDES


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


def extract_skill_description(content: str) -> str:
    """Extract a description from skill body content."""
    import re

    # Strip frontmatter if present
    body = re.sub(r"^---\s*\n.*?\n---\s*\n?", "", content, flags=re.DOTALL)

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if re.match(r"^[-*_]{3,}$", line):
            continue
        return line

    return "Skill instructions"


def normalize_skill_frontmatter(content: str, expected_name: str) -> str:
    """
    Ensure SKILL.md has valid frontmatter with name and description.

    - If no frontmatter exists, create it.
    - If name is missing or mismatched, set it to expected_name.
    - If description is missing, derive one from the first body paragraph.
    """
    import re

    frontmatter_pattern = r"^---\s*\n(.*?)\n---"
    match = re.match(frontmatter_pattern, content, re.DOTALL)
    description = extract_skill_description(content)

    if not match:
        return (
            "---\n"
            f"name: {expected_name}\n"
            f"description: {description}\n"
            "---\n\n"
            f"{content.lstrip()}"
        )

    frontmatter = match.group(1)
    new_frontmatter = frontmatter

    # Ensure name matches directory name
    name_pattern = r"^name:\s*(.+)$"
    name_match = re.search(name_pattern, new_frontmatter, re.MULTILINE)
    if name_match:
        new_frontmatter = re.sub(
            name_pattern,
            f"name: {expected_name}",
            new_frontmatter,
            flags=re.MULTILINE,
        )
    else:
        new_frontmatter = f"name: {expected_name}\n{new_frontmatter}"

    # Ensure description exists
    description_pattern = r"^description:\s*(.+)$"
    if not re.search(description_pattern, new_frontmatter, re.MULTILINE):
        # Keep description near the top for readability
        lines = new_frontmatter.split("\n")
        if lines and lines[0].startswith("name:"):
            lines.insert(1, f"description: {description}")
        else:
            lines.insert(0, f"description: {description}")
        new_frontmatter = "\n".join(lines)

    return content[: match.start(1)] + new_frontmatter + content[match.end(1) :]


def find_skill_markdown(source: Path) -> Path | None:
    """Find the skill markdown file in a skill directory."""
    candidates = [
        item
        for item in source.iterdir()
        if item.is_file() and item.name.lower() == "skill.md"
    ]
    if not candidates:
        return None

    # Prefer canonical name when present; otherwise keep selection deterministic.
    candidates.sort(key=lambda path: (path.name != "SKILL.md", path.name))
    return candidates[0]


def build_skill(name: str, source: Path, agent: str) -> bool | None:
    """
    Build a skill for a specific agent.

    Returns:
        True if built successfully
        False if skipped due to missing skill markdown
        None if skipped due to agent filtering
    """
    skill_md = find_skill_markdown(source)
    if skill_md is None:
        print(f"    Warning: {source} has no SKILL.md/skill.md, skipping")
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

    # Process content: normalize frontmatter and strip agents field
    skill_content = normalize_skill_frontmatter(raw_content, name)
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
        if item.name.lower() == "skill.md" or item.name == "overrides":
            continue

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
    for agent in [*AGENTS, "codex"]:
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

        skills_by_name: dict[str, dict[str, Path]] = {}
        for agent in AGENTS:
            if agent in plugin.skills_skip_agents:
                continue
            for name, path in discover_items(plugin, "skills", agent=agent):
                skills_by_name.setdefault(name, {})[agent] = path

        for name, paths_by_agent in sorted(skills_by_name.items()):
            if name in built:
                print(
                    f"    Warning: Skill '{name}' already exists, skipping duplicate from {plugin.name}"
                )
                continue
            built_for_agents = []
            for agent in AGENTS:
                path = paths_by_agent.get(agent)
                if path is None:
                    continue
                result = build_skill(name, path, agent)
                if result is True:
                    built_for_agents.append(agent)
                elif result is False:
                    break
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
                    elif result is False:
                        break
                if built_for_agents:
                    if set(built_for_agents) == set(AGENTS):
                        print(f"  {name} (custom)")
                    else:
                        print(f"  {name} (custom) [{', '.join(built_for_agents)}]")
                    built.add(name)

    # Process Codex-only custom skills. Keep this narrow: only skills that
    # explicitly opt into codex are built for the codex install target.
    if SKILLS_DIR.exists():
        built_for_codex = []
        for skill_dir in sorted(SKILLS_DIR.iterdir()):
            if not skill_dir.is_dir():
                continue
            skill_md = find_skill_markdown(skill_dir)
            if skill_md is None:
                continue
            allowed_agents = parse_skill_agents(skill_md.read_text())
            if allowed_agents is None or "codex" not in allowed_agents:
                continue
            name = skill_dir.name
            result = build_skill(name, skill_dir, "codex")
            if result is True:
                built_for_codex.append(name)

        for name in built_for_codex:
            print(f"  {name} (custom) [codex]")
            built.add(name)

    print(f"  Built {len(built)} skills")


def build_prompts(plugins: dict[str, Plugin]):
    """Build prompt templates for Pi from plugins and custom prompts directory."""
    print("Building prompt templates...")

    build_prompts_dir = BUILD_DIR / "prompts" / "pi"
    if build_prompts_dir.exists():
        shutil.rmtree(build_prompts_dir)
    build_prompts_dir.mkdir(parents=True, exist_ok=True)

    built = set()

    # Process plugin prompts
    for plugin in plugins.values():
        for name, path in discover_items(plugin, "prompts"):
            if name in built:
                print(
                    f"    Warning: Prompt '{name}' already exists, skipping duplicate from {plugin.name}"
                )
                continue

            shutil.copy(path, build_prompts_dir / f"{name}.md")
            print(f"  {name} (from {plugin.name})")
            built.add(name)

    # Process custom prompts
    if PROMPTS_DIR.exists():
        for prompt_file in sorted(PROMPTS_DIR.glob("*.md")):
            name = prompt_file.stem
            if name in built:
                print(
                    f"    Warning: Custom prompt '{name}' conflicts with plugin prompt"
                )

            shutil.copy(prompt_file, build_prompts_dir / f"{name}.md")
            print(f"  {name} (custom)")
            built.add(name)

    print(f"  Built {len(built)} prompt templates")


def build_subagents(plugins: dict[str, Plugin]):
    """Build subagent definitions for Pi from plugins and custom subagents directory."""
    print("Building subagents...")

    build_subagents_dir = BUILD_DIR / "subagents" / "pi"
    if build_subagents_dir.exists():
        shutil.rmtree(build_subagents_dir)
    build_subagents_dir.mkdir(parents=True, exist_ok=True)

    built = set()

    # Process plugin subagents
    for plugin in plugins.values():
        for name, path in discover_items(plugin, "subagents"):
            if name in built:
                print(
                    f"    Warning: Subagent '{name}' already exists, skipping duplicate from {plugin.name}"
                )
                continue

            shutil.copy(path, build_subagents_dir / f"{name}.md")
            print(f"  {name} (from {plugin.name})")
            built.add(name)

    # Process custom subagents
    if SUBAGENTS_DIR.exists():
        for agent_file in sorted(SUBAGENTS_DIR.glob("*.md")):
            name = agent_file.stem
            if name in built:
                print(
                    f"    Warning: Custom subagent '{name}' conflicts with plugin subagent"
                )

            shutil.copy(agent_file, build_subagents_dir / f"{name}.md")
            print(f"  {name} (custom)")
            built.add(name)

    # Process subagents bundled with extensions
    for ext_dir in custom_extension_dirs():
        agents_dir = ext_dir / "agents"
        if not agents_dir.exists():
            continue
        for agent_file in sorted(agents_dir.glob("*.md")):
            name = agent_file.stem
            if name in built:
                print(
                    f"    Warning: Extension subagent '{name}' from {ext_dir.name} conflicts with existing subagent"
                )
                continue

            shutil.copy(agent_file, build_subagents_dir / f"{name}.md")
            print(f"  {name} (from extension {ext_dir.name})")
            built.add(name)

    print(f"  Built {len(built)} subagents")


def install_skills(force: bool = False):
    """Install built skills to agent directories."""
    print("Installing skills...")

    for agent, paths in INSTALL_PATHS.items():
        if "skills" not in paths:
            continue

        source = BUILD_DIR / agent
        if not source.exists():
            continue

        dest = paths["skills"]
        count = sync_managed_children(
            f"{agent}.skills",
            source,
            dest,
            force=force,
        )

        print(f"  {agent}: {count} skills -> {dest}")


def build_themes():
    """Build Pi themes from custom pi-themes directory."""
    import json

    print("Building themes...")

    build_themes_dir = BUILD_DIR / "themes" / "pi"
    if build_themes_dir.exists():
        shutil.rmtree(build_themes_dir)
    build_themes_dir.mkdir(parents=True, exist_ok=True)

    if not PI_THEMES_DIR.exists():
        print("  No pi-themes directory found, skipping")
        return

    built = 0
    for theme_file in sorted(PI_THEMES_DIR.glob("*.json")):
        # Validate JSON so bad theme files fail fast during build.
        with open(theme_file) as f:
            json.load(f)

        shutil.copy(theme_file, build_themes_dir / theme_file.name)
        print(f"  {theme_file.stem} (custom)")
        built += 1

    print(f"  Built {built} themes")


def install_prompts(force: bool = False):
    """Install built prompt templates to Pi prompt directory."""
    print("Installing prompt templates...")

    source = BUILD_DIR / "prompts" / "pi"
    if not source.exists():
        print("  No built prompt templates found, skipping")
        return

    dest = INSTALL_PATHS["pi"]["prompts"]
    count = sync_managed_children(
        "pi.prompts",
        source,
        dest,
        pattern="*.md",
        force=force,
    )

    print(f"  pi: {count} prompts -> {dest}")


def install_subagents(force: bool = False):
    """Install built subagent definitions to Pi agents directory."""
    print("Installing subagents...")

    source = BUILD_DIR / "subagents" / "pi"
    if not source.exists():
        print("  No built subagents found, skipping")
        return

    dest = INSTALL_PATHS["pi"]["subagents"]
    count = sync_managed_children(
        "pi.subagents",
        source,
        dest,
        pattern="*.md",
        force=force,
    )

    print(f"  pi: {count} subagents -> {dest}")


def install_themes(force: bool = False):
    """Install built Pi themes."""
    print("Installing themes...")

    source = BUILD_DIR / "themes" / "pi"
    if not source.exists():
        print("  No built themes found, skipping")
        return

    dest = INSTALL_PATHS["pi"]["themes"]
    count = sync_managed_children(
        "pi.themes",
        source,
        dest,
        pattern="*.json",
        force=force,
    )

    print(f"  pi: {count} themes -> {dest}")


def copy_plugin_extension_dependency_package(
    plugin: Plugin, extension_name: str, extension_dir: Path
):
    """Copy a plugin package.json for extensions with external dependencies."""
    if (extension_dir / "package.json").exists():
        return

    package_path = plugin.extension_dependency_packages.get(extension_name)
    if not package_path:
        return

    source = PLUGINS_DIR / plugin.dir_name / package_path
    if not source.exists():
        sys.exit(
            f"Error: extension_dependency_packages for {plugin.name}/{extension_name} "
            f"points to missing file: {source}"
        )

    shutil.copy(source, extension_dir / "package.json")


def install_extension_dependencies(extension_dir: Path, extension_name: str):
    """Install pnpm dependencies for an extension when package.json is present."""
    package_json = extension_dir / "package.json"
    if not package_json.exists():
        return

    print(f"    {extension_name}: running pnpm install")
    run_cmd(["pnpm", "install"], cwd=extension_dir)


def install_extensions(plugins: dict[str, Plugin], force: bool = False):
    """Install extensions from plugins and custom extensions directory."""
    print("Installing extensions...")

    if NON_INTERACTIVE:
        print("  (non-interactive mode: skipping interactive extensions and plugins)")

    dest = INSTALL_PATHS["pi"]["extensions"]

    manifest = load_install_manifest()
    targets = manifest.setdefault("targets", {})
    previous = set(targets.get("pi.extensions", []))
    dest.mkdir(parents=True, exist_ok=True)
    skipped_extensions = []
    skipped_plugins = []
    extension_entries = []
    planned = set()

    # Extensions from plugins
    for plugin in plugins.values():
        # Track skipped interactive plugins
        if NON_INTERACTIVE and plugin.name in INTERACTIVE_PLUGINS:
            skipped_plugins.append(plugin.name)
            continue

        for name, path in discover_items(plugin, "extensions"):
            if name in planned:
                print(
                    f"    Warning: Extension '{name}' already exists, skipping duplicate from {plugin.name}"
                )
                continue

            # Skip interactive extensions in non-interactive mode
            if NON_INTERACTIVE and name in INTERACTIVE_EXTENSIONS:
                skipped_extensions.append(name)
                continue

            extension_entries.append((name, path, plugin))
            planned.add(name)

    # Custom extensions
    for ext_dir in custom_extension_dirs():
        name = ext_dir.name

        # Skip interactive extensions in non-interactive mode
        if NON_INTERACTIVE and name in INTERACTIVE_EXTENSIONS:
            skipped_extensions.append(name)
            continue

        if name in planned:
            print(
                f"    Warning: Custom extension '{name}' conflicts with plugin extension"
            )

        extension_entries.append((name, ext_dir, None))
        planned.add(name)

    exit_for_unmanaged_conflicts(
        unmanaged_install_conflicts(dest, planned, previous, force=force)
    )

    installed = set()
    for name, path, plugin in extension_entries:
        dest_ext = dest / name
        remove_path(dest_ext)

        # Extensions are .ts files, need to be wrapped in directory with index.ts
        if path.is_file():
            dest_ext.mkdir(parents=True)
            shutil.copy(path, dest_ext / "index.ts")
        else:
            shutil.copytree(path, dest_ext, ignore=shutil.ignore_patterns("node_modules"))

        if plugin is not None:
            copy_plugin_extension_dependency_package(plugin, name, dest_ext)
        install_extension_dependencies(dest_ext, name)
        if plugin is None:
            print(f"  {name} (custom)")
        else:
            print(f"  {name} (from {plugin.name})")
        installed.add(name)

    for name in sorted(previous - installed):
        installed_ext = dest / name
        if installed_ext.exists() or installed_ext.is_symlink():
            remove_path(installed_ext)

    targets["pi.extensions"] = sorted(installed)
    save_install_manifest(manifest)

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

    if CODEX_MODEL_CATALOG_FILE.exists():
        catalog_dest = dest.parent / "model-catalog.json"
        shutil.copy(CODEX_MODEL_CATALOG_FILE, catalog_dest)
        print(f"  Installed to {catalog_dest}")

    if CODEX_PROFILE_CONFIGS_DIR.exists():
        for profile_config in sorted(CODEX_PROFILE_CONFIGS_DIR.glob("*.config.toml")):
            profile_dest = dest.parent / profile_config.name
            shutil.copy(profile_config, profile_dest)
            print(f"  Installed to {profile_dest}")


def install_codex_rules():
    """Install Codex CLI exec policy rules."""
    print("Installing Codex rules...")

    if not CODEX_RULES_DIR.exists():
        print("  No codex rules found, skipping")
        return

    dest = HOME / ".codex" / "rules"
    dest.mkdir(parents=True, exist_ok=True)

    for source in sorted(CODEX_RULES_DIR.glob("*.rules")):
        target = dest / source.name
        shutil.copy(source, target)
        print(f"  Installed to {target}")


def install_codex_hooks():
    """Install Codex CLI hooks."""
    print("Installing Codex hooks...")

    if not CODEX_HOOKS_FILE.exists():
        print("  No codex hooks found, skipping")
        return

    codex_dir = HOME / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)

    dest_file = codex_dir / "hooks.json"
    shutil.copy(CODEX_HOOKS_FILE, dest_file)
    print(f"  Installed to {dest_file}")

    stale_hook = codex_dir / "hooks" / "terraform_apply_gate.py"
    if stale_hook.exists():
        stale_hook.unlink()
        print(f"  Removed {stale_hook}")


def install_pi_settings():
    """Install Pi agent settings."""
    import json

    print("Installing Pi settings...")

    if not PI_SETTINGS_FILE.exists():
        print("  No pi-settings.json found, skipping")
        return

    dest = HOME / ".pi" / "agent" / "settings.json"
    dest.parent.mkdir(parents=True, exist_ok=True)

    with open(PI_SETTINGS_FILE) as f:
        managed_settings = json.load(f)

    if dest.exists():
        with open(dest) as f:
            settings = json.load(f)
    else:
        settings = {}

    preserved_settings = {
        key: settings[key]
        for key in ("lastChangelogVersion",)
        if key in settings
    }

    for key, value in managed_settings.items():
        settings[key] = value

    settings.update(preserved_settings)

    with open(dest, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")

    print(f"  Installed to {dest}")


def install_pi_models():
    """Install Pi custom model definitions."""
    import json

    print("Installing Pi models...")

    if not PI_MODELS_FILE.exists():
        print("  No pi-models.json found, skipping")
        return

    dest = HOME / ".pi" / "agent" / "models.json"
    dest.parent.mkdir(parents=True, exist_ok=True)

    with open(PI_MODELS_FILE) as f:
        managed_models = json.load(f)

    if dest.exists():
        with open(dest) as f:
            models = json.load(f)
    else:
        models = {}

    # Overlay managed providers onto existing (managed wins on conflict)
    managed_providers = managed_models.get("providers", {})
    existing_providers = models.setdefault("providers", {})
    existing_providers.update(managed_providers)

    with open(dest, "w") as f:
        json.dump(models, f, indent=2)
        f.write("\n")

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
    install_codex_rules()
    install_codex_hooks()
    install_pi_settings()
    install_pi_models()
    install_global_agents_md()


def clean():
    """Remove all installed artifacts."""
    print("Cleaning installed artifacts...")

    manifest = load_install_manifest()

    for agent, paths in INSTALL_PATHS.items():
        if "skills" in paths:
            clean_manifest_target(manifest, f"{agent}.skills", paths["skills"])

    clean_manifest_target(manifest, "pi.extensions", INSTALL_PATHS["pi"]["extensions"])
    clean_manifest_target(manifest, "pi.prompts", INSTALL_PATHS["pi"]["prompts"])
    clean_manifest_target(manifest, "pi.subagents", INSTALL_PATHS["pi"]["subagents"])
    clean_manifest_target(manifest, "pi.themes", INSTALL_PATHS["pi"]["themes"])
    save_install_manifest(manifest)

    if not manifest.get("targets") and INSTALL_MANIFEST.exists():
        INSTALL_MANIFEST.unlink()
        print(f"  Removed {INSTALL_MANIFEST}")

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

    # Clean managed Pi models
    pi_models_dest = HOME / ".pi" / "agent" / "models.json"
    if pi_models_dest.exists():
        pi_models_dest.unlink()
        print(f"  Removed {pi_models_dest}")

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
            "install-prompts",
            "install-subagents",
            "install-themes",
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
    parser.add_argument(
        "--force",
        action="store_true",
        help="Claim existing unmanaged install paths that conflict with managed artifact names",
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
        build_prompts(plugins)
        build_subagents(plugins)
        build_themes()
    elif args.command == "install":
        if NON_INTERACTIVE:
            print("Installing in non-interactive mode...")
        init_submodules()
        build_skills(plugins)
        build_prompts(plugins)
        build_subagents(plugins)
        build_themes()
        install_skills(force=args.force)
        install_prompts(force=args.force)
        install_subagents(force=args.force)
        install_themes(force=args.force)
        install_extensions(plugins, force=args.force)
        install_configs()
        print("\nAll done!")
    elif args.command == "install-skills":
        build_skills(plugins)
        install_skills(force=args.force)
    elif args.command == "install-extensions":
        install_extensions(plugins, force=args.force)
    elif args.command == "install-prompts":
        build_prompts(plugins)
        install_prompts(force=args.force)
    elif args.command == "install-subagents":
        build_subagents(plugins)
        install_subagents(force=args.force)
    elif args.command == "install-themes":
        build_themes()
        install_themes(force=args.force)
    elif args.command == "install-configs":
        install_configs()
    elif args.command == "clean":
        clean()


if __name__ == "__main__":
    main()
