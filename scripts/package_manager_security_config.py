#!/usr/bin/env python3
"""Configure package-manager security defaults in the user's global config."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


HOME = Path.home()


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_config(command: list[str]) -> None:
    subprocess.run(command, check=True)


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text().splitlines()


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n")


def is_section_header(line: str) -> bool:
    return re.match(r"^\s*\[[^]]+\]\s*$", line) is not None


def set_top_level_toml_value(path: Path, key: str, value: str) -> None:
    lines = read_lines(path)
    key_pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")

    for index, line in enumerate(lines):
        if is_section_header(line):
            break
        if key_pattern.match(line):
            lines[index] = f"{key} = {value}"
            write_lines(path, lines)
            return

    insert_at = next(
        (index for index, line in enumerate(lines) if is_section_header(line)),
        len(lines),
    )
    lines.insert(insert_at, f"{key} = {value}")
    write_lines(path, lines)


def set_section_toml_value(path: Path, section: str, key: str, value: str) -> None:
    lines = read_lines(path)
    section_header = f"[{section}]"
    key_pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")

    section_start = None
    for index, line in enumerate(lines):
        if line.strip() == section_header:
            section_start = index
            break

    if section_start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([section_header, f"{key} = {value}"])
        write_lines(path, lines)
        return

    section_end = len(lines)
    for index in range(section_start + 1, len(lines)):
        if is_section_header(lines[index]):
            section_end = index
            break

    for index in range(section_start + 1, section_end):
        if key_pattern.match(lines[index]):
            lines[index] = f"{key} = {value}"
            write_lines(path, lines)
            return

    lines.insert(section_end, f"{key} = {value}")
    write_lines(path, lines)


def configure_npm() -> None:
    if not command_exists("npm"):
        print("  npm: skipped (not installed)")
        return

    run_config(["npm", "config", "set", "min-release-age", "7", "--global"])
    run_config(["npm", "config", "set", "ignore-scripts", "true", "--global"])
    print("  npm: min-release-age=7, ignore-scripts=true")


def configure_pnpm() -> None:
    if not command_exists("pnpm"):
        print("  pnpm: skipped (not installed)")
        return

    run_config(["pnpm", "config", "set", "minimum-release-age", "10080", "--global"])
    print("  pnpm: minimum-release-age=10080")


def configure_bun() -> None:
    if not command_exists("bun"):
        print("  bun: skipped (not installed)")
        return

    dest = HOME / ".bunfig.toml"
    set_section_toml_value(dest, "install", "minimumReleaseAge", "604800")
    print(f"  bun: minimumReleaseAge=604800 -> {dest}")


def configure_uv() -> None:
    if not command_exists("uv"):
        print("  uv: skipped (not installed)")
        return

    dest = HOME / ".config" / "uv" / "uv.toml"
    set_top_level_toml_value(dest, "exclude-newer", '"7 days"')
    print(f"  uv: exclude-newer=7 days -> {dest}")


def main() -> None:
    print("Configuring package-manager security settings...")
    configure_npm()
    configure_pnpm()
    configure_bun()
    configure_uv()
    print("✓ Package-manager security settings configured")


if __name__ == "__main__":
    main()
