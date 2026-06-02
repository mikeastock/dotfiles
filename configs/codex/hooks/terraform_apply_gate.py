#!/usr/bin/env python3
"""Block Terraform apply-shaped Bash commands in Codex PreToolUse hooks."""

from __future__ import annotations

import json
import os
import shlex
import sys

TERRAFORM_BINARIES = {"terraform", "tf", "tofu"}
MISE_COMMANDS = {"run", "exec"}
CONTROL_TOKENS = {"&&", "||", ";", "|"}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    command = extract_command(payload)
    if not command:
        return 0

    if is_terraform_apply_command(command):
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            "Terraform apply blocked. Ask the user for explicit approval "
                            "before running this command."
                        ),
                    }
                }
            )
        )

    return 0


def extract_command(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return ""

    raw_command = tool_input.get("command") or tool_input.get("cmd")
    if isinstance(raw_command, str):
        return raw_command
    if isinstance(raw_command, list):
        return shlex.join(str(part) for part in raw_command)
    return ""


def is_terraform_apply_command(command: str) -> bool:
    for segment in command_segments(command):
        if is_terraform_apply_segment(segment):
            return True
    return False


def command_segments(command: str) -> list[list[str]]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    segments: list[list[str]] = []
    current: list[str] = []

    for token in tokens:
        if token in CONTROL_TOKENS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)

    if current:
        segments.append(current)

    return segments


def is_terraform_apply_segment(tokens: list[str]) -> bool:
    tokens = strip_environment_prefix(tokens)
    if not tokens:
        return False

    first = command_name(tokens[0])
    terraform_args: list[str]

    if first in TERRAFORM_BINARIES:
        terraform_args = tokens[1:]
    elif first == "mise":
        terraform_args = terraform_args_from_mise(tokens)
    else:
        return False

    if terraform_args and command_name(terraform_args[0]) in TERRAFORM_BINARIES:
        terraform_args = terraform_args[1:]

    return "apply" in terraform_args


def strip_environment_prefix(tokens: list[str]) -> list[str]:
    stripped = list(tokens)

    while stripped and is_assignment(stripped[0]):
        stripped.pop(0)

    if stripped and stripped[0] == "env":
        stripped = stripped[1:]
        while stripped and (is_assignment(stripped[0]) or stripped[0].startswith("-")):
            stripped.pop(0)

    return stripped


def terraform_args_from_mise(tokens: list[str]) -> list[str]:
    if len(tokens) < 4:
        return []
    if tokens[1] not in MISE_COMMANDS or tokens[2] != "terraform":
        return []

    args = tokens[3:]
    if "--" in args:
        args = args[args.index("--") + 1 :]
    return args


def command_name(token: str) -> str:
    return os.path.basename(token)


def is_assignment(token: str) -> bool:
    name, separator, _value = token.partition("=")
    return bool(separator and name and name.replace("_", "").isalnum() and not name[0].isdigit())


if __name__ == "__main__":
    raise SystemExit(main())
