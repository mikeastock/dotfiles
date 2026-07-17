from __future__ import annotations

import dataclasses
import json
import re
import shutil
import time
from pathlib import Path

from review_core import (
    Dependencies,
    ProcessRegistry,
    REVIEW_BRANCH,
    Scope,
    fail,
    run_process,
    write_json,
)


@dataclasses.dataclass(frozen=True)
class ReviewContext:
    scope: Scope
    brief: str
    dependencies: Dependencies
    registry: ProcessRegistry


def parse_fable_result(stream: Path, output: Path) -> None:
    event_counts = {"json": 0, "malformed_json": 0, "result": 0}
    terminal_events: list[dict[str, object]] = []
    for line in stream.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            event_counts["malformed_json"] += 1
            continue
        if not isinstance(event, dict):
            event_counts["malformed_json"] += 1
            continue
        event_counts["json"] += 1
        if event.get("type") == "result":
            event_counts["result"] += 1
            terminal_events.append(event)
    terminal = terminal_events[-1] if terminal_events else {}
    valid = (
        terminal.get("subtype") == "success"
        and terminal.get("is_error") is False
        and terminal.get("terminal_reason") in (None, "completed")
        and isinstance(terminal.get("result"), str)
        and bool(str(terminal["result"]).strip())
    )
    if not valid:
        write_json(
            output.parent / "result-diagnostic.json",
            {
                "bytes": stream.stat().st_size,
                "event_counts": event_counts,
                "terminal_event_count": len(terminal_events),
                "last_terminal_subtype": terminal.get("subtype"),
                "last_terminal_is_error": terminal.get("is_error"),
                "last_terminal_reason": terminal.get("terminal_reason"),
            },
        )
        raise fail("Fable stream has no non-empty final result event")
    output.write_text(str(terminal["result"]).strip() + "\n")


def review_prompt(context: ReviewContext, reviewer: str) -> str:
    scope = context.scope
    common = f"""Review only. Do not edit files, commit, push, post comments, deploy, or implement findings.
Repository scope is pinned and immutable for this run:
- fixed point: {scope.fixed_sha}
- merge base: {scope.merge_base_sha}
- head: {scope.head_sha}
- diff: git diff {scope.fixed_sha}...{scope.head_sha}

Inspect repository instructions and the complete changed-file context. Return findings first, ordered by severity, with file and line references. State explicitly when there are no findings. Do not treat another reviewer's absence or failure as approval.

Task-specific review brief:
{context.brief}
"""
    if reviewer == "fable":
        return "You are the trusted senior Fable reviewer. Focus on correctness, regressions, architecture, security, data integrity, and missing tests.\n\n" + common
    return "Use $thermo-nuclear-code-review for its strict structural and architectural code-quality review.\n\n" + common


def run_fable(context: ReviewContext, clone: Path, output_dir: Path, deadline: float) -> Path:
    prompt = output_dir / "prompt.md"
    stream = output_dir / "stream.jsonl"
    stderr = output_dir / "stderr.log"
    output = output_dir / "review.md"
    prompt.write_text(review_prompt(context, "fable"))
    command = [
        str(context.dependencies.claude),
        "-p",
        "--model",
        "claude-fable-5",
        "--effort",
        "high",
        "--output-format",
        "stream-json",
        "--include-partial-messages",
        "--include-hook-events",
        "--tools",
        "Read,Bash",
        "--allowedTools",
        "Read,Bash",
    ]
    try:
        code = run_process(
            command,
            cwd=clone,
            stdout_path=stream,
            stderr_path=stderr,
            deadline=deadline,
            registry=context.registry,
            stdin_path=prompt,
        )
        if code != 0:
            raise fail(f"Fable exited {code}; inspect {stderr}")
        parse_fable_result(stream, output)
    finally:
        stream.unlink(missing_ok=True)
        prompt.unlink(missing_ok=True)
    return output


def run_grok(context: ReviewContext, clone: Path, output_dir: Path, deadline: float) -> Path:
    prompt = output_dir / "prompt.md"
    prompt.write_text(f"/review --branch {REVIEW_BRANCH}\n")
    grok_run = output_dir / "run"
    wrapper = str(context.dependencies.grok_wrapper)
    completed = False
    primary_error: BaseException | None = None
    try:
        start_code = run_process(
            [wrapper, "start", str(clone), str(prompt), str(grok_run)],
            cwd=clone,
            stdout_path=output_dir / "start.log",
            stderr_path=output_dir / "start.stderr.log",
            deadline=deadline,
            registry=context.registry,
        )
        if start_code != 0:
            raise fail(f"Grok launcher exited {start_code}; inspect {output_dir / 'start.stderr.log'}")
        wait_code = run_process(
            [wrapper, "wait", str(grok_run)],
            cwd=clone,
            stdout_path=output_dir / "wait.log",
            stderr_path=output_dir / "wait.stderr.log",
            deadline=deadline,
            registry=context.registry,
        )
        if wait_code != 0:
            raise fail(f"Grok wait exited {wait_code}; inspect {output_dir / 'wait.stderr.log'}")
        source = grok_run / "review.md"
        if not source.is_file() or not source.read_text(errors="replace").strip():
            raise fail(f"Grok completed without a non-empty review: {source}")
        output = output_dir / "review.md"
        shutil.copyfile(source, output)
        completed = True
        return output
    except BaseException as error:
        primary_error = error
        raise
    finally:
        prompt.unlink(missing_ok=True)
        if not completed and (grok_run / "zmx-session").is_file():
            try:
                cleanup_code = run_process(
                    [wrapper, "stop", str(grok_run)],
                    cwd=clone,
                    stdout_path=output_dir / "stop.log",
                    stderr_path=output_dir / "stop.stderr.log",
                    deadline=time.monotonic() + 20,
                    registry=context.registry,
                    honor_cancellation=False,
                )
                if cleanup_code != 0:
                    raise fail(
                        f"canonical Grok stop exited {cleanup_code}; inspect {output_dir / 'stop.stderr.log'}"
                    )
            except Exception as cleanup_error:
                context.registry.protect_path(clone)
                if primary_error is None:
                    raise
                primary_error.add_note(f"Grok cleanup also failed: {cleanup_error}")


def thermo_verdict_prefixes(skill: Path) -> tuple[str, ...]:
    content = skill.read_text(errors="replace")
    marker = "### Verdict"
    if marker not in content:
        raise fail(f"Thermo-Nuclear skill has no verdict contract: {skill}")
    verdict_section = content.split(marker, 1)[1].split("\n---", 1)[0]
    labels = re.findall(r"^\*\*([A-Z][A-Z-]*)\*\* — ", verdict_section, re.MULTILINE)
    if not labels:
        raise fail(f"Thermo-Nuclear skill has no machine-readable verdict labels: {skill}")
    return tuple(f"**{label}** — " for label in labels)


def validate_thermo_result(path: Path, skill: Path) -> None:
    review = path.read_text(errors="replace").strip()
    prefixes = thermo_verdict_prefixes(skill)
    verdict = re.compile(
        r"^(?:" + "|".join(re.escape(prefix) for prefix in prefixes) + r").*\S$",
        re.MULTILINE,
    )
    matches = verdict.findall(review)
    final_line = review.splitlines()[-1] if review else ""
    final_line_is_verdict = verdict.fullmatch(final_line) is not None
    if len(matches) != 1 or not final_line_is_verdict:
        write_json(
            path.parent / "result-diagnostic.json",
            {
                "bytes": path.stat().st_size,
                "lines": len(review.splitlines()),
                "final_line_is_plugin_verdict": final_line_is_verdict,
                "plugin_verdict_labels": len(prefixes),
                "plugin_verdict_lines": len(matches),
            },
        )
        raise fail("Thermo-Nuclear completed without exactly one final plugin verdict")


def run_thermo(context: ReviewContext, clone: Path, output_dir: Path, deadline: float) -> Path:
    prompt = output_dir / "prompt.md"
    output = output_dir / "review.md"
    partial = output_dir / "review.partial.md"
    stderr = output_dir / "stderr.log"
    prompt.write_text(review_prompt(context, "thermo"))
    command = [
        str(context.dependencies.pi),
        "--print",
        "--no-session",
        "--no-extensions",
        "--no-prompt-templates",
        "--skill",
        str(context.dependencies.thermo_skill),
        "--tools",
        "read,bash,grep,find,ls",
        f"@{prompt}",
    ]
    try:
        code = run_process(
            command,
            cwd=clone,
            stdout_path=partial,
            stderr_path=stderr,
            deadline=deadline,
            registry=context.registry,
        )
        if code != 0:
            raise fail(f"Thermo-Nuclear exited {code}; inspect {stderr}")
        validate_thermo_result(partial, context.dependencies.thermo_skill)
        partial.replace(output)
        return output
    finally:
        partial.unlink(missing_ok=True)
        prompt.unlink(missing_ok=True)
