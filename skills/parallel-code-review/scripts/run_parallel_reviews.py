#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import shutil
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from review_adapters import (
    ReviewContext,
    parse_fable_result,
    run_fable,
    run_grok,
    run_thermo,
    validate_thermo_result,
)
from review_core import (
    Dependencies,
    ProcessRegistry,
    ReviewCancelled,
    ReviewError,
    ReviewTimeout,
    Scope,
    create_run_directory,
    fail,
    locate_dependencies,
    prepare_clone,
    read_brief,
    resolve_scope,
    run_external,
    run_process,
    write_json,
)


REVIEWERS = ("fable", "grok", "thermo")
DEFAULT_TIMEOUT_SECONDS = 30 * 60


@dataclasses.dataclass
class ReviewResult:
    name: str
    status: str
    duration_seconds: float
    output: Path | None = None
    error: str | None = None


def run_reviewers(tasks: dict[str, Callable[[], Path]]) -> dict[str, ReviewResult]:
    results: dict[str, ReviewResult] = {}

    def execute(task: Callable[[], Path]) -> tuple[Path | None, BaseException | None, float]:
        started = time.monotonic()
        try:
            output = task()
            if not output.is_file() or not output.read_text(errors="replace").strip():
                raise ReviewError(f"reviewer returned missing or empty output: {output}")
            return output, None, time.monotonic() - started
        except BaseException as error:
            return None, error, time.monotonic() - started

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(execute, task): name for name, task in tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            output, error, duration = future.result()
            if error is None:
                results[name] = ReviewResult(name, "completed", duration, output=output)
            elif isinstance(error, ReviewTimeout):
                results[name] = ReviewResult(name, "timed_out", duration, error=str(error))
            elif isinstance(error, ReviewCancelled):
                results[name] = ReviewResult(name, "cancelled", duration, error=str(error))
            else:
                results[name] = ReviewResult(name, "failed", duration, error=str(error))
    return results


def cleanup_clones(
    clones: dict[str, Path],
    protected_paths: set[Path] | None = None,
) -> list[str]:
    errors = []
    protected_paths = protected_paths or set()
    for name, clone in clones.items():
        if clone in protected_paths:
            errors.append(
                f"{name}: cleanup skipped because owned process termination was not verified: {clone}"
            )
            continue
        try:
            if clone.exists():
                shutil.rmtree(clone)
        except OSError as error:
            errors.append(f"{name}: {error}")
    return errors


def all_reviews_completed(results: dict[str, ReviewResult]) -> bool:
    return set(results) == set(REVIEWERS) and all(
        results[name].status == "completed" for name in REVIEWERS
    )


def setup_failure_results(
    failed_name: str,
    error: Exception,
) -> dict[str, ReviewResult]:
    failed_status = "timed_out" if isinstance(error, ReviewTimeout) else "failed"
    return {
        name: ReviewResult(
            name,
            failed_status if name == failed_name else "not_started",
            0.0,
            error=(
                f"clone setup failed: {error}"
                if name == failed_name
                else f"not started because {failed_name} clone setup failed"
            ),
        )
        for name in REVIEWERS
    }


def write_summary(
    run_dir: Path,
    scope: Scope,
    results: dict[str, ReviewResult],
    cleanup_errors: list[str],
) -> Path:
    completed = sum(result.status == "completed" for result in results.values())
    if completed == len(REVIEWERS) and not cleanup_errors:
        state = "complete"
    elif completed == 0:
        state = "failed"
    else:
        state = "partial failure"
    lines = [
        "# Parallel code review",
        "",
        f"Overall: **{state}** ({completed}/{len(REVIEWERS)} reviewers completed)",
        "",
        "## Pinned scope",
        "",
        f"- Fixed point: `{scope.fixed_sha}` (`{scope.fixed_point}`)",
        f"- Merge base: `{scope.merge_base_sha}`",
        f"- Head: `{scope.head_sha}` (`{scope.head_ref}`)",
        f"- Diff: {scope.diff_stat}",
        f"- Dirty source entries excluded: {scope.dirty_entries}",
        "",
        "## Reviewer outputs",
        "",
    ]
    for name in REVIEWERS:
        result = results.get(name, ReviewResult(name, "failed", 0.0, error="missing result"))
        lines.append(f"### {name.title()}: {result.status}")
        lines.append("")
        if result.output:
            lines.append(f"Output: `{result.output}`")
        else:
            lines.append(f"Failure: {result.error or 'missing output'}")
        lines.append("")
    if cleanup_errors:
        lines.extend(
            ["## Cleanup failures", ""]
            + [f"- {error}" for error in cleanup_errors]
            + [""]
        )
    lines.append(
        "Missing or failed reviewer output is not approval. Preserve and assess each completed review separately."
    )
    summary = run_dir / "summary.md"
    summary.write_text("\n".join(lines) + "\n")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Fable, Grok, and Thermo-Nuclear reviews concurrently against one pinned Git scope."
    )
    parser.add_argument("--repo", default=".", help="Git repository root (default: current directory)")
    fixed = parser.add_mutually_exclusive_group(required=True)
    fixed.add_argument("--base", help="Explicit base branch, tag, or commit SHA")
    fixed.add_argument(
        "--against-main",
        action="store_true",
        help="Use the current remote default branch as the fixed point",
    )
    fixed.add_argument("--pr", help="Pull request number or URL; requires the exact PR head locally")
    parser.add_argument("--head", help="Reviewed head ref (default: HEAD)")
    parser.add_argument(
        "--brief-file",
        required=True,
        help="Task-specific review brief without secrets or raw repository content",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Explicitly exclude acknowledged dirty source-tree changes",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-reviewer timeout (default: 1800)",
    )
    parser.add_argument("--run-dir", help="New directory for private outputs; must not already exist")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate arguments and the pinned scope without launching reviewers",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout_seconds < 1:
        raise fail("--timeout-seconds must be a positive integer")
    registry = ProcessRegistry()
    interrupted = threading.Event()

    def handle_signal(_signum: int, _frame: object) -> None:
        interrupted.set()
        registry.cancelled.set()

    previous_handlers = {
        sig: signal.signal(sig, handle_signal)
        for sig in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        setup_deadline = time.monotonic() + args.timeout_seconds
        try:
            scope = resolve_scope(args, setup_deadline, registry)
        except ReviewCancelled:
            return 130
        if interrupted.is_set():
            return 130
        brief = read_brief(args.brief_file)
        run_dir = create_run_directory(args.run_dir)
        write_json(
            run_dir / "scope.json",
            {
                "fixed_point": scope.fixed_point,
                "fixed_sha": scope.fixed_sha,
                "merge_base_sha": scope.merge_base_sha,
                "head_ref": scope.head_ref,
                "head_sha": scope.head_sha,
                "changed_files": scope.changed_files,
                "diff_stat": scope.diff_stat,
                "dirty_entries_excluded": scope.dirty_entries,
            },
        )
        if args.dry_run:
            write_json(
                run_dir / "dry-run.json",
                {
                    "status": "scope_validated",
                    "reviewers": list(REVIEWERS),
                    "timeout_seconds": args.timeout_seconds,
                },
            )
            print(f"Validated pinned scope {scope.fixed_sha}...{scope.head_sha}")
            print(f"Dry-run artifacts: {run_dir}")
            return 0

        dependencies = locate_dependencies()
        context = ReviewContext(scope, brief, dependencies, registry)
        clones: dict[str, Path] = {}
        results: dict[str, ReviewResult] = {}
        setup_failure: tuple[str, Exception] | None = None
        try:
            reviewers_dir = run_dir / "reviewers"
            clones_dir = run_dir / "clones"
            reviewers_dir.mkdir(mode=0o700)
            clones_dir.mkdir(mode=0o700)
            for name in REVIEWERS:
                if interrupted.is_set():
                    break
                output_dir = reviewers_dir / name
                output_dir.mkdir(mode=0o700)
                clone = clones_dir / name
                clones[name] = clone
                try:
                    prepare_clone(scope, clone, setup_deadline, registry)
                except Exception as error:
                    setup_failure = (name, error)
                    break

            if interrupted.is_set():
                results = {
                    name: ReviewResult(name, "cancelled", 0.0, error="cancelled during setup")
                    for name in REVIEWERS
                }
            elif setup_failure is not None:
                failed_name, error = setup_failure
                results = setup_failure_results(failed_name, error)
            else:
                runners = {"fable": run_fable, "grok": run_grok, "thermo": run_thermo}
                tasks: dict[str, Callable[[], Path]] = {}
                for name in REVIEWERS:
                    deadline = time.monotonic() + args.timeout_seconds
                    runner = runners[name]

                    def task(
                        name: str = name,
                        runner: Callable = runner,
                        deadline: float = deadline,
                    ) -> Path:
                        return runner(context, clones[name], reviewers_dir / name, deadline)

                    tasks[name] = task
                results = run_reviewers(tasks)
        finally:
            registry.terminate_all()
            cleanup_errors = cleanup_clones(clones, registry.protected_paths())

        summary = write_summary(run_dir, scope, results, cleanup_errors)
        print(f"Parallel review artifacts: {run_dir}")
        print(f"Summary: {summary}")
        if interrupted.is_set():
            return 130
        return 0 if all_reviews_completed(results) and not cleanup_errors else 1
    finally:
        registry.terminate_all()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReviewError as error:
        print(f"parallel-code-review: {error}", file=sys.stderr)
        raise SystemExit(2)
