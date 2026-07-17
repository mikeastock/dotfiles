from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Sequence


REVIEW_BRANCH = "review-council-head"


class ReviewError(RuntimeError):
    pass


class ReviewTimeout(ReviewError):
    pass


class ReviewCancelled(ReviewError):
    pass


@dataclasses.dataclass(frozen=True)
class Scope:
    repository: Path
    fixed_point: str
    fixed_sha: str
    merge_base_sha: str
    head_ref: str
    head_sha: str
    changed_files: int
    diff_stat: str
    dirty_entries: int


@dataclasses.dataclass(frozen=True)
class Dependencies:
    claude: Path
    pi: Path
    grok_wrapper: Path
    thermo_skill: Path


class ProcessRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._processes: dict[subprocess.Popen[bytes], Path] = {}
        self._protected_paths: set[Path] = set()
        self.cancelled = threading.Event()

    def add(self, process: subprocess.Popen[bytes], cwd: Path) -> None:
        with self._lock:
            self._processes[process] = cwd

    def discard(self, process: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._processes.pop(process, None)

    def terminate_all(self) -> None:
        self.cancelled.set()
        with self._lock:
            processes = list(self._processes.items())
        for process, cwd in processes:
            if not terminate_process_group(process):
                self.protect_path(cwd)

    def protect_path(self, path: Path) -> None:
        with self._lock:
            self._protected_paths.add(path)

    def protected_paths(self) -> set[Path]:
        with self._lock:
            return set(self._protected_paths)


def fail(message: str) -> ReviewError:
    return ReviewError(message)


def run_external(
    command: Sequence[str],
    *,
    cwd: Path,
    text: bool,
    deadline: float | None = None,
    registry: ProcessRegistry | None = None,
    protected_path: Path | None = None,
) -> subprocess.CompletedProcess:
    if deadline is not None and registry is None:
        raise ValueError("a deadline requires process registry ownership")
    if registry is None:
        return subprocess.run(
            list(command),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            check=False,
        )

    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        start_new_session=True,
    )
    owned_path = protected_path or cwd
    registry.add(process, owned_path)
    try:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                if registry.cancelled.is_set():
                    if not terminate_process_group(process):
                        registry.protect_path(owned_path)
                    raise ReviewCancelled("cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    if not terminate_process_group(process):
                        registry.protect_path(owned_path)
                    raise ReviewTimeout(f"command timed out: {command[0]}")
        if process_group_exists(process) and not terminate_process_group(process):
            registry.protect_path(owned_path)
            raise ReviewError(f"command descendants could not be terminated: {command[0]}")
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    finally:
        registry.discard(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def run_git(
    repository: Path,
    *args: str,
    text: bool = True,
    deadline: float | None = None,
    registry: ProcessRegistry | None = None,
    protected_path: Path | None = None,
) -> str | bytes:
    completed = run_external(
        ["git", "-C", str(repository), *args],
        cwd=repository,
        text=text,
        deadline=deadline,
        registry=registry,
        protected_path=protected_path,
    )
    if completed.returncode != 0:
        stderr = (
            completed.stderr.strip()
            if text
            else completed.stderr.decode(errors="replace").strip()
        )
        raise fail(f"git {' '.join(args)} failed: {stderr}")
    return completed.stdout.strip() if text else completed.stdout


def resolve_commit(
    repository: Path,
    ref: str,
    label: str,
    deadline: float | None = None,
    registry: ProcessRegistry | None = None,
) -> str:
    try:
        sha = run_git(
            repository,
            "rev-parse",
            "--verify",
            f"{ref}^{{commit}}",
            deadline=deadline,
            registry=registry,
        )
    except ReviewError as error:
        raise fail(f"{label} does not resolve to a commit: {ref} ({error})") from error
    assert isinstance(sha, str)
    return sha


def remote_default_ref(
    repository: Path,
    deadline: float | None = None,
    registry: ProcessRegistry | None = None,
) -> str:
    symbolic = run_external(
        ["git", "-C", str(repository), "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        cwd=repository,
        text=True,
        deadline=deadline,
        registry=registry,
    )
    if symbolic.returncode == 0 and symbolic.stdout.strip():
        return symbolic.stdout.strip().removeprefix("refs/remotes/")
    exists = run_external(
        ["git", "-C", str(repository), "rev-parse", "--verify", "--quiet", "origin/main"],
        cwd=repository,
        text=True,
        deadline=deadline,
        registry=registry,
    )
    if exists.returncode == 0:
        return "origin/main"
    raise fail("--against-main requires refs/remotes/origin/HEAD or origin/main")


def resolve_pr(
    repository: Path,
    target: str,
    deadline: float | None = None,
    registry: ProcessRegistry | None = None,
) -> tuple[str, str, str, str]:
    gh = shutil.which("gh")
    if gh is None:
        raise fail("gh is required to resolve a pull request")
    completed = run_external(
        [
            gh,
            "pr",
            "view",
            target,
            "--json",
            "number,headRefOid,baseRefOid,headRefName,baseRefName",
        ],
        cwd=repository,
        text=True,
        deadline=deadline,
        registry=registry,
    )
    if completed.returncode != 0:
        raise fail(f"could not resolve PR {target}: {completed.stderr.strip()}")
    try:
        metadata = json.loads(completed.stdout)
        number = str(metadata["number"])
        base_sha = str(metadata["baseRefOid"])
        head_sha = str(metadata["headRefOid"])
        base_name = str(metadata["baseRefName"])
        head_name = str(metadata["headRefName"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise fail(f"PR {target} returned incomplete metadata") from error
    if not all((number, base_sha, head_sha, base_name, head_name)):
        raise fail(f"PR {target} returned empty fixed-point metadata")
    resolve_commit(repository, base_sha, "PR base SHA", deadline, registry)
    resolve_commit(repository, head_sha, "PR head SHA", deadline, registry)
    return f"PR #{number} ({base_name})", base_sha, head_name, head_sha


def resolve_scope(
    args: argparse.Namespace,
    deadline: float | None = None,
    registry: ProcessRegistry | None = None,
) -> Scope:
    repository = Path(args.repo).expanduser().resolve()
    root = Path(
        str(
            run_git(
                repository,
                "rev-parse",
                "--show-toplevel",
                deadline=deadline,
                registry=registry,
            )
        )
    ).resolve()
    if root != repository:
        repository = root

    dirty_output = run_git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        text=False,
        deadline=deadline,
        registry=registry,
    )
    assert isinstance(dirty_output, bytes)
    dirty_entries = len([entry for entry in dirty_output.split(b"\0") if entry])
    if dirty_entries and not args.allow_dirty:
        raise fail(
            f"working tree has {dirty_entries} dirty entries; rerun with --allow-dirty only after confirming they must be excluded"
        )

    if args.pr:
        fixed_point, fixed_sha, pr_head_ref, pr_head_sha = resolve_pr(
            repository, args.pr, deadline, registry
        )
        head_ref = args.head or "HEAD"
        head_sha = resolve_commit(repository, head_ref, "head", deadline, registry)
        if head_sha != pr_head_sha:
            raise fail(
                f"selected head {head_sha} does not match the pinned PR head {pr_head_sha}; prepare the exact PR checkout first"
            )
        head_ref = f"{pr_head_ref}@{pr_head_sha[:12]}"
    else:
        head_ref = args.head or "HEAD"
        head_sha = resolve_commit(repository, head_ref, "head", deadline, registry)
        fixed_point = (
            remote_default_ref(repository, deadline, registry)
            if args.against_main
            else args.base
        )
        fixed_sha = resolve_commit(repository, fixed_point, "fixed point", deadline, registry)

    merge_base_sha = str(
        run_git(
            repository,
            "merge-base",
            fixed_sha,
            head_sha,
            deadline=deadline,
            registry=registry,
        )
    )
    diff_check = run_external(
        ["git", "-C", str(repository), "diff", "--quiet", f"{merge_base_sha}..{head_sha}"],
        cwd=repository,
        text=True,
        deadline=deadline,
        registry=registry,
    )
    if diff_check.returncode == 0:
        raise fail(f"review scope is empty: {fixed_sha}...{head_sha}")
    if diff_check.returncode != 1:
        raise fail("could not validate the pinned review diff")

    names = run_git(
        repository,
        "diff",
        "--name-only",
        "-z",
        f"{merge_base_sha}..{head_sha}",
        text=False,
        deadline=deadline,
        registry=registry,
    )
    assert isinstance(names, bytes)
    changed_files = len([name for name in names.split(b"\0") if name])
    diff_stat = str(
        run_git(
            repository,
            "diff",
            "--shortstat",
            f"{merge_base_sha}..{head_sha}",
            deadline=deadline,
            registry=registry,
        )
    )
    return Scope(
        repository=repository,
        fixed_point=fixed_point,
        fixed_sha=fixed_sha,
        merge_base_sha=merge_base_sha,
        head_ref=head_ref,
        head_sha=head_sha,
        changed_files=changed_files,
        diff_stat=diff_stat,
        dirty_entries=dirty_entries,
    )


def create_run_directory(requested: str | None) -> Path:
    previous_umask = os.umask(0o077)
    try:
        if requested:
            run_dir = Path(requested).expanduser().resolve()
            if run_dir.exists():
                raise fail(f"run directory already exists: {run_dir}")
            try:
                run_dir.mkdir(parents=True, mode=0o700)
            except FileExistsError as error:
                raise fail(f"run directory already exists: {run_dir}") from error
        else:
            parent = Path(os.environ.get("TMPDIR", "/tmp"))
            run_dir = Path(
                tempfile.mkdtemp(
                    prefix=f"review-council-{os.getuid()}-",
                    dir=parent,
                )
            )
    finally:
        os.umask(previous_umask)
    run_dir.chmod(0o700)
    return run_dir


def read_brief(path_value: str) -> str:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise fail(f"review brief is unavailable: {path}")
    if path.stat().st_size > 64 * 1024:
        raise fail("review brief must be 64 KiB or smaller")
    try:
        brief = path.read_text(errors="strict").strip()
    except UnicodeDecodeError as error:
        raise fail("review brief must be UTF-8 text") from error
    if not brief:
        raise fail("review brief must not be empty")
    if "\0" in brief:
        raise fail("review brief contains a NUL byte")
    return brief


def locate_dependencies() -> Dependencies:
    script = Path(__file__).resolve()
    skills_dir = script.parents[2]

    def executable(command: str) -> Path:
        resolved = shutil.which(command)
        if not resolved:
            raise fail(f"required command is unavailable: {command}")
        path = Path(resolved).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise fail(f"required command is not executable: {path}")
        return path

    grok_relative = Path("grok-review/scripts/run_review.sh")
    thermo_relative = Path("thermo-nuclear-code-review/SKILL.md")
    roots = [
        skills_dir,
        Path.home() / ".agents" / "skills",
        Path.home() / ".claude" / "skills",
    ]
    bundle = next(
        (
            (root / grok_relative, root / thermo_relative)
            for root in roots
            if (root / grok_relative).is_file()
            and (root / thermo_relative).is_file()
        ),
        None,
    )
    if bundle is None:
        raise fail("Grok and Thermo managed resources are unavailable from one skill root")
    grok_wrapper, thermo_skill = (path.resolve() for path in bundle)
    if not os.access(grok_wrapper, os.X_OK):
        raise fail(f"canonical Grok review wrapper is not executable: {grok_wrapper}")
    return Dependencies(
        claude=executable("claude"),
        pi=executable("pi"),
        grok_wrapper=grok_wrapper,
        thermo_skill=thermo_skill,
    )


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def prepare_clone(
    scope: Scope,
    clone: Path,
    deadline: float | None = None,
    registry: ProcessRegistry | None = None,
) -> None:
    try:
        run_git(
            scope.repository,
            "clone",
            "--no-local",
            "--no-checkout",
            "--quiet",
            str(scope.repository),
            str(clone),
            deadline=deadline,
            registry=registry,
            protected_path=clone,
        )
        run_git(
            clone,
            "update-ref",
            "refs/remotes/origin/main",
            scope.fixed_sha,
            deadline=deadline,
            registry=registry,
        )
        run_git(
            clone,
            "update-ref",
            "refs/heads/main",
            scope.fixed_sha,
            deadline=deadline,
            registry=registry,
        )
        run_external(
            ["git", "-C", str(clone), "update-ref", "-d", "refs/remotes/origin/master"],
            cwd=clone,
            text=True,
            deadline=deadline,
            registry=registry,
        )
        run_git(
            clone,
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
            deadline=deadline,
            registry=registry,
        )
        run_git(
            clone,
            "checkout",
            "--quiet",
            "-B",
            REVIEW_BRANCH,
            scope.head_sha,
            deadline=deadline,
            registry=registry,
        )
        run_git(
            clone,
            "remote",
            "set-url",
            "origin",
            "disabled://review-council",
            deadline=deadline,
            registry=registry,
        )
        run_git(
            clone,
            "config",
            "remote.origin.pushurl",
            "disabled://review-council",
            deadline=deadline,
            registry=registry,
        )
    except Exception:
        protected_paths = registry.protected_paths() if registry is not None else set()
        if clone.exists() and clone not in protected_paths:
            shutil.rmtree(clone)
        raise


def process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_for_process_group_exit(process: subprocess.Popen[bytes], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_group_exists(process):
            return True
        time.sleep(0.05)
    return not process_group_exists(process)


def terminate_process_group(process: subprocess.Popen[bytes]) -> bool:
    if not process_group_exists(process):
        process.poll()
        return True
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    if wait_for_process_group_exit(process, 5):
        process.poll()
        return True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    stopped = wait_for_process_group_exit(process, 5)
    process.poll()
    return stopped


def run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    deadline: float,
    registry: ProcessRegistry,
    stdin_path: Path | None = None,
    honor_cancellation: bool = True,
) -> int:
    stdin = stdin_path.open("rb") if stdin_path else subprocess.DEVNULL
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            registry.add(process, cwd)
            try:
                while process.poll() is None:
                    if honor_cancellation and registry.cancelled.is_set():
                        if not terminate_process_group(process):
                            registry.protect_path(cwd)
                        raise ReviewCancelled("cancelled")
                    if time.monotonic() >= deadline:
                        if not terminate_process_group(process):
                            registry.protect_path(cwd)
                        raise ReviewTimeout("timed out")
                    time.sleep(0.05)
                if process_group_exists(process) and not terminate_process_group(process):
                    registry.protect_path(cwd)
                    raise ReviewError("reviewer descendants could not be terminated")
                return process.returncode
            finally:
                registry.discard(process)
    finally:
        if stdin_path:
            stdin.close()
