#!/usr/bin/env python3
"""Share browser-viewable HTML artifacts to Buildr artifact storage."""

from __future__ import annotations

import argparse
import atexit
import mimetypes
import os
import random
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

CONTENT_TYPES = {
    ".css": "text/css",
    ".gif": "image/gif",
    ".html": "text/html",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "application/javascript",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ttf": "font/ttf",
    ".txt": "text/plain",
    ".webp": "image/webp",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".xml": "application/xml",
}

ADJECTIVES = [
    "agile",
    "amber",
    "bold",
    "brave",
    "bright",
    "calm",
    "clear",
    "clever",
    "cobalt",
    "crisp",
    "daring",
    "deep",
    "eager",
    "fast",
    "fresh",
    "golden",
    "green",
    "happy",
    "ivory",
    "keen",
    "lively",
    "lucid",
    "maple",
    "merry",
    "noble",
    "onyx",
    "opal",
    "quick",
    "quiet",
    "rapid",
    "silver",
    "solar",
    "steady",
    "swift",
    "tidy",
    "vivid",
]

NOUNS = [
    "anchor",
    "badge",
    "beacon",
    "brook",
    "canvas",
    "cedar",
    "comet",
    "ember",
    "field",
    "forge",
    "garden",
    "harbor",
    "kernel",
    "lantern",
    "meadow",
    "orbit",
    "panda",
    "pixel",
    "river",
    "rocket",
    "signal",
    "summit",
    "thicket",
    "tiger",
    "valley",
    "window",
]

DEFAULT_BUCKET = "buildr-bizops-artifacts"
DEFAULT_BASE_URL = "https://artifacts.buildrtools.com"
DEFAULT_MAX_FILES = 2000
DEFAULT_MAX_DEPTH = 20
MAX_FILE_BYTES = 1_073_741_824


@dataclass(frozen=True)
class ArtifactFile:
    absolute_path: Path
    relative_path: str
    expected_stat: os.stat_result
    root_real_path: Path


def main() -> int:
    args = parse_args()
    try:
        artifact_files = collect_input_files(args)
        slug = generate_slug()
        upload_files(artifact_files, slug)
        print(build_url(base_url(), slug))
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload an HTML artifact and print its Buildr share URL."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", help="Local .html file or directory containing index.html")
    source.add_argument("--html-file", help="File whose contents should be uploaded as index.html")
    source.add_argument("--html", help="Inline HTML to upload as index.html")
    return parser.parse_args()


def collect_input_files(args: argparse.Namespace) -> list[ArtifactFile]:
    if args.html is not None:
        return [inline_html_file(args.html)]
    if args.html_file is not None:
        return single_html_file(Path(args.html_file).expanduser())
    return collect_path(Path(args.path).expanduser())


def inline_html_file(html: str) -> ArtifactFile:
    if not html.strip():
        raise ValueError("--html cannot be empty")

    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".html", delete=False)
    with tmp:
        tmp.write(html)
    atexit.register(lambda: Path(tmp.name).unlink(missing_ok=True))
    return single_html_file(Path(tmp.name))


def collect_path(path: Path) -> list[ArtifactFile]:
    resolved = path.resolve(strict=False)
    stat = lstat_no_symlink(resolved, f"Path does not exist: {resolved}")
    if is_regular_file(stat):
        return [html_artifact_file(resolved, stat)]
    if not is_directory(stat):
        raise ValueError(f"Path is neither a file nor a directory: {resolved}")

    root_real_path = resolved.resolve(strict=True)
    index_path = resolved / "index.html"
    index_stat = lstat_no_symlink(
        index_path, f"Directory must contain an index.html at its root: {resolved}", root_real_path
    )
    if not is_regular_file(index_stat):
        raise ValueError(f"index.html must be a regular file: {index_path}")

    files: list[ArtifactFile] = []
    walk_dir(resolved, resolved, 0, root_real_path, files)
    return files


def single_html_file(path: Path) -> ArtifactFile:
    resolved = path.resolve(strict=False)
    stat = lstat_no_symlink(resolved, f"Path does not exist: {resolved}")
    return html_artifact_file(resolved, stat)


def html_artifact_file(path: Path, stat: os.stat_result) -> ArtifactFile:
    if not is_regular_file(stat):
        raise ValueError(f"Path is not a regular file: {path}")
    if path.suffix.lower() != ".html":
        raise ValueError(f"Single file must be an .html file: {path}")
    assert_file_size(path, stat)
    return ArtifactFile(
        absolute_path=path,
        relative_path="index.html",
        expected_stat=stat,
        root_real_path=path.resolve(strict=True),
    )


def walk_dir(
    base_dir: Path,
    current_dir: Path,
    depth: int,
    root_real_path: Path,
    files: list[ArtifactFile],
) -> None:
    if depth > DEFAULT_MAX_DEPTH:
        raise ValueError(f"Artifact depth limit exceeded ({DEFAULT_MAX_DEPTH}): {current_dir}")
    if len(files) >= DEFAULT_MAX_FILES:
        raise ValueError(f"Artifact file count limit exceeded ({DEFAULT_MAX_FILES} files)")

    for entry in sorted(current_dir.iterdir(), key=lambda p: p.name):
        stat = lstat_no_symlink(entry, f"Path does not exist: {entry}", root_real_path)
        if is_directory(stat):
            walk_dir(base_dir, entry, depth + 1, root_real_path, files)
            continue
        if not is_regular_file(stat):
            raise ValueError(f"Only regular files and directories are allowed: {entry}")

        assert_allowed_extension(entry)
        assert_file_size(entry, stat)
        files.append(
            ArtifactFile(
                absolute_path=entry,
                relative_path=entry.relative_to(base_dir).as_posix(),
                expected_stat=stat,
                root_real_path=root_real_path,
            )
        )


def lstat_no_symlink(path: Path, missing_error: str, root_real_path: Path | None = None) -> os.stat_result:
    try:
        stat = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(missing_error) from exc
    except NotADirectoryError as exc:
        raise ValueError(missing_error) from exc
    except OSError as exc:
        if exc.errno == 40:
            raise ValueError(f"symlink paths are not allowed: {path}") from exc
        raise

    if is_symlink(stat):
        raise ValueError(f"symlink paths are not allowed: {path}")
    if root_real_path is not None:
        assert_real_path_within_root(root_real_path, path)
    return stat


def assert_allowed_extension(path: Path) -> None:
    if path.suffix.lower() not in CONTENT_TYPES:
        suffix = path.suffix.lower() or "none"
        raise ValueError(f"Unsupported file extension for artifact sharing: {path} ({suffix})")


def assert_file_size(path: Path, stat: os.stat_result) -> None:
    if stat.st_size > MAX_FILE_BYTES:
        raise ValueError(f"Artifact file too large (>1 GiB): {path}")


def assert_real_path_within_root(root_real_path: Path, path: Path) -> None:
    file_real_path = path.resolve(strict=True)
    try:
        file_real_path.relative_to(root_real_path)
    except ValueError as exc:
        raise ValueError(f"Path resolves outside artifact root: {path}") from exc


def read_file_safely(file: ArtifactFile) -> bytes:
    assert_real_path_within_root(file.root_real_path, file.absolute_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(file.absolute_path, flags)
    try:
        opened_stat = os.fstat(fd)
        if not is_regular_file(opened_stat):
            raise ValueError(f"Path is not a regular file: {file.absolute_path}")
        if (
            opened_stat.st_dev != file.expected_stat.st_dev
            or opened_stat.st_ino != file.expected_stat.st_ino
            or opened_stat.st_size != file.expected_stat.st_size
        ):
            raise ValueError(f"Path changed while sharing artifact: {file.absolute_path}")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def upload_files(files: list[ArtifactFile], slug: str) -> None:
    if not files:
        raise ValueError("No artifact files found")
    if shutil.which("aws") is None:
        raise ValueError("aws CLI is required but was not found on PATH")

    env = aws_cli_env(os.environ)
    for file in files:
        body = read_file_safely(file)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        try:
            run_aws_put_object(
                env=env,
                key=f"{slug}/{file.relative_path}",
                body_path=tmp_path,
                content_type=content_type_for(file.relative_path),
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)


def run_aws_put_object(env: dict[str, str], key: str, body_path: str, content_type: str) -> None:
    command = [
        "aws",
        "s3api",
        "put-object",
        "--bucket",
        bucket_name(),
        "--key",
        key,
        "--body",
        body_path,
        "--content-type",
        content_type,
        "--cache-control",
        "public, max-age=31536000, immutable",
        "--no-cli-pager",
    ]
    subprocess.run(command, env=env, check=True, stdout=subprocess.DEVNULL)


def content_type_for(relative_path: str) -> str:
    suffix = Path(relative_path).suffix.lower()
    return CONTENT_TYPES.get(suffix) or mimetypes.guess_type(relative_path)[0] or "application/octet-stream"


def aws_cli_env(source_env: dict[str, str]) -> dict[str, str]:
    env = dict(source_env)
    env["AWS_REGION"] = (
        source_env.get("ARTIFACT_AWS_REGION", "").strip()
        or source_env.get("AWS_REGION", "").strip()
        or "us-east-1"
    )
    copy_artifact_aws_env(env, source_env, "AWS_ACCESS_KEY_ID")
    copy_artifact_aws_env(env, source_env, "AWS_SECRET_ACCESS_KEY")
    copy_artifact_aws_env(env, source_env, "AWS_SESSION_TOKEN")
    return env


def copy_artifact_aws_env(env: dict[str, str], source_env: dict[str, str], aws_name: str) -> None:
    value = source_env.get(f"ARTIFACT_{aws_name}", "").strip()
    if value:
        env[aws_name] = value


def bucket_name() -> str:
    return os.environ.get("ARTIFACT_S3_BUCKET", DEFAULT_BUCKET).strip() or DEFAULT_BUCKET


def base_url() -> str:
    return (os.environ.get("ARTIFACT_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL).rstrip("/")


def generate_slug() -> str:
    return f"{random.choice(ADJECTIVES)}-{random.choice(NOUNS)}-{secrets.token_hex(2)}"


def build_url(url_base: str, slug: str) -> str:
    suffix = "/index.html" if explicit_index_html(url_base) else "/"
    return f"{url_base}/{slug}{suffix}"


def explicit_index_html(url_base: str) -> bool:
    return url_base.startswith("http://localhost:9000") or url_base.startswith("http://127.0.0.1:9000")


def is_regular_file(stat: os.stat_result) -> bool:
    return stat.st_mode & 0o170000 == 0o100000


def is_directory(stat: os.stat_result) -> bool:
    return stat.st_mode & 0o170000 == 0o040000


def is_symlink(stat: os.stat_result) -> bool:
    return stat.st_mode & 0o170000 == 0o120000


if __name__ == "__main__":
    sys.exit(main())
