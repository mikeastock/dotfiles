#!/usr/bin/env python3
"""Serve a stateful Vite app on a Codexbox Tailscale address."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_PORT_START = 43000
DEFAULT_PORT_END = 43999
STATE_ROOT = Path.home() / ".cache" / "buildr-artifacts" / "vite-apps"


def main() -> int:
    args = parse_args()
    try:
        app_dir = Path(args.path).expanduser().resolve(strict=True)
        package = load_package_json(app_dir)
        assert_dev_script(package, app_dir)
        assert_npm_available()

        slug = slugify(args.slug or app_dir.name)
        port = args.port or deterministic_port(slug)
        host = args.host or tailscale_ipv4()
        url_host = resolve_url_host(
            explicit=args.url_host,
            env=os.environ,
            hostname=socket.gethostname(),
        )

        if not args.no_install:
            ensure_dependencies(app_dir)

        state_dir = STATE_ROOT / slug
        state_dir.mkdir(parents=True, exist_ok=True)
        stop_existing_process(state_dir / "pid", app_dir)
        start_vite(app_dir=app_dir, state_dir=state_dir, host=host, port=port)

        print(f"http://{url_host}:{port}/")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a Vite app on the Codexbox Tailscale IP and print its bld.run URL."
    )
    parser.add_argument("--path", required=True, help="Vite app directory containing package.json")
    parser.add_argument("--slug", help="Stable app slug for process state and default port selection")
    parser.add_argument("--port", type=valid_port, help="Port to bind; defaults to a deterministic slug-based port")
    parser.add_argument("--host", help="IP address to bind; defaults to the first `tailscale ip -4` address")
    parser.add_argument("--url-host", help="Public bld.run hostname to print; overrides BLD_RUN_HOST and local hostname derivation")
    parser.add_argument("--no-install", action="store_true", help="Do not run npm install when node_modules is missing")
    return parser.parse_args()


def valid_port(value: str) -> int:
    port = int(value)
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def load_package_json(app_dir: Path) -> dict:
    package_path = app_dir / "package.json"
    if not package_path.is_file():
        raise ValueError(f"Vite app directory must contain package.json: {app_dir}")
    try:
        with package_path.open(encoding="utf-8") as file:
            package = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(f"package.json is not valid JSON: {package_path}") from exc
    if not isinstance(package, dict):
        raise ValueError(f"package.json must contain an object: {package_path}")
    return package


def assert_dev_script(package: dict, app_dir: Path) -> None:
    scripts = package.get("scripts")
    if not isinstance(scripts, dict) or not scripts.get("dev"):
        raise ValueError(f"package.json must define scripts.dev for Vite serving: {app_dir / 'package.json'}")


def assert_npm_available() -> None:
    if shutil.which("npm") is None:
        raise ValueError("npm is required but was not found on PATH")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not slug:
        raise ValueError("App slug cannot be empty after sanitization")
    return slug


def deterministic_port(slug: str) -> int:
    digest = hashlib.sha256(slug.encode("utf-8")).hexdigest()
    span = DEFAULT_PORT_END - DEFAULT_PORT_START + 1
    return DEFAULT_PORT_START + (int(digest[:8], 16) % span)


def tailscale_ipv4() -> str:
    result = subprocess.run(
        ["tailscale", "ip", "-4"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    addresses = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not addresses:
        raise ValueError("tailscale ip -4 returned no address; pass --host explicitly")
    return addresses[0]


def resolve_url_host(*, explicit: str | None, env: dict[str, str], hostname: str) -> str:
    if explicit:
        return explicit.strip().rstrip("/")
    env_host = env.get("BLD_RUN_HOST", "").strip()
    if env_host:
        return env_host.rstrip("/")
    return url_host_from_hostname(hostname)


def url_host_from_hostname(hostname: str) -> str:
    short_hostname = hostname.split(".", 1)[0]
    if not short_hostname.startswith("codexbox-"):
        raise ValueError("Could not derive bld.run host from hostname; pass --url-host")
    user = short_hostname.removeprefix("codexbox-")
    if not user:
        raise ValueError("Could not derive bld.run host from hostname; pass --url-host")
    return f"{user}.bld.run"


def ensure_dependencies(app_dir: Path) -> None:
    if (app_dir / "node_modules").is_dir():
        return
    subprocess.run(["npm", "install"], cwd=app_dir, check=True, stdout=sys.stderr)


def stop_existing_process(pid_path: Path, app_dir: Path) -> None:
    if not pid_path.exists():
        return
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except ValueError:
        pid_path.unlink(missing_ok=True)
        return

    if not process_exists(pid):
        pid_path.unlink(missing_ok=True)
        return
    assert_managed_process(pid, app_dir, pid_path)

    os.killpg(pid, signal.SIGTERM)
    for _ in range(50):
        if not process_exists(pid):
            pid_path.unlink(missing_ok=True)
            return
        time.sleep(0.1)
    os.killpg(pid, signal.SIGKILL)
    pid_path.unlink(missing_ok=True)


def assert_managed_process(pid: int, app_dir: Path, pid_path: Path) -> None:
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return
    cwd_path = proc_root / str(pid) / "cwd"
    try:
        process_cwd = cwd_path.resolve(strict=True)
    except FileNotFoundError:
        pid_path.unlink(missing_ok=True)
        return
    if process_cwd != app_dir:
        raise ValueError(f"Refusing to stop PID {pid}; it is not running from {app_dir}. Remove stale PID file: {pid_path}")


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def start_vite(*, app_dir: Path, state_dir: Path, host: str, port: int) -> None:
    stdout_path = state_dir / "stdout.log"
    stderr_path = state_dir / "stderr.log"
    stdout_file = stdout_path.open("ab")
    stderr_file = stderr_path.open("ab")
    try:
        process = subprocess.Popen(
            vite_command(host, port),
            cwd=app_dir,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
    finally:
        stdout_file.close()
        stderr_file.close()

    (state_dir / "pid").write_text(f"{process.pid}\n", encoding="utf-8")
    time.sleep(1)
    if process.poll() is not None:
        raise ValueError(f"Vite exited immediately; inspect logs in {state_dir}")


def vite_command(host: str, port: int) -> list[str]:
    return ["npm", "run", "dev", "--", "--host", host, "--port", str(port), "--strictPort"]


if __name__ == "__main__":
    sys.exit(main())
