#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 path/to/file.html [port]" >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 64
fi

input_path="$1"
requested_port="${2:-}"

if [[ ! -f "$input_path" ]]; then
  echo "HTML file not found: $input_path" >&2
  exit 66
fi

if [[ "${input_path##*.}" != "html" && "${input_path##*.}" != "htm" ]]; then
  echo "Expected an .html or .htm file: $input_path" >&2
  exit 65
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 69
fi

abs_file="$(python3 - "$input_path" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve())
PY
)"
serve_dir="$(dirname "$abs_file")"
file_name="$(basename "$abs_file")"

is_port_free() {
  python3 - "$1" <<'PY'
import socket
import sys
port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        sys.exit(1)
PY
}

pick_port() {
  if [[ -n "$requested_port" ]]; then
    if [[ ! "$requested_port" =~ ^[0-9]+$ ]]; then
      echo "Port must be numeric: $requested_port" >&2
      exit 65
    fi

    if ! is_port_free "$requested_port"; then
      echo "Port is already in use: $requested_port" >&2
      exit 69
    fi

    echo "$requested_port"
    return
  fi

  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("0.0.0.0", 0))
    print(sock.getsockname()[1])
PY
}

port="$(pick_port)"
pid_file="/tmp/serve-html-artifact-${port}.pid"
log_file="/tmp/serve-html-artifact-${port}.log"

if [[ -f "$pid_file" ]]; then
  old_pid="$(cat "$pid_file")"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    echo "Server already running for port $port with PID $old_pid" >&2
    exit 69
  fi
fi

(
  cd "$serve_dir"
  nohup python3 -m http.server "$port" --bind 0.0.0.0 > "$log_file" 2>&1 &
  echo "$!" > "$pid_file"
)

pid="$(cat "$pid_file")"

cleanup_on_failure() {
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
}

local_url="http://127.0.0.1:${port}/${file_name}"

verified=false
for _ in {1..30}; do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsI --max-time 1 "$local_url" >/dev/null 2>&1; then
      verified=true
      break
    fi
  else
    if python3 - "$local_url" <<'PY' >/dev/null 2>&1
from urllib.request import Request, urlopen
import sys
request = Request(sys.argv[1], method="HEAD")
with urlopen(request, timeout=1) as response:
    raise SystemExit(0 if response.status == 200 else 1)
PY
    then
      verified=true
      break
    fi
  fi
  sleep 0.2
done

if [[ "$verified" != "true" ]]; then
  cleanup_on_failure
  echo "Server did not become ready. Log: $log_file" >&2
  exit 70
fi

magic_dns=""
if command -v tailscale >/dev/null 2>&1; then
  magic_dns="$(tailscale status --self 2>/dev/null | awk 'NR == 1 { print $3 }')"
fi

if [[ -z "$magic_dns" || "$magic_dns" == "-" ]]; then
  magic_dns="$(hostname)"
fi

tailscale_url="http://${magic_dns}:${port}/${file_name}"

cat <<EOF
Serving HTML artifact
File: $abs_file
Directory: $serve_dir
PID: $pid
Log: $log_file
Local URL: $local_url
Tailscale URL: $tailscale_url
Stop: kill \$(cat $pid_file)
EOF
