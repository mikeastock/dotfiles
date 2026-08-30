#!/usr/bin/env bash
#
# Build a fresh local Letta trajectory data root for one skill-doctor run:
# install @letta-ai/trajectory (with the bundled grok-build pnpm patch) under
# the root, normalize locally discoverable agent sessions, and build the
# history index.
#
# Usage: ingest.sh --root PATH [--days N] [--source NAME]... [--limit N]
#
# --root is required and should be a new directory per run (for example
# "$REPORT_DIR/trajectories"). Nothing outside it is read or written except
# the native session stores (read-only) and pnpm's global store cache.
#
# Everything stays on this machine.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="$SCRIPT_DIR/trajectories"

ROOT=""
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --root)
            ROOT="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

[ -n "$ROOT" ] || { echo "error: --root PATH is required" >&2; exit 2; }
command -v node >/dev/null || { echo "error: node (>=22, for node:sqlite) is required" >&2; exit 1; }
command -v pnpm >/dev/null || { echo "error: pnpm is required (corepack enable, or mise use -g pnpm)" >&2; exit 1; }

mkdir -p "$ROOT/state" "$ROOT/normalized" "$ROOT/patches"
cp "$PIPELINE_DIR/package.json" "$ROOT/package.json"
cp "$PIPELINE_DIR/pnpm-workspace.yaml" "$ROOT/pnpm-workspace.yaml"
cp "$PIPELINE_DIR"/patches/*.patch "$ROOT/patches/"

echo "Trajectory root: $ROOT"
(cd "$ROOT" && pnpm install --silent --prefer-offline)

node "$PIPELINE_DIR/normalize.mjs" --root "$ROOT" "${ARGS[@]}" || echo "normalize finished with errors; continuing to combine" >&2
node "$PIPELINE_DIR/combine.mjs" --root "$ROOT"
