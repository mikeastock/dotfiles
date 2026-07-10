#!/usr/bin/env bash

set -euo pipefail

reference_root=${EFFECT_REFERENCE_ROOT:-/data/workspace/code/oss}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

ensure_reference_repo() {
    local path=$1
    local url=$2
    local project=$3
    local marker=$4

    if [ ! -e "$path" ]; then
        git clone "$url" "$path"
    elif [ ! -d "$path" ]; then
        fail "Reference path exists but is not a directory: $path"
    fi

    local root
    root=$(git -C "$path" rev-parse --show-toplevel 2>/dev/null) || fail "Reference path is not a Git checkout: $path"
    if [ "$root" != "$path" ]; then
        fail "Reference path is not the checkout root: $path"
    fi
    git -C "$path" rev-parse --verify 'HEAD^{commit}' >/dev/null 2>&1 || fail "Reference checkout has no checked-out commit: $path"
    test -f "$path/$marker" || fail "Reference checkout is missing $marker: $path"

    local origin
    origin=$(git -C "$path" remote get-url origin 2>/dev/null) || fail "Reference checkout has no origin: $path"

    local slug
    case "$origin" in
        https://github.com/*)
            slug=${origin#https://github.com/}
            ;;
        git@github.com:*)
            slug=${origin#git@github.com:}
            ;;
        *)
            fail "Reference checkout has the wrong origin: $path ($origin)"
            ;;
    esac
    slug=${slug%.git}

    case "$project:$slug" in
        effect-smol:Effect-TS/effect-smol | \
        opencode:anomalyco/opencode | \
        opencode:sst/opencode | \
        executor:UsefulSoftwareCo/executor | \
        executor:RhysSullivan/executor) ;;
        *)
            fail "Reference checkout has the wrong origin: $path ($origin)"
            ;;
    esac
}

mkdir -p "$reference_root"
ensure_reference_repo "$reference_root/effect-smol" https://github.com/Effect-TS/effect-smol effect-smol LLMS.md
ensure_reference_repo "$reference_root/opencode" https://github.com/anomalyco/opencode opencode packages/core/src/catalog.ts
ensure_reference_repo "$reference_root/executor" https://github.com/UsefulSoftwareCo/executor executor packages/core/sdk/src/fuma-runtime.ts
