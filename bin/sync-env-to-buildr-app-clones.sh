#!/usr/bin/env bash
set -euo pipefail

source_dir=$(pwd -P)
source_name=$(basename "$source_dir")
source_env="$source_dir/.env"
repos_root="$HOME/code/buildr"

if [[ ! -f "$source_env" ]]; then
  echo "Missing source file: $source_env" >&2
  exit 1
fi

if [[ ! -d "$repos_root" ]]; then
  echo "Missing repos root: $repos_root" >&2
  exit 1
fi

if [[ ! "$source_name" =~ ^app([0-9]+)?$ ]]; then
  echo "Run this script from a buildr app repo (app, app2, app3, ...)." >&2
  exit 1
fi

repos=()
while IFS= read -r repo; do
  repos+=("$repo")
done < <(fd -t d -a -d 1 '^app([0-9]+)?$' "$repos_root" | sort)

if [[ ${#repos[@]} -eq 0 ]]; then
  echo "No buildr app repos found under $repos_root" >&2
  exit 1
fi

synced=0

for repo in "${repos[@]}"; do
  repo=${repo%/}

  if [[ "$repo" == "$source_dir" ]]; then
    continue
  fi

  cp "$source_env" "$repo/.env"
  echo "Synced $source_env -> $repo/.env"
  synced=$((synced + 1))
done

if [[ $synced -eq 0 ]]; then
  echo "No target repos found."
  exit 0
fi

echo "Synced .env to $synced repo(s)."
