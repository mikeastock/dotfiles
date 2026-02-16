#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $(basename "$0") <input-png> <output-base>"
  exit 1
fi

input="$1"
base="$2"
key_color="${FAVICON_KEY_COLOR:-#FF00FF}"
fuzz="${FAVICON_FUZZ:-30%}"

if ! command -v magick >/dev/null 2>&1; then
  echo "Error: ImageMagick 'magick' not found."
  exit 1
fi

if [ ! -f "$input" ]; then
  echo "Error: input file not found: $input"
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

magick "$input" -fuzz "$fuzz" -transparent "$key_color" "$tmp_dir/transparent.png"
magick "$tmp_dir/transparent.png" -trim +repage -gravity center -background none -extent "%[fx:max(w,h)]x%[fx:max(w,h)]" "$tmp_dir/square.png"

cp "$tmp_dir/square.png" "${base}-transparent.png"

sizes=(16 32 48)
for size in "${sizes[@]}"; do
  magick "$tmp_dir/square.png" -resize "${size}x${size}" "${base}-${size}.png"
done

magick "${base}-16.png" "${base}-32.png" "${base}-48.png" "${base}.ico"

magick "$tmp_dir/square.png" -resize 180x180 "${base}-apple-touch-icon.png"
magick "$tmp_dir/square.png" -resize 192x192 "${base}-192.png"
magick "$tmp_dir/square.png" -resize 512x512 "${base}-512.png"
magick "$tmp_dir/square.png" -resize 512x512 "${base}.webp"

echo "Wrote: ${base}-transparent.png, ${base}.ico, ${base}-16.png, ${base}-32.png, ${base}-48.png"
echo "Wrote: ${base}-apple-touch-icon.png, ${base}-192.png, ${base}-512.png, ${base}.webp"
