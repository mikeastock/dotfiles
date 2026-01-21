---
name: nano-banana-pro
description: Generate or edit images via Gemini 3 Pro Image (Nano Banana Pro). Use when user asks to create, generate, or edit images.
homepage: https://ai.google.dev/
---

# Nano Banana Pro (Gemini 3 Pro Image)

Use the bundled script to generate or edit images.

## Requirements

- `uv` (install via `brew install uv`)
- `GEMINI_API_KEY` environment variable

## Generate

```bash
uv run {baseDir}/scripts/generate_image.py --prompt "your image description" --filename "output.png" --resolution 1K
```

## Edit

```bash
uv run {baseDir}/scripts/generate_image.py --prompt "edit instructions" --filename "output.png" --input-image "/path/in.png" --resolution 2K
```

## Notes

- Resolutions: `1K` (default), `2K`, `4K`.
- Use timestamps in filenames: `yyyy-mm-dd-hh-mm-ss-name.png`.
- Do not read the image back; report the saved path only.
