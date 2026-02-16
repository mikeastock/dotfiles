---
name: favicon-generator
description: Generate flat favicons from image prompts, then key out a magenta background and build PNG/ICO/WebP outputs with ImageMagick. Use when you need a reliable favicon workflow.
compatibility: Requires ImageMagick (magick), uv, and GEMINI_API_KEY for image generation.
---

# Favicon Generator (magenta key workflow)

Create clean, flat favicons with a transparent background. Generate a base PNG on a solid magenta background, remove the magenta with ImageMagick, then export favicon.ico, PNG sizes, Apple touch icon, and WebP.

## Prereqs

- `uv`
- `magick` (ImageMagick)
- `GEMINI_API_KEY` set

## Prompt template

Use a solid magenta background so it can be keyed out later. Keep the icon flat and simple so it reads at 16×16.

```
Favicon icon, 1:1 square, solid magenta #FF00FF background. Simple flat vector icon of: <subject>. Bold geometric shapes, solid fills, no gradients, no shadows. Centered, fills 75–85% of frame. Do not use magenta in the icon.
```

## Generate the base image

Use the Nano Banana Pro skill to generate the PNG. Run from your project directory so outputs land where you need them.

Example (update the path for your agent):

- Codex: `~/.codex/skills/nano-banana-pro/scripts/generate_image.py`
- Claude: `~/.claude/skills/nano-banana-pro/scripts/generate_image.py`
- Pi: `~/.pi/agent/skills/nano-banana-pro/scripts/generate_image.py`

```
uv run <nanoBananaDir>/scripts/generate_image.py \
  --prompt "<your prompt>" \
  --filename "yyyy-mm-dd-hh-mm-ss-favicon.png" \
  --resolution 1K
```

Iterate at 1K, then re-run at 2K/4K only when the prompt is locked.

## Convert to favicon outputs

Run the script from this skill:

```
bash {baseDir}/scripts/faviconize.sh <input-png> <output-base>
```

Outputs:

- `<output-base>-transparent.png`
- `<output-base>-16.png`, `-32.png`, `-48.png`
- `<output-base>.ico`
- `<output-base>-apple-touch-icon.png` (180×180)
- `<output-base>-192.png`, `<output-base>-512.png`
- `<output-base>.webp` (512×512)

### Optional tuning

Set a different key color or fuzz if needed:

```
FAVICON_KEY_COLOR="#FF00FF" FAVICON_FUZZ="30%" bash {baseDir}/scripts/faviconize.sh input.png favicon
```

## Update HTML + manifest

Add or update links in your HTML layout:

```
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
<link rel="apple-touch-icon" href="/favicon-apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
```

Update `site.webmanifest`:

```
{
  "icons": [
    {"src": "/favicon-192.png", "sizes": "192x192", "type": "image/png"},
    {"src": "/favicon-512.png", "sizes": "512x512", "type": "image/png"},
    {"src": "/favicon.webp", "sizes": "512x512", "type": "image/webp"}
  ]
}
```

## Common pitfalls

- Magenta bleeding into edges means the generator used background gradients. Regenerate with a flat `#FF00FF` background.
- Avoid magenta accents in the icon or they will be keyed out.
- If the icon is too small in the tab, increase its size in the prompt and rerun the conversion.
