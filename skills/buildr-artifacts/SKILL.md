---
name: buildr-artifacts
description: Publish browser-viewable artifacts. Use static mode for S3-hosted HTML artifacts and Vite app mode for stateful apps that should run on Codexbox with a bld.run URL.
compatibility: Static mode requires aws CLI and Codexbox instance role permissions for the artifact S3 bucket. Vite app mode requires npm, tailscale, and an existing per-user bld.run DNS record.
metadata:
  homepage: https://artifacts.buildrtools.com
allowed-tools: Bash({baseDir}/scripts/share_artifact.py:*) Bash({baseDir}/scripts/serve_vite_app.py:*) Read
---

# Buildr Artifacts

Publish browser-viewable artifacts in one of two modes:

- **Static mode:** upload immutable HTML and assets to Buildr's private S3-backed artifact hosting.
- **Vite app mode:** run a stateful Vite app on the Codexbox Tailscale IP and return the user's `bld.run` URL.

## Choose a Mode

Use static mode when the artifact is a report, dashboard, prototype, or static directory that can be uploaded and viewed as files.

Use Vite app mode when the artifact needs runtime state, API calls from the box, local files, WebSockets, hot reloading, or a long-running dev server.

## Static Mode

Share a single HTML file:

```bash
{baseDir}/scripts/share_artifact.py --path /path/to/report.html
```

Share a static artifact directory:

```bash
{baseDir}/scripts/share_artifact.py --path /path/to/artifact-dir
```

The directory must contain `index.html` at its root. The script uploads supported static assets alongside it and prints the share URL.

Share generated HTML without creating a directory:

```bash
{baseDir}/scripts/share_artifact.py --html-file /path/to/generated.html
```

## Output

The script prints only the shareable URL on success:

```text
https://artifacts.buildrtools.com/bright-river-a1b2/
```

Report that URL to the user.

## Vite App Mode

Run a Vite project directory on the Codexbox Tailscale IP:

```bash
{baseDir}/scripts/serve_vite_app.py --path /path/to/vite-app
```

The directory must contain `package.json` with a `scripts.dev` command. If `node_modules` is missing, the script runs `npm install`, starts `npm run dev -- --host <tailscale-ip> --port <port> --strictPort` in the background, and prints the app URL:

```text
http://mike.bld.run:43123/
```

Use an explicit slug or port when you need stable process identity or a known URL:

```bash
{baseDir}/scripts/serve_vite_app.py --path /path/to/vite-app --slug pipeline-demo --port 43123
```

Use `--url-host` if hostname-based bld.run derivation is not available:

```bash
{baseDir}/scripts/serve_vite_app.py --path /path/to/vite-app --url-host mike.bld.run
```

Vite app logs and PID files live under:

```text
~/.cache/buildr-artifacts/vite-apps/<slug>/
```

Rerunning the same slug stops the previous process and starts the replacement.

## Output

Both scripts print only the shareable URL on success. Report that URL to the user.

## Environment

Codexbox normally sources these from `/home/codex/.config/codexbox/env`, populated from Secrets Manager:

- `ARTIFACTS_AWS_REGION` — AWS region, defaults to `us-east-1`
- `ARTIFACTS_S3_BUCKET` — Bucket name, defaults to `buildr-bizops-artifacts`
- `ARTIFACTS_BASE_URL` — URL base, defaults to `https://artifacts.buildrtools.com`
- `BLD_RUN_HOST` — optional Vite app URL host override, for example `mike.bld.run`

Static uploads use the Codexbox instance role. Do not configure artifact access keys.

## Safety Rules

The script preserves the pi extension's constraints:

- Single-file uploads must be `.html` and are published as `index.html`.
- Directory uploads must have a root `index.html`.
- Symlinks are rejected.
- Only regular files and directories are allowed.
- Supported extensions: `.html`, `.css`, `.js`, `.json`, `.txt`, `.xml`, `.svg`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.ico`, `.pdf`, `.ttf`, `.woff`, `.woff2`.
- Maximum 2,000 files, maximum depth 20, maximum file size 1 GiB.

## Tips

- Prefer writing artifacts under `tmp/` or another scratch directory, then upload the final directory.
- Do not upload secrets or raw customer data unless the user explicitly requests it and confirms the artifact is safe to share internally.
- If static upload fails with missing credentials or access denied, check that the Codexbox instance role has artifact bucket permissions.
- If Vite starts but the URL does not load, check the app logs in `~/.cache/buildr-artifacts/vite-apps/<slug>/` and confirm the printed port is reachable over Tailscale.
