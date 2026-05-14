---
name: serve-html-artifact
description: Serve a local HTML artifact over an HTTP server bound to 0.0.0.0 and return a shareable Tailscale MagicDNS URL. Use when the user asks to serve, preview, host, or open an HTML file/artifact from the current machine, especially when they ask for a Tailscale URL.
---

# Serve HTML Artifact

## Quick start

Use the bundled script with the HTML file path:

```bash
/home/mikeastock/.agents/skills/serve-html-artifact/scripts/serve-html-artifact.sh path/to/file.html
```

The script:

1. Verifies the HTML file exists.
2. Starts `python3 -m http.server` bound to `0.0.0.0`.
3. Chooses a free port unless one is supplied.
4. Writes PID/log metadata under `/tmp/serve-html-artifact-*`.
5. Verifies the URL returns HTTP 200.
6. Prints the local URL and Tailscale MagicDNS URL.

## Common usage

Serve with an auto-selected port:

```bash
/home/mikeastock/.agents/skills/serve-html-artifact/scripts/serve-html-artifact.sh artifacts/report.html
```

Serve with a fixed port:

```bash
/home/mikeastock/.agents/skills/serve-html-artifact/scripts/serve-html-artifact.sh artifacts/report.html 8123
```

## Agent workflow

When asked to serve an HTML artifact:

1. Run the script from the repository or artifact directory.
2. Report the `Tailscale URL` line to the user.
3. Include the PID and log path so the user can stop or debug the server.

To stop a server:

```bash
kill $(cat /tmp/serve-html-artifact-<port>.pid)
```

## Notes

- The script serves the file's parent directory, not the whole repository unless the file lives at repository root.
- It requires `python3` and either `curl` or Python's standard library for verification.
- Tailscale MagicDNS is detected with `tailscale status --self`; the script falls back to `hostname` if Tailscale is unavailable.
