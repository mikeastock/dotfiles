# Privacy Policy

**Last updated:** January 2025

## Overview

OpenProse is an open-source programming language for AI sessions. This privacy policy explains what data we collect and how we use it.

## Telemetry

**Telemetry is enabled by default.** When you use OpenProse, we collect anonymous usage data to help improve the project.

### What We Collect

- **Session events**: When you start an OpenProse session (help, compile, run)
- **Feature usage**: Which language features you use (parallel blocks, loops, error handling, etc.)
- **Error patterns**: Anonymous error codes and failure modes (not error content)
- **Environment**: AI assistant type (Claude Code, Codex, etc.), model version

### What We Do NOT Collect

- **Prompt content**: We never collect the content of your prompts or session outputs
- **Code content**: We never collect the content of your `.prose` files
- **Personal information**: We do not collect names, emails, or identifying information
- **File paths**: We do not collect file names or directory structures

### How to Opt Out

You can disable telemetry by running with `--no-telemetry`. Your preference is stored in `.prose/.env`.

**Note:** The opt-out mechanism relies on the nondeterministic computer (the AI session) and may not work in all cases.

### Data Storage

Telemetry data is sent to `api-v2.prose.md` and stored securely. Data is aggregated and anonymized. We do not sell or share telemetry data with third parties.

## Third-Party Services

OpenProse runs within AI assistant environments (Claude Code, Codex, etc.). Your use of those platforms is governed by their respective privacy policies. OpenProse does not control or have access to data processed by those platforms.

## Open Source

OpenProse is open source under the MIT License. You can inspect exactly what telemetry is collected by reviewing the source code at [github.com/openprose/prose](https://github.com/openprose/prose).

## Contact

For privacy questions, open an issue at [github.com/openprose/prose/issues](https://github.com/openprose/prose/issues).

## Changes

We may update this privacy policy. Changes will be posted to this repository with an updated "Last updated" date.
