---
name: x-search
description: Use this skill when the user asks to search X/Twitter posts, test X search credentials, initialize a local X OAuth app, refresh X OAuth tokens, or fetch recent public posts from X API v2. Uses ~/.env for app credentials and ~/.local/state/codex/x-search/tokens.json for mutable OAuth tokens.
---

# X Search

Search X/Twitter through the official X API v2 using a local OAuth 2.0 app.

## Credential Model

Read stable app credentials from `~/.env`:

```env
X_SEARCH_CLIENT_ID=...
X_SEARCH_CLIENT_SECRET=...
```

Do not store access tokens or refresh tokens in `~/.env`. The scripts store mutable OAuth state in:

```txt
~/.local/state/codex/x-search/tokens.json
```

The OAuth redirect URI is hardcoded as:

```txt
http://127.0.0.1:8787/callback
```

The X Developer app must include that exact callback URL and request these scopes:

```txt
tweet.read users.read offline.access
```

Add `bookmark.read` only if this same app will also fetch bookmarks.

## Commands

Initialize or replace the local OAuth token cache:

```bash
node ~/.agents/skills/x-search/scripts/x-oauth-init.mjs
```

The script prints an authorization URL and waits for the callback. Open the URL, approve the app, and let X redirect to the local callback.

Search recent posts:

```bash
node ~/.agents/skills/x-search/scripts/x-search.mjs --query 'openai codex lang:en -is:retweet' --max 25
```

Machine-readable output:

```bash
node ~/.agents/skills/x-search/scripts/x-search.mjs --query 'openai codex' --json
```

Full archive search, only when the X account/app has access:

```bash
node ~/.agents/skills/x-search/scripts/x-search.mjs --query 'openai codex' --all
```

## Workflow

1. If token setup is missing or invalid, run `x-oauth-init.mjs`.
2. For normal searches, run `x-search.mjs --query ...`.
3. If the search returns an X authorization or product-access error, report the concrete status and message. Do not hide it behind a generic failure.
4. Never print `X_SEARCH_CLIENT_SECRET`, `access_token`, or `refresh_token`.
5. Treat `/2/tweets/search/recent` as the default. It covers recent public posts, not the full archive.
6. Use `/2/tweets/search/all` only when explicitly requested or clearly needed, and explain that X may reject it unless the app has full-archive access.

## Output

Default output is compact Markdown with date, handle, URL, and post text. Use `--json` when another script or workflow will consume the result.
