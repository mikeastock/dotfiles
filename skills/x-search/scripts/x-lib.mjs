import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const REDIRECT_URI = "http://127.0.0.1:8787/callback";
export const DEFAULT_SCOPES = "tweet.read users.read offline.access";
export const STATE_DIR = path.join(os.homedir(), ".local", "state", "codex", "x-search");
export const TOKEN_PATH = path.join(STATE_DIR, "tokens.json");

export function loadEnv() {
  const envPath = path.join(os.homedir(), ".env");
  const values = { ...process.env };

  if (!fs.existsSync(envPath)) {
    return values;
  }

  const text = fs.readFileSync(envPath, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    values[match[1]] = unquoteEnvValue(match[2].trim());
  }

  return values;
}

export function loadClientConfig() {
  const env = loadEnv();
  const clientId = env.X_SEARCH_CLIENT_ID?.trim();
  const clientSecret = env.X_SEARCH_CLIENT_SECRET?.trim();

  if (!clientId) {
    throw new Error("Missing X_SEARCH_CLIENT_ID in ~/.env.");
  }

  if (!clientSecret) {
    throw new Error("Missing X_SEARCH_CLIENT_SECRET in ~/.env.");
  }

  return { clientId, clientSecret };
}

export function readTokenCache() {
  if (!fs.existsSync(TOKEN_PATH)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(TOKEN_PATH, "utf8"));
}

export function writeTokenCache(token) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  fs.chmodSync(STATE_DIR, 0o700);
  fs.writeFileSync(TOKEN_PATH, `${JSON.stringify(token, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(TOKEN_PATH, 0o600);
}

export function tokenFromResponse(body, previous = {}) {
  if (typeof body.access_token !== "string" || body.access_token.length === 0) {
    throw new Error("X token response did not include access_token.");
  }

  const expiresIn = typeof body.expires_in === "number" ? body.expires_in : 7200;
  return {
    access_token: body.access_token,
    refresh_token: body.refresh_token || previous.refresh_token,
    expires_at: new Date(Date.now() + expiresIn * 1000).toISOString(),
    scope: body.scope || previous.scope || DEFAULT_SCOPES,
    token_type: body.token_type || previous.token_type || "bearer"
  };
}

export async function refreshTokenIfNeeded(token, clientConfig, { force = false } = {}) {
  if (!token?.refresh_token) {
    throw new Error(`No refresh token found. Run: node ~/.agents/skills/x-search/scripts/x-oauth-init.mjs`);
  }

  const expiresAt = Date.parse(token.expires_at || "");
  const shouldRefresh = force || !Number.isFinite(expiresAt) || expiresAt - Date.now() < 60_000;

  if (!shouldRefresh) {
    return token;
  }

  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: token.refresh_token
  });

  const response = await fetch("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers: {
      authorization: basicAuth(clientConfig),
      "content-type": "application/x-www-form-urlencoded"
    },
    body: params
  });
  const body = await response.json().catch(async () => ({ text: await response.text() }));

  if (!response.ok) {
    throw new Error(`Could not refresh X access token (${response.status}): ${JSON.stringify(body)}`);
  }

  const nextToken = tokenFromResponse(body, token);
  writeTokenCache(nextToken);
  return nextToken;
}

export async function xFetch(url, options = {}) {
  const clientConfig = loadClientConfig();
  let token = readTokenCache();

  if (!token) {
    throw new Error(`No X token cache found. Run: node ~/.agents/skills/x-search/scripts/x-oauth-init.mjs`);
  }

  token = await refreshTokenIfNeeded(token, clientConfig);
  let response = await fetch(url, withBearer(token, options));

  if (response.status !== 401) {
    return response;
  }

  token = await refreshTokenIfNeeded(token, clientConfig, { force: true });
  response = await fetch(url, withBearer(token, options));
  return response;
}

export function basicAuth({ clientId, clientSecret }) {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

export function pkcePair() {
  const verifier = base64Url(randomBytes(32));
  const challenge = base64Url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function randomState() {
  return base64Url(randomBytes(24));
}

function withBearer(token, options) {
  return {
    ...options,
    headers: {
      ...options.headers,
      authorization: `Bearer ${token.access_token}`
    }
  };
}

function base64Url(buffer) {
  return buffer
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function unquoteEnvValue(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }

  return value;
}
