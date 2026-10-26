import { readFileSync } from "node:fs";
import { mkdir, rename, rm, stat, utimes, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import type { OAuthCredentials } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// Route Pi's `anthropic` OAuth through Claude Code's active credential, the one
// claude-swap (cswap) rotates between accounts. Pi never owns a refresh token:
// every request reads ~/.claude/.credentials.json, so a cswap switch applies to
// the next request. Refreshes follow Claude Code's lock protocol, which cswap
// and Claude Code both honor, so the rotated token is adopted rather than raced.
// Request shaping stays with @gotgenes/pi-anthropic-auth.

const TOKEN_URL = "https://platform.claude.com/v1/oauth/token";
const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const REFRESH_TIMEOUT_MS = 15_000;
// Claude Code's credential locks (proper-lockfile): stale after 60s, touched every 5s.
const LOCK_STALE_MS = 60_000;
const LOCK_TOUCH_MS = 3_000;
const LOCK_TIMEOUT_MS = 20_000;
// Stored in Pi's auth.json in place of real tokens, so Pi's built-in Anthropic
// refresh can never consume Claude Code's refresh token if this extension is removed.
const MANAGED = "managed-by-claude-code";

interface ClaudeOAuth {
	accessToken: string;
	refreshToken: string;
	expiresAt: number;
	scopes?: string[];
	[key: string]: unknown;
}

const configHome = process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude");
const credentialsPath = join(configHome, ".credentials.json");
const lockDirs = [join(configHome, ".oauth_refresh.lock"), join(dirname(configHome), `${basename(configHome)}.lock`)];

function readCredentialsFile(): Record<string, unknown> & { claudeAiOauth: ClaudeOAuth } {
	let data: Record<string, unknown>;
	try {
		data = JSON.parse(readFileSync(credentialsPath, "utf8"));
	} catch (error) {
		throw new Error(`Cannot read Claude Code credentials at ${credentialsPath}; log in with \`claude\` or \`cswap switch\``, {
			cause: error,
		});
	}
	const oauth = data.claudeAiOauth as ClaudeOAuth | undefined;
	if (!oauth?.accessToken || !oauth.refreshToken || typeof oauth.expiresAt !== "number") {
		throw new Error(`${credentialsPath} holds no Claude Code OAuth login`);
	}
	return data as Record<string, unknown> & { claudeAiOauth: ClaudeOAuth };
}

function needsRefresh(oauth: ClaudeOAuth): boolean {
	return Date.now() + REFRESH_MARGIN_MS >= oauth.expiresAt;
}

function toPiCredential(oauth: ClaudeOAuth): OAuthCredentials {
	return { access: MANAGED, refresh: MANAGED, expires: oauth.expiresAt };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function tryLock(dir: string): Promise<boolean> {
	try {
		await mkdir(dir);
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
	}
	const age = await stat(dir).then(
		(s) => Date.now() - s.mtimeMs,
		() => Number.POSITIVE_INFINITY,
	);
	if (age <= LOCK_STALE_MS) return false;
	await rm(dir, { recursive: true, force: true });
	return tryLock(dir);
}

// Take Claude Code's primary then legacy credential lock, releasing the primary
// when the legacy one is contended, as Claude Code itself does.
async function withClaudeCredentialLocks<T>(fn: () => Promise<T>): Promise<T> {
	const [primary, legacy] = lockDirs;
	const deadline = Date.now() + LOCK_TIMEOUT_MS;
	for (;;) {
		if (await tryLock(primary)) {
			if (await tryLock(legacy)) break;
			await rm(primary, { recursive: true, force: true });
		}
		if (Date.now() > deadline) throw new Error("Timed out waiting for Claude Code's credential lock");
		await sleep(1000 + Math.random() * 1000);
	}
	const touch = setInterval(() => {
		const now = new Date();
		for (const dir of lockDirs) void utimes(dir, now, now).catch(() => {});
	}, LOCK_TOUCH_MS);
	try {
		return await fn();
	} finally {
		clearInterval(touch);
		for (const dir of [legacy, primary]) await rm(dir, { recursive: true, force: true });
	}
}

async function refreshClaudeCredential(): Promise<ClaudeOAuth> {
	return withClaudeCredentialLocks(async () => {
		// Re-read under the lock: cswap, Claude Code, or another Pi may have refreshed or switched.
		const data = readCredentialsFile();
		const oauth = data.claudeAiOauth;
		if (!needsRefresh(oauth)) return oauth;

		// Not cancellable: once the grant is posted the old refresh token is spent,
		// so the response must be persisted.
		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ grant_type: "refresh_token", refresh_token: oauth.refreshToken, client_id: CLIENT_ID }),
			signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS),
		});
		const body = await response.text();
		if (!response.ok) {
			let code = "";
			try {
				code = JSON.parse(body).error ?? "";
			} catch {}
			throw new Error(`Claude Code token refresh failed: HTTP ${response.status}${code ? ` ${code}` : ""}`);
		}
		const token = JSON.parse(body) as { access_token: string; expires_in: number; refresh_token?: string; scope?: string };
		oauth.accessToken = token.access_token;
		oauth.expiresAt = Date.now() + token.expires_in * 1000;
		if (token.refresh_token) oauth.refreshToken = token.refresh_token;
		if (token.scope) oauth.scopes = token.scope.split(" ");

		const tmp = `${credentialsPath}.${process.pid}.tmp`;
		await writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
		await rename(tmp, credentialsPath);
		return oauth;
	});
}

// One refresh per process at a time; concurrent requests share it.
let inflight: Promise<ClaudeOAuth> | undefined;
function refreshOnce(): Promise<ClaudeOAuth> {
	inflight ??= refreshClaudeCredential().finally(() => {
		inflight = undefined;
	});
	return inflight;
}

export default function cswapAnthropicExtension(pi: ExtensionAPI): void {
	// Registered at session_start because @gotgenes/pi-anthropic-auth unregisters
	// `anthropic` while loading; registerProvider merges this onto its transport.
	pi.on("session_start", () => {
		pi.registerProvider("anthropic", {
			oauth: {
				name: "Anthropic (Claude Code via cswap)",
				isSubscription: true,
				async login() {
					return toPiCredential(readCredentialsFile().claudeAiOauth);
				},
				async refreshToken() {
					const oauth = readCredentialsFile().claudeAiOauth;
					return toPiCredential(needsRefresh(oauth) ? await refreshOnce() : oauth);
				},
				getApiKey() {
					// Pi only refreshes when its stored expiry nears, but a cswap switch can
					// activate a token that expires sooner. Refresh it in the background.
					const oauth = readCredentialsFile().claudeAiOauth;
					if (needsRefresh(oauth)) void refreshOnce().catch(() => {});
					return oauth.accessToken;
				},
			},
		});
	});
}
