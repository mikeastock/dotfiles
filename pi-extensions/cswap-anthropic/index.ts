import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { mkdir, rename, rm, stat, utimes, writeFile } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import { basename, dirname, join } from "node:path";
import type { OAuthCredentials } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// Route Pi's `anthropic` OAuth through Claude Code's active credential, the one
// claude-swap (cswap) rotates between accounts. Pi never owns a refresh token.
// macOS reads the Keychain item Claude Code uses (`Claude Code-credentials`);
// Linux reads `~/.claude/.credentials.json`. A cswap switch applies to the next
// request. Refreshes take Claude Code's credential locks and write back to the
// store that was read, so a one-time refresh token is not spent and then lost.
// Request shaping stays with @gotgenes/pi-anthropic-auth.

const TOKEN_URL = "https://platform.claude.com/v1/oauth/token";
const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const REFRESH_TIMEOUT_MS = 15_000;
// Claude Code's credential locks (proper-lockfile): stale after 60s, touched every 5s.
const LOCK_STALE_MS = 60_000;
const LOCK_TOUCH_MS = 3_000;
const LOCK_TIMEOUT_MS = 20_000;
const SECURITY = "/usr/bin/security";
const SECURITY_TIMEOUT_MS = 5_000;
// security -i reads stdin with a 4096-byte buffer. Stay under it or the write truncates.
const SECURITY_STDIN_LIMIT = 4096 - 64;
const KEYCHAIN_SERVICE = "Claude Code-credentials";
const KEYCHAIN_NOT_FOUND = 44;
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

interface CredentialFile {
	claudeAiOauth: ClaudeOAuth;
	[key: string]: unknown;
}

interface ActiveLogin {
	data: CredentialFile;
	backend: "keychain" | "file";
	service?: string;
	// Keychain read failed and the file was used instead. Its refresh token may
	// already have been rotated in the Keychain; consuming it logs Claude Code out.
	degraded: boolean;
}

function configHome(): string {
	return process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude");
}

function credentialsPath(): string {
	return join(configHome(), ".credentials.json");
}

function lockDirs(): string[] {
	const home = configHome();
	return [join(home, ".oauth_refresh.lock"), join(dirname(home), `${basename(home)}.lock`)];
}

function keychainAccount(): string {
	if (process.env.USER) return process.env.USER;
	try {
		return userInfo().username;
	} catch {
		return "claude-code-user";
	}
}

function hashedService(configDir: string): string {
	const digest = createHash("sha256").update(configDir.normalize("NFC")).digest("hex").slice(0, 8);
	return `${KEYCHAIN_SERVICE}-${digest}`;
}

// Same service selection as cswap: a custom config dir hashes into its own item,
// and an explicit dir that still resolves to the default profile also tries the
// unsuffixed item Claude Code may already have written.
function keychainServices(): string[] {
	const secure = process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
	if (secure !== undefined) return [secure ? hashedService(secure) : KEYCHAIN_SERVICE];
	const configDir = process.env.CLAUDE_CONFIG_DIR;
	if (!configDir) return [KEYCHAIN_SERVICE];
	const services = [hashedService(configDir)];
	try {
		if (realpathSync(configDir) === realpathSync(join(homedir(), ".claude"))) services.push(KEYCHAIN_SERVICE);
	} catch {
		// An unresolvable path is not the default profile.
	}
	return services;
}

function parseCredential(raw: string, where: string): CredentialFile {
	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (error) {
		throw new Error(`${where} is not Claude Code credential JSON`, { cause: error });
	}
	const oauth = (data as CredentialFile | null)?.claudeAiOauth;
	if (!oauth?.accessToken || !oauth.refreshToken || typeof oauth.expiresAt !== "number") {
		throw new Error(`${where} holds no Claude Code OAuth login`);
	}
	return data as CredentialFile;
}

function readCredentialsFile(): CredentialFile {
	const path = credentialsPath();
	let raw: string;
	try {
		raw = readFileSync(path, "utf8");
	} catch (error) {
		throw new Error(`Cannot read Claude Code credentials at ${path}; log in with \`claude\` or \`cswap switch\``, {
			cause: error,
		});
	}
	return parseCredential(raw, path);
}

function security(args: string[], input?: string): { status: number; stdout: string; stderr: string } {
	try {
		const stdout = execFileSync(SECURITY, args, {
			encoding: "utf8",
			input,
			timeout: SECURITY_TIMEOUT_MS,
		});
		return { status: 0, stdout, stderr: "" };
	} catch (error) {
		const failed = error as NodeJS.ErrnoException & { status?: number; stdout?: string | Buffer; stderr?: string | Buffer };
		if (failed.code === "ENOENT") throw new Error(`${SECURITY} is not available`);
		if (failed.code === "ETIMEDOUT") throw new Error(`${SECURITY} timed out`);
		return {
			status: failed.status ?? 1,
			stdout: failed.stdout?.toString() ?? "",
			stderr: failed.stderr?.toString() ?? "",
		};
	}
}

function quoteSecurity(value: string): string {
	return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function readKeychainOnce(service: string, account: string): string | null {
	const result = security(["find-generic-password", "-a", account, "-w", "-s", service]);
	if (result.status === 0) return result.stdout.endsWith("\n") ? result.stdout.slice(0, -1) : result.stdout;
	if (result.status === KEYCHAIN_NOT_FOUND) return null;
	throw new Error(`Keychain read failed (rc=${result.status}): ${result.stderr.trim()}`);
}

function sleepSync(ms: number): void {
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function readKeychain(service: string, account: string): string | null {
	let last: unknown;
	for (let attempt = 0; attempt < 2; attempt++) {
		try {
			return readKeychainOnce(service, account);
		} catch (error) {
			last = error;
			if (attempt === 0) sleepSync(300);
		}
	}
	throw last;
}

function writeKeychain(service: string, account: string, secret: string): void {
	const hex = Buffer.from(secret, "utf8").toString("hex");
	const command = `add-generic-password -U -a ${quoteSecurity(account)} -s ${quoteSecurity(service)} -X ${hex}\n`;
	const result =
		Buffer.byteLength(command) <= SECURITY_STDIN_LIMIT
			? security(["-i"], command)
			: security(["add-generic-password", "-U", "-a", account, "-s", service, "-X", hex]);
	if (result.status !== 0) {
		throw new Error(`Keychain write failed (rc=${result.status}): ${result.stderr.trim()}`);
	}
}

function readActive(): ActiveLogin {
	if (process.platform === "darwin") {
		const account = keychainAccount();
		let keychainFailed = false;
		for (const service of keychainServices()) {
			try {
				const raw = readKeychain(service, account);
				if (raw) return { data: parseCredential(raw, `Keychain item "${service}"`), backend: "keychain", service, degraded: false };
			} catch {
				keychainFailed = true;
				break;
			}
		}
		if (existsSync(credentialsPath())) return { data: readCredentialsFile(), backend: "file", degraded: keychainFailed };
		if (keychainFailed) {
			throw new Error(
				"Claude Code's macOS Keychain credential is unreadable and ~/.claude/.credentials.json is absent. Unlock the login keychain, then retry.",
			);
		}
		throw new Error(
			`No Claude Code OAuth login in the macOS Keychain (${keychainServices().join(", ")}, account ${account}). Log in with \`claude\` or \`cswap switch\`.`,
		);
	}
	return { data: readCredentialsFile(), backend: "file", degraded: false };
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
	const dirs = lockDirs();
	const [primary, legacy] = dirs;
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
		for (const dir of dirs) void utimes(dir, now, now).catch(() => {});
	}, LOCK_TOUCH_MS);
	try {
		return await fn();
	} finally {
		clearInterval(touch);
		for (const dir of [legacy, primary]) await rm(dir, { recursive: true, force: true });
	}
}

async function writeCredentialsFile(json: string): Promise<void> {
	const path = credentialsPath();
	await mkdir(dirname(path), { recursive: true });
	const tmp = `${path}.${process.pid}.tmp`;
	await writeFile(tmp, json, { mode: 0o600 });
	await rename(tmp, path);
}

async function persist(login: ActiveLogin): Promise<void> {
	const json = JSON.stringify(login.data);
	if (login.backend === "keychain") {
		if (!login.service) throw new Error("Keychain login has no service name");
		writeKeychain(login.service, keychainAccount(), json);
		// Claude Code hot-reloads a credentials file that is already present. Do not create one.
		if (existsSync(credentialsPath())) {
			try {
				await writeCredentialsFile(json);
			} catch {
				// The Keychain write already succeeded and is what Claude Code reads on macOS.
			}
		}
		return;
	}
	await writeCredentialsFile(json);
}

async function refreshClaudeCredential(): Promise<ClaudeOAuth> {
	return withClaudeCredentialLocks(async () => {
		// Re-read under the lock: cswap, Claude Code, or another Pi may have refreshed or switched.
		const login = readActive();
		const oauth = login.data.claudeAiOauth;
		if (!needsRefresh(oauth)) return oauth;
		if (login.degraded) {
			throw new Error(
				"Claude Code's macOS Keychain credential is unreadable. Refusing to refresh from the credentials file, because that refresh token may already have been rotated.",
			);
		}

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
			} catch {
				// Body is not JSON; the status is the useful part.
			}
			throw new Error(`Claude Code token refresh failed: HTTP ${response.status}${code ? ` ${code}` : ""}`);
		}
		const token = JSON.parse(body) as { access_token: string; expires_in: number; refresh_token?: string; scope?: string };
		oauth.accessToken = token.access_token;
		oauth.expiresAt = Date.now() + token.expires_in * 1000;
		if (token.refresh_token) oauth.refreshToken = token.refresh_token;
		if (token.scope) oauth.scopes = token.scope.split(" ");
		await persist(login);
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

function currentOAuth(): ClaudeOAuth {
	const login = readActive();
	if (needsRefresh(login.data.claudeAiOauth) && !login.degraded) void refreshOnce().catch(() => {});
	if (login.degraded && Date.now() >= login.data.claudeAiOauth.expiresAt) {
		throw new Error(
			"Claude Code's macOS Keychain credential is unreadable and the credentials file login is expired. Unlock the login keychain, then retry.",
		);
	}
	return login.data.claudeAiOauth;
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
					return toPiCredential(currentOAuth());
				},
				async refreshToken() {
					const oauth = readActive().data.claudeAiOauth;
					return toPiCredential(needsRefresh(oauth) ? await refreshOnce() : oauth);
				},
				getApiKey() {
					// Pi only refreshes when its stored expiry nears, but a cswap switch can
					// activate a token that expires sooner. Read the active store every time.
					return currentOAuth().accessToken;
				},
			},
		});
	});
}
