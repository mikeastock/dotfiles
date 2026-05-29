/**
 * Sync Pi's theme with macOS system appearance.
 *
 * Ghostty already switches between Catppuccin Mocha and Latte. This keeps Pi's
 * own TUI theme aligned with the same dark/light pair. Remote sessions can use
 * an override file written by a macOS-side helper over SSH, which works through
 * mosh and existing tmux sessions.
 */

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

const execFileAsync = promisify(execFile);
const DARK_THEME = "catppuccin-mocha";
const LIGHT_THEME = "catppuccin-latte";
const CHECK_INTERVAL_MS = 2000;
const OVERRIDE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

function overridePath(): string {
	return process.env.PI_MAC_SYSTEM_THEME_OVERRIDE_PATH ?? path.join(homedir(), ".pi", "agent", "theme-sync-override.json");
}

function overrideMaxAgeMs(): number {
	const configured = process.env.PI_MAC_SYSTEM_THEME_OVERRIDE_MAX_AGE_MS;
	if (!configured) {
		return OVERRIDE_MAX_AGE_MS;
	}

	const parsed = Number(configured);
	return Number.isFinite(parsed) && parsed >= 0 ? parsed : OVERRIDE_MAX_AGE_MS;
}

function themeFromAppearance(appearance: unknown): string | null {
	if (typeof appearance !== "string") {
		return null;
	}

	switch (appearance.trim().toLowerCase()) {
		case "dark":
			return DARK_THEME;
		case "light":
			return LIGHT_THEME;
		default:
			return null;
	}
}

export function themeFromOverrideText(text: string, nowMs = Date.now(), maxAgeMs = overrideMaxAgeMs()): string | null {
	let override: unknown;
	try {
		override = JSON.parse(text);
	} catch {
		return null;
	}

	if (!override || typeof override !== "object") {
		return null;
	}

	const record = override as { appearance?: unknown; updatedAt?: unknown };
	const theme = themeFromAppearance(record.appearance);
	if (!theme || typeof record.updatedAt !== "string") {
		return null;
	}

	const updatedAtMs = Date.parse(record.updatedAt);
	if (!Number.isFinite(updatedAtMs) || nowMs - updatedAtMs > maxAgeMs) {
		return null;
	}

	return theme;
}

async function overrideSystemTheme(): Promise<string | null> {
	try {
		return themeFromOverrideText(await readFile(overridePath(), "utf8"));
	} catch {
		return null;
	}
}

async function macOSDarkModeEnabled(): Promise<boolean | null> {
	try {
		const { stdout } = await execFileAsync("osascript", [
			"-e",
			'tell application "System Events" to tell appearance preferences to return dark mode',
		]);
		return stdout.trim() === "true";
	} catch {
		return null;
	}
}

async function macOSSystemTheme(): Promise<string | null> {
	const darkModeEnabled = await macOSDarkModeEnabled();
	if (darkModeEnabled === null) {
		return null;
	}

	return darkModeEnabled ? DARK_THEME : LIGHT_THEME;
}

export async function currentSystemTheme(): Promise<string | null> {
	const overrideTheme = await overrideSystemTheme();
	if (overrideTheme) {
		return overrideTheme;
	}

	if (process.platform !== "darwin") {
		return null;
	}

	return macOSSystemTheme();
}

export default function (pi: ExtensionAPI) {
	let intervalId: ReturnType<typeof setInterval> | null = null;
	let appliedTheme: string | null = null;

	async function applySystemTheme(ctx: ExtensionContext) {
		const theme = await currentSystemTheme();
		if (!theme || theme === appliedTheme) {
			return;
		}

		ctx.ui.setTheme(theme);
		appliedTheme = theme;
	}

	pi.on("session_start", async (_event, ctx) => {
		await applySystemTheme(ctx);

		intervalId = setInterval(() => {
			void applySystemTheme(ctx);
		}, CHECK_INTERVAL_MS);
	});

	pi.on("session_shutdown", () => {
		if (intervalId) {
			clearInterval(intervalId);
			intervalId = null;
		}
	});
}
