/**
 * Sync Pi's theme with macOS system appearance.
 *
 * Ghostty already switches between Catppuccin Mocha and Latte. This keeps Pi's
 * own TUI theme aligned with the same dark/light pair.
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

export function piThemeFromHerdrThemeName(themeName: string): string | null {
	const normalized = themeName.trim().toLowerCase();

	if (normalized === "catppuccin" || normalized === "catppuccin-mocha") {
		return DARK_THEME;
	}

	if (normalized === "catppuccin-latte") {
		return LIGHT_THEME;
	}

	return null;
}

export function themeFromHerdrConfigText(configText: string): string | null {
	let inThemeSection = false;

	for (const line of configText.split(/\r?\n/)) {
		const trimmed = line.trim();

		if (!trimmed || trimmed.startsWith("#")) {
			continue;
		}

		if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
			inThemeSection = trimmed === "[theme]";
			continue;
		}

		if (!inThemeSection) {
			continue;
		}

		const match = trimmed.match(/^name\s*=\s*["']?([^"'#]+)["']?/);
		if (!match) {
			continue;
		}

		return piThemeFromHerdrThemeName(match[1]);
	}

	return null;
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

async function herdrSystemTheme(): Promise<string | null> {
	const configPath = process.env.HERDR_CONFIG_PATH ?? path.join(homedir(), ".config", "herdr", "config.toml");

	try {
		return themeFromHerdrConfigText(await readFile(configPath, "utf8"));
	} catch {
		return null;
	}
}

async function currentSystemTheme(): Promise<string | null> {
	if (process.platform === "darwin") {
		return macOSSystemTheme();
	}

	if (process.env.HERDR_ENV || process.env.HERDR_SOCKET_PATH) {
		return herdrSystemTheme();
	}

	return null;
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
