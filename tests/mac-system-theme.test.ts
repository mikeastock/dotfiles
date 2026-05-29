import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { currentSystemTheme, themeFromOverrideText } from "../pi-extensions/mac-system-theme/index.ts";

const NOW = Date.parse("2026-05-29T12:00:00Z");

describe("mac-system-theme", () => {
	it("maps a dark override to the Pi dark theme", () => {
		const text = JSON.stringify({ appearance: "dark", updatedAt: new Date(NOW).toISOString() });

		assert.equal(themeFromOverrideText(text, NOW), "catppuccin-mocha");
	});

	it("maps a light override to the Pi light theme", () => {
		const text = JSON.stringify({ appearance: "light", updatedAt: new Date(NOW).toISOString() });

		assert.equal(themeFromOverrideText(text, NOW), "catppuccin-latte");
	});

	it("ignores stale overrides", () => {
		const text = JSON.stringify({ appearance: "dark", updatedAt: new Date(NOW - 2000).toISOString() });

		assert.equal(themeFromOverrideText(text, NOW, 1000), null);
	});

	it("uses the override file outside macOS", async () => {
		const dir = await mkdtemp(path.join(tmpdir(), "pi-theme-"));
		const overridePath = path.join(dir, "theme-sync-override.json");
		process.env.PI_MAC_SYSTEM_THEME_OVERRIDE_PATH = overridePath;
		process.env.PI_MAC_SYSTEM_THEME_OVERRIDE_MAX_AGE_MS = "86400000";

		try {
			await writeFile(
				overridePath,
				JSON.stringify({ appearance: "light", updatedAt: new Date().toISOString(), source: "test" }),
				"utf8",
			);

			assert.equal(await currentSystemTheme(), "catppuccin-latte");
		} finally {
			delete process.env.PI_MAC_SYSTEM_THEME_OVERRIDE_PATH;
			delete process.env.PI_MAC_SYSTEM_THEME_OVERRIDE_MAX_AGE_MS;
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("does nothing outside macOS without an override", async () => {
		assert.equal(await currentSystemTheme(), null);
	});
});
