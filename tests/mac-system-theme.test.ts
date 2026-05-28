import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { piThemeFromHerdrThemeName, themeFromHerdrConfigText } from "../pi-extensions/mac-system-theme/index.ts";

describe("mac-system-theme Herdr config mapping", () => {
	it("maps Herdr Catppuccin dark themes to Pi Mocha", () => {
		assert.equal(piThemeFromHerdrThemeName("catppuccin"), "catppuccin-mocha");
		assert.equal(piThemeFromHerdrThemeName("catppuccin-mocha"), "catppuccin-mocha");
	});

	it("maps Herdr Catppuccin Latte to Pi Latte", () => {
		assert.equal(piThemeFromHerdrThemeName("catppuccin-latte"), "catppuccin-latte");
	});

	it("reads the Herdr theme name from the theme section", () => {
		const config = `
[ui]
accent = "cyan"

[theme]
name = "catppuccin-latte"

[terminal]
new_cwd = "follow"
`;

		assert.equal(themeFromHerdrConfigText(config), "catppuccin-latte");
	});

	it("ignores theme-like keys outside the theme section", () => {
		const config = `
[ui]
name = "catppuccin-latte"

[theme]
name = "catppuccin"
`;

		assert.equal(themeFromHerdrConfigText(config), "catppuccin-mocha");
	});
});
