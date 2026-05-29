import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { currentSystemTheme } from "../pi-extensions/mac-system-theme/index.ts";

describe("mac-system-theme", () => {
	it("does nothing outside macOS", async () => {
		assert.equal(await currentSystemTheme(), null);
	});
});
