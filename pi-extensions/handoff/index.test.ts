import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getEffectiveHandoffOptions } from "./lib/effective-options.js";

describe("handoff model preservation", () => {
	it("preserves the current model when no explicit mode or model is provided", () => {
		assert.deepEqual(
			getEffectiveHandoffOptions(undefined, "anthropic/claude-sonnet-4-6"),
			{ model: "anthropic/claude-sonnet-4-6" },
		);
	});

	it("does not override an explicit mode with the current model", () => {
		assert.deepEqual(
			getEffectiveHandoffOptions({ mode: "rush" }, "anthropic/claude-sonnet-4-6"),
			{ mode: "rush" },
		);
	});

	it("does not override an explicit model", () => {
		assert.deepEqual(
			getEffectiveHandoffOptions({ model: "anthropic/claude-haiku-4-5" }, "anthropic/claude-sonnet-4-6"),
			{ model: "anthropic/claude-haiku-4-5" },
		);
	});
});
