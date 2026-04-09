import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { visibleWidth } from "@mariozechner/pi-tui";
import { _test } from "./index.js";

describe("openai-fast", () => {
	it("builds footer right-side candidates with thinking level", () => {
		assert.deepEqual(
			_test.buildFooterRightSideCandidates(
				{ provider: "openai-codex", id: "gpt-5.4", reasoning: true } as any,
				"medium",
			),
			["(openai-codex) gpt-5.4 • medium", "gpt-5.4 • medium"],
		);
	});

	it("injects FAST inline after the model thinking section", () => {
		const originalLine = "cwd branch                      (openai-codex) gpt-5.4 • medium";
		const updatedLine = _test.injectFastIntoFooterLine(
			originalLine,
			{ provider: "openai-codex", id: "gpt-5.4", reasoning: true } as any,
			"medium",
			"⚡",
		);

		assert.equal(updatedLine, "cwd branch                 (openai-codex) gpt-5.4 • medium • ⚡");
		assert.equal(visibleWidth(updatedLine), visibleWidth(originalLine));
	});

	it("parses supported model keys", () => {
		assert.deepEqual(_test.parseSupportedModelKey("openai/gpt-5.4"), {
			provider: "openai",
			id: "gpt-5.4",
		});
		assert.equal(_test.parseSupportedModelKey("bad"), undefined);
	});

	it("adds priority service tier to provider payloads", () => {
		assert.deepEqual(_test.applyFastServiceTier({ model: "gpt-5.4" }), {
			model: "gpt-5.4",
			service_tier: "priority",
		});
	});

	it("describes unsupported active state", () => {
		assert.equal(
			_test.describeCurrentState(
				{ model: { provider: "openai", id: "gpt-4.1" } as any },
				true,
				[{ provider: "openai", id: "gpt-5.4" }],
			),
			"Fast mode is on, but openai/gpt-4.1 does not support it. Supported models: openai/gpt-5.4.",
		);
	});

	it("does not render the fast indicator for unsupported models", () => {
		assert.equal(
			_test.getFastIndicator(
				{
					model: { provider: "openai", id: "gpt-4.1" } as any,
					ui: {
						theme: { fg: (_color: string, text: string) => `[${_color}]${text}` },
					},
				} as any,
				true,
				[{ provider: "openai", id: "gpt-5.4" }],
			),
			undefined,
		);
	});
});
