import assert from "node:assert/strict";
import { describe, it } from "node:test";
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
		assert.equal(
			_test.injectFastIntoFooterLine(
				"cwd branch                      (openai-codex) gpt-5.4 • medium",
				{ provider: "openai-codex", id: "gpt-5.4", reasoning: true } as any,
				"medium",
				"⚡",
			),
			"cwd branch                    (openai-codex) gpt-5.4 • medium • ⚡",
		);
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
});
