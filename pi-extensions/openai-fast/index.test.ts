import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { visibleWidth } from "@earendil-works/pi-tui";
import openaiFast, { _test } from "./index.js";

describe("openai-fast helpers", () => {
	it("builds footer right-side candidates with thinking level", () => {
		assert.deepEqual(
			_test.buildFooterRightSideCandidates(
				{ provider: "openai-codex", id: "gpt-5.4", reasoning: true } as any,
				"medium",
			),
			["(openai-codex) gpt-5.4 • medium", "gpt-5.4 • medium"],
		);
	});

	it("injects the fast indicator without changing footer width", () => {
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

describe("openai-fast extension registration", () => {
	it("registers the fast flag, command, and lifecycle hooks", () => {
		const flags: string[] = [];
		const commands: string[] = [];
		const events: string[] = [];

		openaiFast({
			registerFlag(name: string) {
				flags.push(name);
			},
			registerCommand(name: string) {
				commands.push(name);
			},
			on(name: string) {
				events.push(name);
			},
			getFlag() {
				return false;
			},
		} as any);

		assert.deepEqual(flags, ["fast"]);
		assert.deepEqual(commands, ["fast"]);
		assert.deepEqual(events.sort(), [
			"before_provider_request",
			"model_select",
			"session_shutdown",
			"session_start",
		]);
	});

	it("--fast overrides persisted startup state and writes active true back to global config", async () => {
		const notifications: string[] = [];
		const writes: Array<{ path: string; config: unknown }> = [];
		let sessionStartHandler: ((event: unknown, ctx: any) => Promise<void>) | undefined;

		const extension = _test.createOpenaiFastExtension({
			resolveFastConfig() {
				return {
					configPath: "/tmp/home/.pi/agent/openai-fast.json",
					persistState: true,
					active: false,
					supportedModels: [{ provider: "openai", id: "gpt-5.4" }],
				};
			},
			readConfigFile() {
				return { persistState: true, active: false, supportedModels: ["openai/gpt-5.4"] };
			},
			writeConfigFile(path: string, config: unknown) {
				writes.push({ path, config });
			},
			footerComponent: { prototype: { render() { return []; } } },
		});

		extension({
			registerFlag() {},
			registerCommand() {},
			on(name: string, handler: any) {
				if (name === "session_start") {
					sessionStartHandler = handler;
				}
			},
			getFlag(name: string) {
				return name === "fast";
			},
		} as any);

		await sessionStartHandler?.({}, {
			cwd: "/tmp/project",
			model: { provider: "openai", id: "gpt-5.4" },
			ui: {
				notify(message: string) {
					notifications.push(message);
				},
			},
		});

		assert.equal(notifications[0], "Fast mode is on for openai/gpt-5.4.");
		assert.deepEqual(writes, [
			{
				path: "/tmp/home/.pi/agent/openai-fast.json",
				config: { persistState: true, active: true, supportedModels: ["openai/gpt-5.4"] },
			},
		]);
	});
});
