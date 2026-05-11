import test from "node:test";
import assert from "node:assert/strict";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerExecCommandTool } from "../src/tools/exec-command-tool.ts";

function createRegisteredTool() {
	let tool:
		| {
				prepareArguments?: (args: unknown) => Record<string, unknown>;
				execute?: (toolCallId: string, params: unknown, signal?: AbortSignal, onUpdate?: unknown, ctx?: { cwd: string }) => Promise<unknown>;
			}
		| undefined;
	const pi = {
		registerTool(definition: typeof tool) {
			tool = definition;
		},
	} as unknown as ExtensionAPI;
	return {
		pi,
		getTool() {
			assert.ok(tool);
			return tool;
		},
	};
}

test("exec_command prepareArguments normalizes common command aliases", () => {
	const { pi, getTool } = createRegisteredTool();
	registerExecCommandTool(pi);

	assert.deepEqual(getTool().prepareArguments?.({ command: "pwd", cwd: "/tmp" }), {
		cmd: "pwd",
		command: "pwd",
		cwd: "/tmp",
		workdir: "/tmp",
	});
});

test("exec_command prepareArguments preserves invalid optional field types for validation", () => {
	const { pi, getTool } = createRegisteredTool();
	registerExecCommandTool(pi);

	assert.deepEqual(getTool().prepareArguments?.({ cmd: "ls", tty: "true", yield_time_ms: "1000" }), {
		cmd: "ls",
		tty: "true",
		yield_time_ms: "1000",
	});
});

test("exec_command execute delegates to Pi's native bash result shape", async () => {
	const { pi, getTool } = createRegisteredTool();
	registerExecCommandTool(pi);

	const result = await getTool().execute?.("call-native-bash", { cmd: "printf native-pi-bash" }, undefined, undefined, {
		cwd: process.cwd(),
	});

	assert.deepEqual(result, {
		content: [{ type: "text", text: "native-pi-bash" }],
		details: undefined,
	});
});
