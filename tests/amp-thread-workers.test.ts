import assert from "node:assert/strict";
import { describe, it } from "node:test";
import registerThreadWorkers, { buildWorkerPrompt } from "../amp-plugins/thread-workers.ts";

type RegisteredTool = {
	name: string;
	execute(input: Record<string, unknown>, ctx: unknown): Promise<string | void>;
};

function registeredTools() {
	const tools: RegisteredTool[] = [];
	const amp = {
		registerTool(definition: RegisteredTool) {
			tools.push(definition);
			return { unsubscribe() {} };
		},
	};

	registerThreadWorkers(amp as never);

	return tools;
}

describe("thread-workers Amp plugin", () => {
	it("builds worker instructions that report back to the parent thread", () => {
		const prompt = buildWorkerPrompt({
			prompt: "Implement the parser skeleton.",
			parentThreadID: "T-parent",
			label: "parser",
		});

		assert.match(prompt, /Implement the parser skeleton\./);
		assert.match(prompt, /T-parent/);
		assert.match(prompt, /send_to_thread/);
		assert.match(prompt, /parser/);
	});

	it("registers spawn_worker and send_to_thread tools", () => {
		const tools = registeredTools();

		assert.deepEqual(
			tools.map((tool) => tool.name),
			["spawn_worker", "send_to_thread"],
		);
	});

	it("spawn_worker creates a builtin agent thread and seeds it with worker instructions", async () => {
		let requestedMode: string | undefined;
		let createOptions: unknown;
		let workerMessage = "";
		const tools: RegisteredTool[] = [];
		const amp = {
			registerTool(definition: RegisteredTool) {
				tools.push(definition);
				return { unsubscribe() {} };
			},
			getBuiltinAgent(mode: string) {
				requestedMode = mode;
				return {
					async createThread(options: unknown) {
						createOptions = options;
						return {
							id: "T-worker",
							async appendUserMessage(message: { content: string }) {
								workerMessage = message.content;
							},
						};
					},
				};
			},
		};
		registerThreadWorkers(amp as never);

		const spawnWorker = tools.find((tool) => tool.name === "spawn_worker");
		assert.ok(spawnWorker);

		const result = await spawnWorker.execute(
			{ prompt: "Build task one", mode: "deep", label: "task-one", show: true },
			{ thread: { id: "T-parent" } },
		);

		assert.equal(requestedMode, "deep");
		assert.deepEqual(createOptions, { parentThreadID: "T-parent", show: true });
		assert.match(workerMessage, /Build task one/);
		assert.match(workerMessage, /T-parent/);
		assert.match(workerMessage, /send_to_thread/);
		assert.match(String(result), /T-worker/);
	});

	it("send_to_thread appends a steering user message to the target thread", async () => {
		let requestedThreadID: string | undefined;
		let appendedMessage: unknown;
		let appendOptions: unknown;
		const tools: RegisteredTool[] = [];
		const amp = {
			registerTool(definition: RegisteredTool) {
				tools.push(definition);
				return { unsubscribe() {} };
			},
			threads: {
				get(threadID: string) {
					requestedThreadID = threadID;
					return {
						async appendUserMessage(message: unknown, options: unknown) {
							appendedMessage = message;
							appendOptions = options;
						},
					};
				},
			},
		};
		registerThreadWorkers(amp as never);

		const sendToThread = tools.find((tool) => tool.name === "send_to_thread");
		assert.ok(sendToThread);

		const result = await sendToThread.execute({ threadID: "T-parent", message: "Worker done" }, {});

		assert.equal(requestedThreadID, "T-parent");
		assert.deepEqual(appendedMessage, { type: "user-message", content: "Worker done" });
		assert.deepEqual(appendOptions, { steer: true });
		assert.equal(result, "Sent message to thread T-parent.");
	});
});
