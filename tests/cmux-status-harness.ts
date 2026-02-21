import cmuxStatus from "../pi-extensions/cmux-status/index.ts";

type Handler = (event: unknown, ctx: unknown) => Promise<void> | void;

const handlers = new Map<string, Handler[]>();

const pi = {
	on(event: string, handler: Handler) {
		const existing = handlers.get(event) ?? [];
		existing.push(handler);
		handlers.set(event, existing);
	},
} as const;

cmuxStatus(pi as never);

const ctx = {
	cwd: "/tmp/dotfiles",
	hasUI: false,
} as const;

const emit = async (eventName: string, event: unknown): Promise<void> => {
	for (const handler of handlers.get(eventName) ?? []) {
		await handler(event, ctx);
	}
};

const main = async (): Promise<void> => {
	await emit("agent_start", { type: "agent_start" });
	await emit("tool_call", {
		type: "tool_call",
		toolCallId: "call-1",
		toolName: "AskUserQuestion",
		input: {},
	});
	await emit("tool_call", {
		type: "tool_call",
		toolCallId: "call-2",
		toolName: "AskUserQuestion",
		input: {},
	});
	await emit("tool_call", {
		type: "tool_call",
		toolCallId: "call-3",
		toolName: "bash",
		input: { command: "git commit -m 'done'" },
	});
	await emit("agent_end", {
		type: "agent_end",
		messages: [{ role: "assistant", stopReason: "endTurn", content: [] }],
	});

	await emit("agent_start", { type: "agent_start" });
	await emit("agent_end", {
		type: "agent_end",
		messages: [{ role: "assistant", stopReason: "error", content: [] }],
	});
};

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
