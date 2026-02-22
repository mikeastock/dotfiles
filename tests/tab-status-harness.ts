import tabStatus from "../pi-extensions/tab-status/index.ts";

type Handler = (event: unknown, ctx: unknown) => Promise<void> | void;

const handlers = new Map<string, Handler[]>();
const titles: string[] = [];
const oscWrites: string[] = [];

const pi = {
	on(event: string, handler: Handler) {
		const existing = handlers.get(event) ?? [];
		existing.push(handler);
		handlers.set(event, existing);
	},
} as const;

const originalWrite = process.stdout.write.bind(process.stdout);
(process.stdout as unknown as { write: typeof process.stdout.write }).write = ((chunk: unknown) => {
	oscWrites.push(String(chunk));
	return true;
}) as typeof process.stdout.write;

tabStatus(pi as never);

const ctx = {
	cwd: "/tmp/dotfiles",
	hasUI: true,
	ui: {
		setTitle(title: string) {
			titles.push(title);
		},
	},
} as const;

const emit = async (eventName: string, event: unknown): Promise<void> => {
	for (const handler of handlers.get(eventName) ?? []) {
		await handler(event, ctx);
	}
};

const formatOsc = (value: string): string =>
	value.replace(/\u001b/g, "<ESC>").replace(/\u0007/g, "<BEL>");

const main = async (): Promise<void> => {
	await emit("session_start", { type: "session_start" });
	await emit("agent_start", { type: "agent_start" });
	await emit("tool_call", {
		type: "tool_call",
		toolCallId: "call-1",
		toolName: "AskUserQuestion",
		input: {},
	});
	await emit("tool_result", {
		type: "tool_result",
		toolCallId: "call-1",
		toolName: "AskUserQuestion",
		details: { cancelled: true },
	});
	await emit("agent_end", {
		type: "agent_end",
		messages: [{ role: "assistant", stopReason: "error", content: [] }],
	});

	await emit("agent_start", { type: "agent_start" });
	await emit("tool_call", {
		type: "tool_call",
		toolCallId: "call-2",
		toolName: "bash",
		input: { command: "git commit -m 'done'" },
	});
	await emit("agent_end", {
		type: "agent_end",
		messages: [{ role: "assistant", stopReason: "endTurn", content: [] }],
	});
	await emit("session_shutdown", { type: "session_shutdown" });

};

main()
	.catch((error) => {
		originalWrite(`HARNESS_ERROR ${String(error)}\n`);
		process.exitCode = 1;
	})
	.finally(() => {
		(process.stdout as unknown as { write: typeof process.stdout.write }).write = originalWrite;
		for (const title of titles) {
			originalWrite(`TITLE ${title}\n`);
		}
		for (const value of oscWrites) {
			originalWrite(`OSC ${formatOsc(value)}\n`);
		}
	});
