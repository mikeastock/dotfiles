/**
 * Stall detection harness for cmux-status.
 *
 * Requires PI_CMUX_STATUS_STALL_TIMEOUT_MS to be set low (e.g. 50).
 */
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

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

const main = async (): Promise<void> => {
	// Start agent, then go idle long enough to trigger the stall timeout
	await emit("agent_start", { type: "agent_start" });

	// Wait for the stall timeout to fire (configured externally to ~50ms)
	await sleep(150);

	// Activity recovers from stall
	await emit("turn_start", { type: "turn_start" });
	await emit("agent_end", {
		type: "agent_end",
		messages: [{ role: "assistant", stopReason: "endTurn", content: [] }],
	});

	await emit("session_shutdown", { type: "session_shutdown" });
};

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
