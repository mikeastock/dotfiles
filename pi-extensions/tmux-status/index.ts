/**
 * Append an agent status icon to the tmux window name.
 *
 * Reads the window name on session start, then updates it with a trailing
 * status icon as the agent state changes.  On shutdown the original name is
 * restored so the fish `_tmux_window_name` function resumes cleanly.
 *
 * States:  new → running → waitingInput / stalled → done / failed
 *
 * Only activates when $TMUX is set.
 */
import type {
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
	SessionSwitchEvent,
	BeforeAgentStartEvent,
	AgentStartEvent,
	AgentEndEvent,
	TurnStartEvent,
	ToolCallEvent,
	ToolResultEvent,
	SessionShutdownEvent,
} from "@mariozechner/pi-coding-agent";
import type { StopReason } from "@mariozechner/pi-ai";
import { execFile } from "node:child_process";

type StatusState = "new" | "running" | "waitingInput" | "stalled" | "done" | "failed";

const STATUS_ICON: Record<StatusState, string> = {
	new: "\u{f011b}",          // 󰄛 nf-md-robot
	running: "\u{f046e}",      // 󰑮 nf-md-run
	waitingInput: "\u{f0184}", // 󰆄 nf-md-comment_question
	stalled: "\u{f03e4}",      // 󰏤 nf-md-pause
	done: "\u{f012c}",         // 󰄬 nf-md-check
	failed: "\u{f0156}",       // 󰅖 nf-md-close
};

const DEFAULT_STALL_TIMEOUT_MS = 180_000;

const parseNumberWithFallback = (raw: string | undefined, fallback: number): number => {
	if (raw === undefined) return fallback;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 0) return fallback;
	return Math.floor(value);
};

const tmuxCommand = (...args: string[]): Promise<string> =>
	new Promise((resolve, reject) => {
		execFile("tmux", args, { timeout: 3_000 }, (error, stdout) => {
			if (error) {
				reject(error);
				return;
			}
			resolve(stdout.trimEnd());
		});
	});

export default function (pi: ExtensionAPI) {
	if (!process.env.TMUX) return;

	const stallTimeoutMs = parseNumberWithFallback(
		process.env.PI_TMUX_STATUS_STALL_TIMEOUT_MS,
		DEFAULT_STALL_TIMEOUT_MS,
	);

	let state: StatusState = "new";
	let running = false;
	let awaitingAskUserQuestion = false;
	let askUserQuestionCancelled = false;
	let timeoutId: ReturnType<typeof setTimeout> | undefined;
	let hasEmittedState = false;
	let baseWindowName: string | undefined;

	// ── tmux window name ──

	const readWindowName = async (): Promise<string> => {
		try {
			return await tmuxCommand("display-message", "-p", "#W");
		} catch {
			return "";
		}
	};

	const setWindowName = async (name: string): Promise<void> => {
		try {
			await tmuxCommand("rename-window", name);
		} catch {
			// Swallow — tmux may have gone away.
		}
	};

	const updateWindowName = async (next: StatusState): Promise<void> => {
		if (!baseWindowName) return;
		await setWindowName(`${baseWindowName} ${STATUS_ICON[next]}`);
	};

	const restoreWindowName = async (): Promise<void> => {
		if (!baseWindowName) return;
		await setWindowName(baseWindowName);
		baseWindowName = undefined;
	};

	// ── State machine ──

	const setState = async (next: StatusState): Promise<void> => {
		if (hasEmittedState && state === next) return;
		hasEmittedState = true;
		state = next;
		await updateWindowName(next);
	};

	const clearStallTimeout = (): void => {
		if (timeoutId === undefined) return;
		clearTimeout(timeoutId);
		timeoutId = undefined;
	};

	const resetStallTimeout = (): void => {
		if (!running || awaitingAskUserQuestion) return;
		clearStallTimeout();
		timeoutId = setTimeout(async () => {
			if (running && state === "running" && !awaitingAskUserQuestion) {
				await setState("stalled");
			}
		}, stallTimeoutMs);
	};

	const markActivity = async (): Promise<void> => {
		if (!running || awaitingAskUserQuestion) return;
		if (state === "stalled" || state === "waitingInput") {
			await setState("running");
		}
		resetStallTimeout();
	};

	const resetState = async (next: StatusState): Promise<void> => {
		running = false;
		awaitingAskUserQuestion = false;
		askUserQuestionCancelled = false;
		clearStallTimeout();
		await setState(next);
	};

	const beginRun = async (): Promise<void> => {
		running = true;
		awaitingAskUserQuestion = false;
		askUserQuestionCancelled = false;
		await setState("running");
		resetStallTimeout();
	};

	// ── Helpers ──

	const getStopReason = (messages: AgentEndEvent["messages"]): StopReason | undefined => {
		for (let i = messages.length - 1; i >= 0; i -= 1) {
			const message = messages[i];
			if (message.role === "assistant" && "stopReason" in message) {
				return message.stopReason;
			}
		}
		return undefined;
	};

	const isAskUserQuestionCancelled = (event: ToolResultEvent): boolean => {
		if (event.toolName !== "AskUserQuestion") return false;
		if (!event.details || typeof event.details !== "object") return false;
		const details = event.details as Record<string, unknown>;
		return details.cancelled === true;
	};

	// ── Event handlers ──

	pi.on("session_start", async (_event: SessionStartEvent, _ctx: ExtensionContext) => {
		baseWindowName = await readWindowName();
		await resetState("new");
	});

	pi.on("session_switch", async (event: SessionSwitchEvent, _ctx: ExtensionContext) => {
		if (!baseWindowName) baseWindowName = await readWindowName();
		await resetState(event.reason === "new" ? "new" : "done");
	});

	pi.on("before_agent_start", async (_event: BeforeAgentStartEvent, _ctx: ExtensionContext) => {
		await markActivity();
	});

	pi.on("agent_start", async (_event: AgentStartEvent, _ctx: ExtensionContext) => {
		await beginRun();
	});

	pi.on("turn_start", async (_event: TurnStartEvent, _ctx: ExtensionContext) => {
		await markActivity();
	});

	pi.on("tool_call", async (event: ToolCallEvent, _ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			awaitingAskUserQuestion = true;
			clearStallTimeout();
			await setState("waitingInput");
			return;
		}
		await markActivity();
	});

	pi.on("tool_result", async (event: ToolResultEvent, _ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			awaitingAskUserQuestion = false;
			if (isAskUserQuestionCancelled(event)) {
				askUserQuestionCancelled = true;
				clearStallTimeout();
				await setState("failed");
				return;
			}
		}
		await markActivity();
	});

	pi.on("agent_end", async (event: AgentEndEvent, _ctx: ExtensionContext) => {
		running = false;
		awaitingAskUserQuestion = false;
		clearStallTimeout();

		const stopReason = getStopReason(event.messages);
		if (stopReason === "error" || askUserQuestionCancelled) {
			await setState("failed");
			return;
		}

		await setState("done");
	});

	pi.on("session_shutdown", async (_event: SessionShutdownEvent, _ctx: ExtensionContext) => {
		clearStallTimeout();
		hasEmittedState = false;
		await restoreWindowName();
	});
}
