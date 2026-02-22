/**
 * Update terminal title and Ghostty-native status (OSC progress + notifications).
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
import { basename } from "node:path";

type StatusState = "new" | "running" | "waitingInput" | "stalled" | "done" | "failed";

type StatusTracker = {
	state: StatusState;
	running: boolean;
	awaitingAskUserQuestion: boolean;
	askUserQuestionCancelled: boolean;
};

type NotifyMode = "off" | "important" | "all";

type LastNotification = {
	key: string;
	sentAt: number;
};

const STATUS_TEXT: Record<StatusState, string> = {
	new: " 󱞩",
	running: " ",
	waitingInput: " ",
	stalled: " ",
	done: " ",
	failed: " ",
};

const DEFAULT_STALL_TIMEOUT_MS = 180_000;
const DEFAULT_NOTIFY_DEDUPE_SECONDS = 30;
const ESC = "\u001b]";
const BEL = "\u0007";

const parseNotifyMode = (): NotifyMode => {
	const raw = (process.env.PI_TAB_STATUS_GHOSTTY_NOTIFY ?? "important").trim().toLowerCase();
	if (raw === "off" || raw === "important" || raw === "all") return raw;
	return "important";
};

const parseNumberWithFallback = (raw: string | undefined, fallback: number): number => {
	if (raw === undefined) return fallback;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 0) return fallback;
	return Math.floor(value);
};

const sanitizeOscField = (value: string): string => value.replace(/[;\u0007\u001b]/g, " ").trim();

export default function (pi: ExtensionAPI) {
	const status: StatusTracker = {
		state: "new",
		running: false,
		awaitingAskUserQuestion: false,
		askUserQuestionCancelled: false,
	};

	const stallTimeoutMs = parseNumberWithFallback(process.env.PI_TAB_STATUS_STALL_TIMEOUT_MS, DEFAULT_STALL_TIMEOUT_MS);
	const notifyMode = parseNotifyMode();
	const notifyDedupeWindowMs = parseNumberWithFallback(
		process.env.PI_TAB_STATUS_NOTIFY_DEDUPE_SECONDS,
		DEFAULT_NOTIFY_DEDUPE_SECONDS,
	) * 1_000;
	const isGhostty = process.env.TERM_PROGRAM === "ghostty";
	const useFishHelper = process.env.PI_TAB_STATUS_USE_FISH_HELPER !== "0";

	let timeoutId: ReturnType<typeof setTimeout> | undefined;
	let lastNotification: LastNotification | undefined;
	let fishHelperMissing = false;
	let hasEmittedState = false;

	const cwdBase = (ctx: ExtensionContext): string => basename(ctx.cwd || "pi");

	const setTitle = (ctx: ExtensionContext, next: StatusState): void => {
		status.state = next;
		if (!ctx.hasUI) return;
		ctx.ui.setTitle(`pi - ${cwdBase(ctx)}${STATUS_TEXT[next]}`);
	};

	const emitOsc = (command: string): void => {
		if (!isGhostty) return;
		process.stdout.write(`${ESC}${command}${BEL}`);
	};

	const runFishHelper = (action: string, title?: string, body?: string): boolean => {
		if (!isGhostty || !useFishHelper || fishHelperMissing) return false;
		execFile(
			"fish",
			["-c", "pi_ghostty_status $argv[1] $argv[2] $argv[3]", "--", action, title ?? "", body ?? ""],
			(error) => {
				if (!error) return;
				const err = error as NodeJS.ErrnoException;
				if (err.code === "ENOENT") {
					fishHelperMissing = true;
				}
			},
		);
		return true;
	};

	const setProgressNone = (): void => {
		if (runFishHelper("clear")) return;
		emitOsc("9;4;0");
	};

	const setProgressIndeterminate = (): void => {
		if (runFishHelper("running")) return;
		emitOsc("9;4;3");
	};

	const setProgressPaused = (): void => {
		if (runFishHelper("waiting")) return;
		emitOsc("9;4;4");
	};

	const setProgressDone = (): void => {
		if (runFishHelper("done")) return;
		emitOsc("9;4;1;100");
	};

	const setProgressFailed = (): void => {
		if (runFishHelper("failed")) return;
		emitOsc("9;4;2;100");
	};

	const recentlyNotified = (key: string): boolean => {
		if (notifyDedupeWindowMs <= 0) return false;
		if (!lastNotification) return false;
		if (lastNotification.key !== key) return false;
		return Date.now() - lastNotification.sentAt < notifyDedupeWindowMs;
	};

	const notify = (ctx: ExtensionContext, title: string, body: string): void => {
		if (!isGhostty || notifyMode === "off") return;
		const safeTitle = sanitizeOscField(title);
		const safeBody = sanitizeOscField(body);
		const key = `${safeTitle}\n${safeBody}`;
		if (recentlyNotified(key)) return;
		if (!runFishHelper("notify", safeTitle, safeBody)) {
			emitOsc(`777;notify;${safeTitle};${safeBody}`);
		}
		lastNotification = { key, sentAt: Date.now() };

		if (!ctx.hasUI) return;
		ctx.ui.setTitle(`pi - ${cwdBase(ctx)}${STATUS_TEXT[status.state]}`);
	};

	const applyGhosttyState = (next: StatusState): void => {
		switch (next) {
			case "new":
				setProgressNone();
				break;
			case "running":
				setProgressIndeterminate();
				break;
			case "waitingInput":
			case "stalled":
				setProgressPaused();
				break;
			case "done":
				setProgressDone();
				break;
			case "failed":
				setProgressFailed();
				break;
		}
	};

	const setState = (ctx: ExtensionContext, next: StatusState): void => {
		if (hasEmittedState && status.state === next) return;
		hasEmittedState = true;
		setTitle(ctx, next);
		applyGhosttyState(next);
	};

	const clearTabTimeout = (): void => {
		if (timeoutId === undefined) return;
		clearTimeout(timeoutId);
		timeoutId = undefined;
	};

	const resetTimeout = (ctx: ExtensionContext): void => {
		if (!status.running || status.awaitingAskUserQuestion) return;
		clearTabTimeout();
		timeoutId = setTimeout(() => {
			if (status.running && status.state === "running" && !status.awaitingAskUserQuestion) {
				setState(ctx, "stalled");
			}
		}, stallTimeoutMs);
	};

	const markActivity = (ctx: ExtensionContext): void => {
		if (!status.running) return;
		if (status.awaitingAskUserQuestion) return;
		if (status.state === "stalled" || status.state === "waitingInput") {
			setState(ctx, "running");
		}
		resetTimeout(ctx);
	};

	const resetState = (ctx: ExtensionContext, next: StatusState): void => {
		status.running = false;
		status.awaitingAskUserQuestion = false;
		status.askUserQuestionCancelled = false;
		clearTabTimeout();
		setState(ctx, next);
	};

	const beginRun = (ctx: ExtensionContext): void => {
		status.running = true;
		status.awaitingAskUserQuestion = false;
		status.askUserQuestionCancelled = false;
		setState(ctx, "running");
		resetTimeout(ctx);
	};

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

	pi.on("session_start", async (_event: SessionStartEvent, ctx: ExtensionContext) => {
		resetState(ctx, "new");
	});

	pi.on("session_switch", async (event: SessionSwitchEvent, ctx: ExtensionContext) => {
		resetState(ctx, event.reason === "new" ? "new" : "done");
	});

	pi.on("before_agent_start", async (_event: BeforeAgentStartEvent, ctx: ExtensionContext) => {
		markActivity(ctx);
	});

	pi.on("agent_start", async (_event: AgentStartEvent, ctx: ExtensionContext) => {
		beginRun(ctx);
	});

	pi.on("turn_start", async (_event: TurnStartEvent, ctx: ExtensionContext) => {
		markActivity(ctx);
	});

	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			status.awaitingAskUserQuestion = true;
			clearTabTimeout();
			setState(ctx, "waitingInput");
			notify(ctx, `Pi · ${cwdBase(ctx)}`, "Needs input");
			return;
		}

		markActivity(ctx);
	});

	pi.on("tool_result", async (event: ToolResultEvent, ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			status.awaitingAskUserQuestion = false;
			if (isAskUserQuestionCancelled(event)) {
				status.askUserQuestionCancelled = true;
				clearTabTimeout();
				setState(ctx, "failed");
				notify(ctx, `Pi · ${cwdBase(ctx)}`, "Question cancelled");
				return;
			}
		}

		markActivity(ctx);
	});

	pi.on("agent_end", async (event: AgentEndEvent, ctx: ExtensionContext) => {
		status.running = false;
		status.awaitingAskUserQuestion = false;
		clearTabTimeout();

		const stopReason = getStopReason(event.messages);
		if (stopReason === "error" || status.askUserQuestionCancelled) {
			setState(ctx, "failed");
			notify(ctx, `Pi · ${cwdBase(ctx)}`, "Run failed");
			return;
		}

		setState(ctx, "done");
		if (notifyMode === "all") {
			notify(ctx, `Pi · ${cwdBase(ctx)}`, "Run complete");
		}
	});

	pi.on("session_shutdown", async (_event: SessionShutdownEvent, ctx: ExtensionContext) => {
		clearTabTimeout();
		setProgressNone();
		hasEmittedState = false;
		if (!ctx.hasUI) return;
		ctx.ui.setTitle(`pi - ${cwdBase(ctx)}`);
	});
}
