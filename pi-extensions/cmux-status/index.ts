/**
 * Update cmux sidebar status pill, terminal title, and Ghostty-native status
 * (OSC progress + notifications) to reflect Pi agent lifecycle.
 *
 * States: new | running | waiting-input | stalled | complete | failed
 *
 * Environment variables:
 *   PI_CMUX_STATUS_KEY                – cmux status key (default: "pi")
 *   PI_CMUX_STATUS_STALL_TIMEOUT_MS   – ms of inactivity before "stalled" (default: 180000)
 *   PI_CMUX_STATUS_GHOSTTY_NOTIFY     – "off" | "important" | "all" (default: "important")
 *   PI_CMUX_STATUS_NOTIFY_DEDUPE_SECONDS – dedupe window in seconds (default: 30)
 *   PI_CMUX_STATUS_USE_FISH_HELPER    – set "0" to disable fish helper (default: enabled)
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

type StatusState = "new" | "running" | "waiting-input" | "stalled" | "complete" | "failed";
type NotifyMode = "off" | "important" | "all";
type LastNotification = { key: string; sentAt: number };

const STATUS_ICON: Record<StatusState, string> = {
	new: " 󱞩",
	running: " ",
	"waiting-input": " ",
	stalled: " ",
	complete: " ",
	failed: " ",
};

const CMUX_VALUE: Record<StatusState, string | undefined> = {
	new: undefined,
	running: "running",
	"waiting-input": "waiting-input",
	stalled: "stalled",
	complete: "complete",
	failed: "failed",
};

const DEFAULT_STATUS_KEY = "pi";
const DEFAULT_STALL_TIMEOUT_MS = 180_000;
const DEFAULT_NOTIFY_DEDUPE_SECONDS = 30;
const ESC = "\u001b]";
const BEL = "\u0007";

const parseStatusKey = (): string => {
	const raw = process.env.PI_CMUX_STATUS_KEY;
	if (!raw) return DEFAULT_STATUS_KEY;
	const trimmed = raw.trim();
	return trimmed.length > 0 ? trimmed : DEFAULT_STATUS_KEY;
};

const parseNotifyMode = (): NotifyMode => {
	const raw = (process.env.PI_CMUX_STATUS_GHOSTTY_NOTIFY ?? "important").trim().toLowerCase();
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

const execFileAsync = (file: string, args: string[]): Promise<void> =>
	new Promise((resolve, reject) => {
		execFile(file, args, { timeout: 3_000 }, (error) => {
			if (error) {
				reject(error);
				return;
			}
			resolve();
		});
	});

export default function (pi: ExtensionAPI) {
	const statusKey = parseStatusKey();
	const stallTimeoutMs = parseNumberWithFallback(process.env.PI_CMUX_STATUS_STALL_TIMEOUT_MS, DEFAULT_STALL_TIMEOUT_MS);
	const notifyMode = parseNotifyMode();
	const notifyDedupeWindowMs =
		parseNumberWithFallback(process.env.PI_CMUX_STATUS_NOTIFY_DEDUPE_SECONDS, DEFAULT_NOTIFY_DEDUPE_SECONDS) * 1_000;
	const isGhostty = process.env.TERM_PROGRAM === "ghostty";
	const useFishHelper = process.env.PI_CMUX_STATUS_USE_FISH_HELPER !== "0";

	let state: StatusState = "new";
	let running = false;
	let awaitingAskUserQuestion = false;
	let askUserQuestionCancelled = false;
	let cmuxMissing = false;
	let currentCmuxStatus: string | undefined;
	let timeoutId: ReturnType<typeof setTimeout> | undefined;
	let lastNotification: LastNotification | undefined;
	let fishHelperMissing = false;
	let hasEmittedState = false;

	// ── Cmux ──

	const runCmux = async (args: string[]): Promise<boolean> => {
		if (cmuxMissing) return false;
		try {
			await execFileAsync("cmux", args);
			return true;
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code === "ENOENT") {
				cmuxMissing = true;
			}
			return false;
		}
	};

	const setCmuxStatus = async (value: string): Promise<void> => {
		if (currentCmuxStatus === value) return;
		const ok = await runCmux(["set-status", statusKey, value]);
		if (ok) {
			currentCmuxStatus = value;
		}
	};

	const clearCmuxStatus = async (): Promise<void> => {
		if (!currentCmuxStatus) return;
		const ok = await runCmux(["clear-status", statusKey]);
		if (ok) {
			currentCmuxStatus = undefined;
		}
	};

	// ── Terminal title ──

	const cwdBase = (ctx: ExtensionContext): string => basename(ctx.cwd || "pi");

	const setTitle = (ctx: ExtensionContext, next: StatusState): void => {
		if (!ctx.hasUI) return;
		ctx.ui.setTitle(`pi - ${cwdBase(ctx)}${STATUS_ICON[next]}`);
	};

	// ── Ghostty OSC / notifications ──

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

	const applyGhosttyState = (next: StatusState): void => {
		switch (next) {
			case "new":
				setProgressNone();
				break;
			case "running":
				setProgressIndeterminate();
				break;
			case "waiting-input":
			case "stalled":
				setProgressPaused();
				break;
			case "complete":
				setProgressDone();
				break;
			case "failed":
				setProgressFailed();
				break;
		}
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
		setTitle(ctx, state);
	};

	// ── Unified state machine ──

	const setState = async (ctx: ExtensionContext, next: StatusState): Promise<void> => {
		if (hasEmittedState && state === next) return;
		hasEmittedState = true;
		state = next;

		setTitle(ctx, next);
		applyGhosttyState(next);

		const cmuxValue = CMUX_VALUE[next];
		if (cmuxValue) {
			await setCmuxStatus(cmuxValue);
		} else {
			await clearCmuxStatus();
		}
	};

	// ── Stall timeout ──

	const clearStallTimeout = (): void => {
		if (timeoutId === undefined) return;
		clearTimeout(timeoutId);
		timeoutId = undefined;
	};

	const resetStallTimeout = (ctx: ExtensionContext): void => {
		if (!running || awaitingAskUserQuestion) return;
		clearStallTimeout();
		timeoutId = setTimeout(async () => {
			if (running && state === "running" && !awaitingAskUserQuestion) {
				await setState(ctx, "stalled");
			}
		}, stallTimeoutMs);
	};

	// ── Activity helpers ──

	const markActivity = async (ctx: ExtensionContext): Promise<void> => {
		if (!running || awaitingAskUserQuestion) return;
		if (state === "stalled" || state === "waiting-input") {
			await setState(ctx, "running");
		}
		resetStallTimeout(ctx);
	};

	const resetState = async (ctx: ExtensionContext, next: StatusState): Promise<void> => {
		running = false;
		awaitingAskUserQuestion = false;
		askUserQuestionCancelled = false;
		clearStallTimeout();
		await setState(ctx, next);
	};

	const beginRun = async (ctx: ExtensionContext): Promise<void> => {
		running = true;
		awaitingAskUserQuestion = false;
		askUserQuestionCancelled = false;
		await setState(ctx, "running");
		resetStallTimeout(ctx);
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

	pi.on("session_start", async (_event: SessionStartEvent, ctx: ExtensionContext) => {
		await resetState(ctx, "new");
	});

	pi.on("session_switch", async (event: SessionSwitchEvent, ctx: ExtensionContext) => {
		await resetState(ctx, event.reason === "new" ? "new" : "complete");
	});

	pi.on("before_agent_start", async (_event: BeforeAgentStartEvent, ctx: ExtensionContext) => {
		await markActivity(ctx);
	});

	pi.on("agent_start", async (_event: AgentStartEvent, ctx: ExtensionContext) => {
		await beginRun(ctx);
	});

	pi.on("turn_start", async (_event: TurnStartEvent, ctx: ExtensionContext) => {
		await markActivity(ctx);
	});

	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			awaitingAskUserQuestion = true;
			clearStallTimeout();
			await setState(ctx, "waiting-input");
			notify(ctx, `Pi · ${cwdBase(ctx)}`, "Needs input");
			return;
		}
		await markActivity(ctx);
	});

	pi.on("tool_result", async (event: ToolResultEvent, ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			awaitingAskUserQuestion = false;
			if (isAskUserQuestionCancelled(event)) {
				askUserQuestionCancelled = true;
				clearStallTimeout();
				await setState(ctx, "failed");
				notify(ctx, `Pi · ${cwdBase(ctx)}`, "Question cancelled");
				return;
			}
		}
		await markActivity(ctx);
	});

	pi.on("agent_end", async (event: AgentEndEvent, ctx: ExtensionContext) => {
		running = false;
		awaitingAskUserQuestion = false;
		clearStallTimeout();

		const stopReason = getStopReason(event.messages);
		if (stopReason === "error" || askUserQuestionCancelled) {
			await setState(ctx, "failed");
			notify(ctx, `Pi · ${cwdBase(ctx)}`, "Run failed");
			return;
		}

		await setState(ctx, "complete");
		if (notifyMode === "all") {
			notify(ctx, `Pi · ${cwdBase(ctx)}`, "Run complete");
		}
	});

	pi.on("session_shutdown", async (_event: SessionShutdownEvent, ctx: ExtensionContext) => {
		clearStallTimeout();
		setProgressNone();
		await clearCmuxStatus();
		hasEmittedState = false;
		if (!ctx.hasUI) return;
		ctx.ui.setTitle(`pi - ${cwdBase(ctx)}`);
	});
}
