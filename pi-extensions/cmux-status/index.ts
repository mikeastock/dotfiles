/**
 * Send high-signal Pi run notifications via cmux only.
 */
import type {
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
	SessionSwitchEvent,
	AgentStartEvent,
	AgentEndEvent,
	ToolCallEvent,
	ToolResultEvent,
} from "@mariozechner/pi-coding-agent";
import type { StopReason } from "@mariozechner/pi-ai";
import { execFile } from "node:child_process";
import { basename } from "node:path";

type TrackerState = {
	sawCommit: boolean;
	askUserQuestionCancelled: boolean;
};

type LastNotification = {
	key: string;
	sentAt: number;
};

const DEFAULT_DEDUPE_SECONDS = 30;
const GIT_COMMIT_RE = /\bgit\b[^\n]*\bcommit\b/;

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

const parseDedupeWindowMs = (): number => {
	const rawSeconds = process.env.PI_CMUX_NOTIFY_DEDUPE_SECONDS;
	if (rawSeconds === undefined) return DEFAULT_DEDUPE_SECONDS * 1_000;

	const seconds = Number(rawSeconds);
	if (!Number.isFinite(seconds) || seconds < 0) {
		return DEFAULT_DEDUPE_SECONDS * 1_000;
	}
	return Math.floor(seconds * 1_000);
};

export default function (pi: ExtensionAPI) {
	const state: TrackerState = {
		sawCommit: false,
		askUserQuestionCancelled: false,
	};
	const dedupeWindowMs = parseDedupeWindowMs();
	let cmuxMissing = false;
	let lastNotification: LastNotification | undefined;

	const cwdBase = (ctx: ExtensionContext): string => basename(ctx.cwd || "pi");

	const notifyRouteArgs = (): string[] => {
		const args: string[] = [];
		const tabId = process.env.CMUX_TAB_ID;
		const panelId = process.env.CMUX_PANEL_ID;
		if (tabId) args.push("--tab", tabId);
		if (panelId) args.push("--panel", panelId);
		return args;
	};

	const recentlyNotified = (key: string): boolean => {
		if (dedupeWindowMs <= 0) return false;
		if (!lastNotification) return false;
		if (lastNotification.key !== key) return false;
		return Date.now() - lastNotification.sentAt < dedupeWindowMs;
	};

	const notify = async (ctx: ExtensionContext, subtitle: string, body: string): Promise<void> => {
		if (cmuxMissing) return;

		const title = `Pi · ${cwdBase(ctx)}`;
		const dedupeKey = `${title}\n${subtitle}\n${body}`;
		if (recentlyNotified(dedupeKey)) return;

		try {
			await execFileAsync("cmux", [
				"notify",
				"--title",
				title,
				"--subtitle",
				subtitle,
				"--body",
				body,
				...notifyRouteArgs(),
			]);
			lastNotification = { key: dedupeKey, sentAt: Date.now() };
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code === "ENOENT") {
				cmuxMissing = true;
			}
		}
	};

	const resetRunState = (): void => {
		state.sawCommit = false;
		state.askUserQuestionCancelled = false;
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

	pi.on("session_start", async (_event: SessionStartEvent) => {
		resetRunState();
	});

	pi.on("session_switch", async (_event: SessionSwitchEvent) => {
		resetRunState();
	});

	pi.on("agent_start", async (_event: AgentStartEvent) => {
		resetRunState();
	});

	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext) => {
		if (event.toolName === "bash") {
			const command = typeof event.input.command === "string" ? event.input.command : "";
			if (command && GIT_COMMIT_RE.test(command)) {
				state.sawCommit = true;
			}
		}

		if (event.toolName === "AskUserQuestion") {
			await notify(ctx, "Needs input", "Pi is waiting for your answer.");
		}
	});

	pi.on("tool_result", async (event: ToolResultEvent, ctx: ExtensionContext) => {
		if (!isAskUserQuestionCancelled(event)) return;
		state.askUserQuestionCancelled = true;
		await notify(ctx, "Failed", "Pi question was cancelled.");
	});

	pi.on("agent_end", async (event: AgentEndEvent, ctx: ExtensionContext) => {
		const stopReason = getStopReason(event.messages);
		if (stopReason === "error" || state.askUserQuestionCancelled) {
			const body = state.askUserQuestionCancelled
				? "Run ended after a cancelled question."
				: "Run ended with an error.";
			await notify(ctx, "Failed", body);
			return;
		}

		const body = state.sawCommit ? "Run complete (commit detected)." : "Run complete.";
		await notify(ctx, "Complete", body);
	});
}
