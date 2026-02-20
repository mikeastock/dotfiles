/**
 * Send Pi run status updates to cmux notifications with macOS fallback.
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

type StatusState = "new" | "running" | "doneCommitted" | "doneNoCommit" | "blocked";

type StatusTracker = {
	state: StatusState;
	running: boolean;
	sawCommit: boolean;
	awaitingAskUserQuestion: boolean;
	askUserQuestionCancelled: boolean;
};

type NotificationState = {
	subtitle: string;
	body: string;
};

const STATUS_TEXT: Record<StatusState, string> = {
	new: ":new",
	running: ":running...",
	doneCommitted: ":✅",
	doneNoCommit: ":🚧",
	blocked: ":🛑",
};

const STATUS_NOTIFICATION: Record<StatusState, NotificationState> = {
	new: {
		subtitle: "New session",
		body: "Ready for the next prompt.",
	},
	running: {
		subtitle: "Running",
		body: "Pi is working on your request.",
	},
	doneCommitted: {
		subtitle: "Complete",
		body: "Run complete with a git commit.",
	},
	doneNoCommit: {
		subtitle: "Complete",
		body: "Run complete with no git commit.",
	},
	blocked: {
		subtitle: "Needs input",
		body: "Pi is waiting for input or attention.",
	},
};

const INACTIVE_TIMEOUT_MS = 180_000;
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

const escapeAppleScript = (value: string): string =>
	value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

export default function (pi: ExtensionAPI) {
	const status: StatusTracker = {
		state: "new",
		running: false,
		sawCommit: false,
		awaitingAskUserQuestion: false,
		askUserQuestionCancelled: false,
	};
	let timeoutId: ReturnType<typeof setTimeout> | undefined;
	let cmuxMissing = false;
	let osascriptMissing = false;
	const nativeClearTimeout = globalThis.clearTimeout;

	const cwdBase = (ctx: ExtensionContext): string => basename(ctx.cwd || "pi");

	const notifyStatus = async (ctx: ExtensionContext, next: StatusState): Promise<void> => {
		const detail = STATUS_NOTIFICATION[next];
		const title = `Pi · ${cwdBase(ctx)} ${STATUS_TEXT[next]}`;

		if (!cmuxMissing) {
			try {
				const args = ["notify", "--title", title, "--subtitle", detail.subtitle, "--body", detail.body];
				await execFileAsync("cmux", args);
				return;
			} catch (error) {
				const err = error as NodeJS.ErrnoException;
				if (err.code === "ENOENT") {
					cmuxMissing = true;
				}
			}
		}

		if (process.platform !== "darwin" || osascriptMissing) return;

		try {
			await execFileAsync("osascript", [
				"-e",
				`display notification "${escapeAppleScript(detail.subtitle)} — ${escapeAppleScript(detail.body)}" with title "${escapeAppleScript(title)}"`,
			]);
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code === "ENOENT") {
				osascriptMissing = true;
			}
		}
	};

	const setStatus = async (ctx: ExtensionContext, next: StatusState, force = false): Promise<void> => {
		if (!force && status.state === next) return;
		status.state = next;
		await notifyStatus(ctx, next);
	};

	const clearStatusTimeout = (): void => {
		if (timeoutId === undefined) return;
		nativeClearTimeout(timeoutId);
		timeoutId = undefined;
	};

	const resetTimeout = (ctx: ExtensionContext): void => {
		clearStatusTimeout();
		timeoutId = setTimeout(() => {
			if (status.running && status.state === "running") {
				void setStatus(ctx, "blocked");
			}
		}, INACTIVE_TIMEOUT_MS);
	};

	const markActivity = async (ctx: ExtensionContext): Promise<void> => {
		if (status.awaitingAskUserQuestion) return;
		if (status.state === "blocked") {
			await setStatus(ctx, "running");
		}
		if (!status.running) return;
		resetTimeout(ctx);
	};

	const resetState = async (ctx: ExtensionContext, next: StatusState): Promise<void> => {
		status.running = false;
		status.sawCommit = false;
		status.awaitingAskUserQuestion = false;
		status.askUserQuestionCancelled = false;
		clearStatusTimeout();
		await setStatus(ctx, next, true);
	};

	const beginRun = async (ctx: ExtensionContext): Promise<void> => {
		status.running = true;
		status.sawCommit = false;
		status.awaitingAskUserQuestion = false;
		status.askUserQuestionCancelled = false;
		await setStatus(ctx, "running");
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
		await resetState(ctx, "new");
	});

	pi.on("session_switch", async (event: SessionSwitchEvent, ctx: ExtensionContext) => {
		await resetState(ctx, event.reason === "new" ? "new" : "doneCommitted");
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
		if (event.toolName === "bash") {
			const command = typeof event.input.command === "string" ? event.input.command : "";
			if (command && GIT_COMMIT_RE.test(command)) {
				status.sawCommit = true;
			}
		}
		if (event.toolName === "AskUserQuestion") {
			status.awaitingAskUserQuestion = true;
			clearStatusTimeout();
			await setStatus(ctx, "blocked");
			return;
		}
		await markActivity(ctx);
	});

	pi.on("tool_result", async (event: ToolResultEvent, ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			status.awaitingAskUserQuestion = false;
			if (isAskUserQuestionCancelled(event)) {
				status.askUserQuestionCancelled = true;
				clearStatusTimeout();
				await setStatus(ctx, "blocked");
				return;
			}
		}
		await markActivity(ctx);
	});

	pi.on("agent_end", async (event: AgentEndEvent, ctx: ExtensionContext) => {
		status.running = false;
		clearStatusTimeout();
		const stopReason = getStopReason(event.messages);
		if (stopReason === "error" || status.askUserQuestionCancelled) {
			await setStatus(ctx, "blocked");
			return;
		}
		await setStatus(ctx, status.sawCommit ? "doneCommitted" : "doneNoCommit");
	});

	pi.on("session_shutdown", async (_event: SessionShutdownEvent, _ctx: ExtensionContext) => {
		clearStatusTimeout();
	});
}
