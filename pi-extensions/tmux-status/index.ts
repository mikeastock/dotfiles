/**
 * Append an agent status icon to the tmux window name.
 *
 * Computes the base window name from ctx.cwd (via the fish __workspace_title
 * function) so the name is always correct regardless of what other tmux
 * panes or sessions might do.  On shutdown the base name is restored so
 * the fish _tmux_window_name function resumes cleanly.
 *
 * States:  new → running → waitingInput / stalled → done / failed
 *
 * Only activates when $TMUX is set.
 */
import type {
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
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
import { HANDOFF_ACTIVITY_END_EVENT, HANDOFF_ACTIVITY_START_EVENT, type HandoffActivityEvent } from "../handoff/events.js";
import { SUBAGENT_RUN_END_EVENT, SUBAGENT_RUN_START_EVENT, type SubagentRunEndEvent, type SubagentRunStartEvent } from "../subagent/events.js";
import { TmuxStatusState, type StatusState } from "./state.js";

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

const execCommand = (cmd: string, args: string[], options?: { cwd?: string }): Promise<string> =>
	new Promise((resolve, reject) => {
		execFile(cmd, args, { timeout: 3_000, ...options }, (error, stdout) => {
			if (error) {
				reject(error);
				return;
			}
			resolve(stdout.trimEnd());
		});
	});

const tmuxCommand = (...args: string[]): Promise<string> => execCommand("tmux", args);

export default function (pi: ExtensionAPI) {
	if (!process.env.TMUX) return;

	const paneId = process.env.TMUX_PANE;
	if (!paneId) return;

	const stallTimeoutMs = parseNumberWithFallback(
		process.env.PI_TMUX_STATUS_STALL_TIMEOUT_MS,
		DEFAULT_STALL_TIMEOUT_MS,
	);

	let state: StatusState = "new";
	let running = false;
	const statusTracker = new TmuxStatusState();
	let awaitingAskUserQuestion = false;
	let askUserQuestionCancelled = false;
	let timeoutId: ReturnType<typeof setTimeout> | undefined;
	let hasEmittedState = false;
	let currentCwd: string | undefined;
	let baseWindowName: string | undefined;
	let windowId: string | undefined;

	// ── tmux window name ──
	//
	// We compute the base window name from ctx.cwd instead of reading the
	// current tmux window name.  This avoids races where another pane/session
	// renames our window between shutdown and startup (e.g. during /reload).
	//
	// `tmux rename-window` without -t targets the *focused* window, not the
	// pane's window.  We resolve the window ID from $TMUX_PANE once on startup
	// and always pass `-t <window_id>`.

	const resolveWindowId = async (): Promise<string | undefined> => {
		try {
			return await tmuxCommand("display-message", "-t", paneId, "-p", "#{window_id}");
		} catch {
			return undefined;
		}
	};

	const computeBaseWindowName = async (cwd: string): Promise<string> => {
		// Prefer the fish __workspace_title function for consistency with the
		// fish _tmux_window_name handler (includes repo aliases and nerd font
		// git branch icon).
		try {
			return await execCommand("fish", ["-c", "__workspace_title"], { cwd });
		} catch {
			// Fallback: dir + git branch (no aliases or icons).
		}

		const dir = basename(cwd);
		try {
			let branch = await execCommand("git", ["-C", cwd, "symbolic-ref", "--short", "HEAD"]);
			if (!branch) branch = await execCommand("git", ["-C", cwd, "rev-parse", "--short", "HEAD"]);
			if (branch && branch.length > 20) branch = branch.slice(0, 19) + "…";
			return branch ? `${dir} ${branch}` : dir;
		} catch {
			return dir;
		}
	};

	const setWindowName = async (name: string): Promise<void> => {
		if (!windowId) return;
		try {
			await tmuxCommand("rename-window", "-t", windowId, name);
		} catch {
			// Swallow — tmux may have gone away.
		}
	};

	const updateWindowName = async (next: StatusState): Promise<void> => {
		if (!currentCwd) return;
		baseWindowName = await computeBaseWindowName(currentCwd);
		await setWindowName(`${baseWindowName} ${STATUS_ICON[next]}`);
	};

	const restoreWindowName = async (): Promise<void> => {
		if (!currentCwd) return;
		const name = await computeBaseWindowName(currentCwd);
		await setWindowName(name);
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

	const resetState = async (next: Extract<StatusState, "new" | "done" | "failed">): Promise<void> => {
		running = false;
		awaitingAskUserQuestion = false;
		askUserQuestionCancelled = false;
		clearStallTimeout();
		await setState(statusTracker.reset(next));
	};

	const beginRun = async (): Promise<void> => {
		running = true;
		awaitingAskUserQuestion = false;
		askUserQuestionCancelled = false;
		await setState("running");
		resetStallTimeout();
	};

	const applyTerminalState = async (next: Extract<StatusState, "done" | "failed">): Promise<void> => {
		statusTracker.setTerminalState(next);
		await setState(statusTracker.getIdleState());
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

	const isAsyncSubagentRunStartEvent = (data: unknown): data is SubagentRunStartEvent => {
		if (!data || typeof data !== "object") return false;
		const event = data as Record<string, unknown>;
		return typeof event.id === "string" && event.execution === "async";
	};

	const isAsyncSubagentRunEndEvent = (data: unknown): data is SubagentRunEndEvent => {
		if (!isAsyncSubagentRunStartEvent(data)) return false;
		return (data as { status?: unknown }).status === "completed"
			|| (data as { status?: unknown }).status === "failed"
				? typeof (data as { exitCode?: unknown }).exitCode === "number"
				: false;
	};

	const isHandoffActivityEvent = (data: unknown): data is HandoffActivityEvent => {
		if (!data || typeof data !== "object") return false;
		const event = data as Record<string, unknown>;
		return event.phase === "generation" || event.phase === "seeding";
	};

	// ── Event handlers ──

	pi.on("session_start", async (event: SessionStartEvent, ctx: ExtensionContext) => {
		if (!windowId) windowId = await resolveWindowId();
		currentCwd = ctx.cwd;
		await resetState(event.reason === "resume" || event.reason === "fork" ? "done" : "new");
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
			await applyTerminalState("failed");
			return;
		}

		await applyTerminalState("done");
	});

	pi.events.on(HANDOFF_ACTIVITY_START_EVENT, async (data: unknown) => {
		if (!isHandoffActivityEvent(data)) return;
		const next = statusTracker.startExternalActivity("handoff");
		if (!next || running || awaitingAskUserQuestion) return;
		clearStallTimeout();
		await setState(next);
	});

	pi.events.on(HANDOFF_ACTIVITY_END_EVENT, async (data: unknown) => {
		if (!isHandoffActivityEvent(data)) return;
		const next = statusTracker.endExternalActivity("handoff");
		if (!next || running || awaitingAskUserQuestion) return;
		await setState(next);
	});

	pi.events.on(SUBAGENT_RUN_START_EVENT, async (data: unknown) => {
		if (!isAsyncSubagentRunStartEvent(data)) return;
		const next = statusTracker.handleAsyncStart(data.id);
		if (!next || running || awaitingAskUserQuestion) return;
		clearStallTimeout();
		await setState(next);
	});

	pi.events.on(SUBAGENT_RUN_END_EVENT, async (data: unknown) => {
		if (!isAsyncSubagentRunEndEvent(data)) return;
		const next = statusTracker.handleAsyncEnd(data.id, data.status);
		if (!next || running || awaitingAskUserQuestion) return;
		await setState(next);
	});

	pi.on("session_shutdown", async (_event: SessionShutdownEvent, _ctx: ExtensionContext) => {
		clearStallTimeout();
		hasEmittedState = false;
		await restoreWindowName();
	});
}
