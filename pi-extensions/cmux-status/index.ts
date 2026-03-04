/**
 * Update cmux sidebar status pill to reflect Pi agent lifecycle.
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

const DEFAULT_STATUS_KEY = "pi";

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

const parseStatusKey = (): string => {
	const raw = process.env.PI_CMUX_STATUS_KEY;
	if (!raw) return DEFAULT_STATUS_KEY;
	const trimmed = raw.trim();
	return trimmed.length > 0 ? trimmed : DEFAULT_STATUS_KEY;
};

export default function (pi: ExtensionAPI) {
	let askUserQuestionCancelled = false;
	const statusKey = parseStatusKey();
	let cmuxMissing = false;
	let currentStatus: string | undefined;

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

	const setStatus = async (value: string): Promise<void> => {
		if (currentStatus === value) return;
		const ok = await runCmux(["set-status", statusKey, value]);
		if (ok) {
			currentStatus = value;
		}
	};

	const clearStatus = async (): Promise<void> => {
		if (!currentStatus) return;
		const ok = await runCmux(["clear-status", statusKey]);
		if (ok) {
			currentStatus = undefined;
		}
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
		askUserQuestionCancelled = false;
		await clearStatus();
	});

	pi.on("session_switch", async (_event: SessionSwitchEvent) => {
		askUserQuestionCancelled = false;
		await clearStatus();
	});

	pi.on("agent_start", async (_event: AgentStartEvent) => {
		askUserQuestionCancelled = false;
		await setStatus("running");
	});

	pi.on("tool_call", async (event: ToolCallEvent, _ctx: ExtensionContext) => {
		if (event.toolName === "AskUserQuestion") {
			await setStatus("waiting-input");
		}
	});

	pi.on("tool_result", async (event: ToolResultEvent, _ctx: ExtensionContext) => {
		if (!isAskUserQuestionCancelled(event)) return;
		askUserQuestionCancelled = true;
		await setStatus("failed");
	});

	pi.on("agent_end", async (event: AgentEndEvent, _ctx: ExtensionContext) => {
		const stopReason = getStopReason(event.messages);
		if (stopReason === "error" || askUserQuestionCancelled) {
			await setStatus("failed");
			return;
		}
		await setStatus("complete");
	});
}
