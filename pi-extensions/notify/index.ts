/**
 * Desktop Notification Extension
 *
 * Sends OSC 777 desktop notifications when the agent finishes and updates the terminal title.
 * Title format: "pi <cwd> <status>"
 */

import { basename } from "node:path";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const notify = (title: string, body: string): void => {
	process.stdout.write(`\x1b]777;notify;${title};${body}\x07`);
};

const isTextPart = (part: unknown): part is { type: "text"; text: string } =>
	Boolean(part && typeof part === "object" && "type" in part && part.type === "text" && "text" in part);

const extractLastAssistantText = (messages: Array<{ role?: string; content?: unknown }>): string | null => {
	for (let i = messages.length - 1; i >= 0; i--) {
		const message = messages[i];
		if (message?.role !== "assistant") {
			continue;
		}

		if (typeof message.content === "string") {
			return message.content.trim() || null;
		}

		if (Array.isArray(message.content)) {
			const text = message.content.filter(isTextPart).map((part) => part.text).join("\n").trim();
			return text || null;
		}

		return null;
	}

	return null;
};

const formatNotification = (text: string | null): { title: string; body: string } => {
	const normalized = (text ?? "").replace(/\s+/g, " ").trim();
	if (!normalized) {
		return { title: "Ready for input", body: "" };
	}

	const maxBody = 200;
	return {
		title: "π",
		body: normalized.length > maxBody ? `${normalized.slice(0, maxBody - 1)}…` : normalized,
	};
};

const setStateTitle = (
	ctx: { hasUI: boolean; cwd: string; ui: { setTitle: (title: string) => void } },
	state: "waiting" | "working",
): void => {
	if (!ctx.hasUI) {
		return;
	}
	const cwdLabel = basename(ctx.cwd) || ctx.cwd;
	const symbol = state === "waiting" ? "⏸" : "▶";
	ctx.ui.setTitle(`pi ${cwdLabel} ${symbol}`);
};

export default function (pi: ExtensionAPI) {
	pi.on("session_start", async (_event, ctx) => {
		setStateTitle(ctx, "waiting");
	});

	pi.on("agent_start", async (_event, ctx) => {
		setStateTitle(ctx, "working");
	});

	pi.on("agent_end", async (event, ctx) => {
		setStateTitle(ctx, "waiting");
		const lastText = extractLastAssistantText(event.messages ?? []);
		const { title, body } = formatNotification(lastText);
		notify(title, body);
	});
}
