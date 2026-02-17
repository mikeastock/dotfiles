/**
 * Desktop Notification Extension
 *
 * Sends desktop notifications when the agent finishes and updates the terminal title
 * with a per-pane state summary for panes that share the same tab label.
 *
 * Tab label: PI_NOTIFY_TAB_BASE or basename(cwd)
 * Pane label: ZMX_SESSION or pid
 *
 * Supported terminals for notifications via OSC 777: Ghostty, iTerm2, WezTerm, rxvt-unicode
 * Not supported: Kitty (uses OSC 99), Terminal.app, Windows Terminal, Alacritty
 */

import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { mkdir, readFile, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Markdown, type MarkdownTheme } from "@mariozechner/pi-tui";

/**
 * Send a desktop notification via OSC 777 escape sequence.
 */
const notify = (title: string, body: string): void => {
	// OSC 777 format: ESC ] 777 ; notify ; title ; body BEL
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

		const content = message.content;
		if (typeof content === "string") {
			return content.trim() || null;
		}

		if (Array.isArray(content)) {
			const text = content.filter(isTextPart).map((part) => part.text).join("\n").trim();
			return text || null;
		}

		return null;
	}

	return null;
};

const plainMarkdownTheme: MarkdownTheme = {
	heading: (text) => text,
	link: (text) => text,
	linkUrl: () => "",
	code: (text) => text,
	codeBlock: (text) => text,
	codeBlockBorder: () => "",
	quote: (text) => text,
	quoteBorder: () => "",
	hr: () => "",
	listBullet: () => "",
	bold: (text) => text,
	italic: (text) => text,
	strikethrough: (text) => text,
	underline: (text) => text,
};

const simpleMarkdown = (text: string, width = 80): string => {
	const markdown = new Markdown(text, 0, 0, plainMarkdownTheme);
	return markdown.render(width).join("\n");
};

const formatNotification = (text: string | null): { title: string; body: string } => {
	const simplified = text ? simpleMarkdown(text) : "";
	const normalized = simplified.replace(/\s+/g, " ").trim();
	if (!normalized) {
		return { title: "Ready for input", body: "" };
	}

	const maxBody = 200;
	const body = normalized.length > maxBody ? `${normalized.slice(0, maxBody - 1)}…` : normalized;
	return { title: "π", body };
};

type AgentState = "waiting" | "working";

type StatusEntry = {
	pid: number;
	tab: string;
	pane: string;
	state: AgentState;
	updatedAt: number;
};

const STATUS_DIR = join(tmpdir(), "pi-notify-status");
const STALE_MS = 1000 * 60 * 60 * 12;

const sanitizeLabel = (value: string): string => value.replace(/[|/]/g, "-").trim();

const getTabLabel = (cwd: string): string => {
	const explicitBase = process.env.PI_NOTIFY_TAB_BASE?.trim();
	if (explicitBase) {
		return sanitizeLabel(explicitBase);
	}
	const cwdLabel = basename(cwd) || cwd;
	return sanitizeLabel(cwdLabel);
};

const getPaneLabel = (): string => {
	const zmxSession = process.env.ZMX_SESSION?.trim();
	if (zmxSession) {
		return sanitizeLabel(zmxSession);
	}
	return `pid:${process.pid}`;
};

const selfStatusPath = (): string => join(STATUS_DIR, `${process.pid}.json`);

const isProcessAlive = (pid: number): boolean => {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
};

const writeSelfStatus = async (tab: string, pane: string, state: AgentState): Promise<void> => {
	await mkdir(STATUS_DIR, { recursive: true });
	const entry: StatusEntry = {
		pid: process.pid,
		tab,
		pane,
		state,
		updatedAt: Date.now(),
	};

	const finalPath = selfStatusPath();
	const tempPath = `${finalPath}.tmp-${Date.now()}-${Math.random().toString(36).slice(2)}`;
	try {
		await writeFile(tempPath, `${JSON.stringify(entry)}\n`, "utf8");
		await rename(tempPath, finalPath);
	} catch (error) {
		await unlink(tempPath).catch(() => undefined);
		throw error;
	}
};

const removeSelfStatus = async (): Promise<void> => {
	await unlink(selfStatusPath()).catch(() => undefined);
};

const deleteIfOld = async (path: string, now: number): Promise<void> => {
	try {
		const info = await stat(path);
		if (now - info.mtimeMs > STALE_MS) {
			await unlink(path).catch(() => undefined);
		}
	} catch {
		// Ignore stat/unlink failures.
	}
};

const loadPaneStates = async (tab: string): Promise<Array<{ pane: string; state: AgentState; pid: number }>> => {
	await mkdir(STATUS_DIR, { recursive: true });
	const now = Date.now();
	const files = await readdir(STATUS_DIR);
	const states: Array<{ pane: string; state: AgentState; pid: number }> = [];

	for (const file of files) {
		if (!file.endsWith(".json")) {
			continue;
		}

		const path = join(STATUS_DIR, file);
		try {
			const raw = await readFile(path, "utf8");
			const entry = JSON.parse(raw) as Partial<StatusEntry>;
			if (
				typeof entry.pid !== "number" ||
				typeof entry.tab !== "string" ||
				typeof entry.pane !== "string" ||
				(entry.state !== "waiting" && entry.state !== "working")
			) {
				await deleteIfOld(path, now);
				continue;
			}
			if (!isProcessAlive(entry.pid)) {
				await unlink(path).catch(() => undefined);
				continue;
			}
			if (entry.tab !== tab) {
				continue;
			}
			states.push({ pane: entry.pane, state: entry.state, pid: entry.pid });
		} catch {
			await deleteIfOld(path, now);
		}
	}

	states.sort((a, b) => {
		if (a.pane === b.pane) {
			return a.pid - b.pid;
		}
		return a.pane.localeCompare(b.pane);
	});

	return states;
};

const setStateTitle = async (
	ctx: { hasUI: boolean; cwd: string; ui: { setTitle: (title: string) => void } },
	state: AgentState,
): Promise<void> => {
	const tab = getTabLabel(ctx.cwd);
	const pane = getPaneLabel();
	await writeSelfStatus(tab, pane, state);

	if (!ctx.hasUI) {
		return;
	}

	const states = await loadPaneStates(tab);
	const summary = states.map((entry) => `${entry.pane}:${entry.state === "waiting" ? "⏸" : "▶"}`).join("/");
	const current = `${pane}:${state === "waiting" ? "⏸" : "▶"}`;
	ctx.ui.setTitle(`${tab} | ${summary || current}`);
};

const notificationTitle = (title: string): string => {
	const zmxSession = process.env.ZMX_SESSION?.trim();
	if (!zmxSession) {
		return title;
	}
	return `${title} ${zmxSession}`;
};

export default function (pi: ExtensionAPI) {
	pi.on("session_start", async (_event, ctx) => {
		await setStateTitle(ctx, "waiting");
	});

	pi.on("agent_start", async (_event, ctx) => {
		await setStateTitle(ctx, "working");
	});

	pi.on("agent_end", async (event, ctx) => {
		await setStateTitle(ctx, "waiting");

		const lastText = extractLastAssistantText(event.messages ?? []);
		const { title, body } = formatNotification(lastText);
		notify(notificationTitle(title), body);
	});

	pi.on("session_shutdown", async () => {
		await removeSelfStatus();
	});
}
