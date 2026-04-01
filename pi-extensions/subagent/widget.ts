/**
 * Status widget for async subagent runs.
 * Adapted from HazAT's pi-interactive-subagents.
 */

import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { truncateToWidth, visibleWidth } from "@mariozechner/pi-tui";
import type { SubagentAgentSource } from "./events.js";

export interface AsyncRun {
	id: string;
	agent: string;
	agentSource: SubagentAgentSource;
	task: string;
	startedAt: number;
	pane: string;
	sessionFile: string;
	tempFiles: string[];
	batchId?: string;
	windowId?: string;
}

const ACCENT = "\x1b[38;2;77;163;255m";
const RST = "\x1b[0m";

function formatElapsedMMSS(startTime: number): string {
	const seconds = Math.floor((Date.now() - startTime) / 1000);
	const m = Math.floor(seconds / 60);
	const s = seconds % 60;
	return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/**
 * Build a bordered content line: │left          right│
 */
function borderLine(left: string, right: string, width: number): string {
	const contentWidth = Math.max(0, width - 2);
	const rightVis = visibleWidth(right);
	const maxLeft = Math.max(0, contentWidth - rightVis);
	const truncLeft = truncateToWidth(left, maxLeft);
	const leftVis = visibleWidth(truncLeft);
	const pad = Math.max(0, contentWidth - leftVis - rightVis);
	return `${ACCENT}│${RST}${truncLeft}${" ".repeat(pad)}${right}${ACCENT}│${RST}`;
}

/**
 * Build the bordered top line: ╭─ Title ──── info ─╮
 */
function borderTop(title: string, info: string, width: number): string {
	const inner = Math.max(0, width - 2);
	const titlePart = `─ ${title} `;
	const infoPart = ` ${info} ─`;
	const fillLen = Math.max(0, inner - titlePart.length - infoPart.length);
	const fill = "─".repeat(fillLen);
	const content = `${titlePart}${fill}${infoPart}`.slice(0, inner).padEnd(inner, "─");
	return `${ACCENT}╭${content}╮${RST}`;
}

/**
 * Build the bordered bottom line: ╰──────────────────╯
 */
function borderBottom(width: number): string {
	const inner = Math.max(0, width - 2);
	return `${ACCENT}╰${"─".repeat(inner)}╯${RST}`;
}

let widgetInterval: ReturnType<typeof setInterval> | null = null;

export function updateWidget(ctx: ExtensionContext | null, runs: Map<string, AsyncRun>): void {
	if (!ctx?.hasUI) return;

	if (runs.size === 0) {
		ctx.ui.setWidget("subagent-status", undefined);
		if (widgetInterval) {
			clearInterval(widgetInterval);
			widgetInterval = null;
		}
		return;
	}

	ctx.ui.setWidget(
		"subagent-status",
		(_tui: any, _theme: any) => {
			return {
				invalidate() {},
				render(width: number) {
					const count = runs.size;
					const title = "Subagents";
					const info = `${count} running`;

					const lines: string[] = [borderTop(title, info, width)];

					for (const [_id, run] of runs) {
						const elapsed = formatElapsedMMSS(run.startedAt);
						const taskPreview =
							run.task.length > 40 ? run.task.slice(0, 40) + "…" : run.task;
						const left = ` ${elapsed}  ${run.agent} `;
						const right = ` "${taskPreview}" `;
						lines.push(borderLine(left, right, width));
					}

					lines.push(borderBottom(width));
					return lines;
				},
			};
		},
		{ placement: "aboveEditor" },
	);
}

export function startWidgetRefresh(ctx: ExtensionContext | null, runs: Map<string, AsyncRun>): void {
	if (widgetInterval) return;
	updateWidget(ctx, runs);
	widgetInterval = setInterval(() => {
		if (runs.size > 0) updateWidget(ctx, runs);
	}, 1000);
}

export function stopWidgetRefresh(): void {
	if (widgetInterval) {
		clearInterval(widgetInterval);
		widgetInterval = null;
	}
}
