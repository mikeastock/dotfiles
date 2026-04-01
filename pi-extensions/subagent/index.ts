/**
 * Subagent Tool - Delegate tasks to specialized agents
 *
 * Spawns a separate `pi` process for each subagent invocation,
 * giving it an isolated context window.
 *
 * Supports three modes:
 *   - Single: { agent: "name", task: "..." }
 *   - Parallel: { tasks: [{ agent: "name", task: "..." }, ...] }
 *   - Chain: { chain: [{ agent: "name", task: "... {previous} ..." }, ...] }
 *
 * Uses JSON mode to capture structured output from subagents.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Message } from "@mariozechner/pi-ai";
import { StringEnum } from "@mariozechner/pi-ai";
import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { type ExtensionAPI, getMarkdownTheme } from "@mariozechner/pi-coding-agent";
import { Container, Markdown, Spacer, Text } from "@mariozechner/pi-tui";
import { Type } from "@sinclair/typebox";
import { type AgentConfig, type AgentScope, discoverAgents } from "./agents.js";
import { getSavedScopedModelIds, resolveModelOverride } from "./model-selection.js";
import {
	isTmuxAvailable,
	createPaneInWindow,
	createPaneWithCommand,
	createWindow,
	closePane,
	closeWindow,
	getWindowPanes,
	makeBatchWindowName,
	pollForExit,
	runCommandInPane,
	shellEscape,
	tileWindow,
} from "./tmux.js";
import {
	SUBAGENT_RUN_END_EVENT,
	SUBAGENT_RUN_START_EVENT,
	buildSubagentRunEndEvent,
	buildSubagentRunStartEvent,
} from "./events.js";
import type { SubagentAgentSource } from "./events.js";
import { type AsyncRun, updateWidget, startWidgetRefresh, stopWidgetRefresh } from "./widget.js";

const BUNDLED_AGENTS_DIR = path.join(import.meta.dirname, "agents");

function readLastAssistantMessage(sessionFile: string): string {
	try {
		const raw = fs.readFileSync(sessionFile, "utf8");
		const lines = raw.split("\n").filter((l) => l.trim());
		for (let i = lines.length - 1; i >= 0; i--) {
			try {
				const entry = JSON.parse(lines[i]);
				if (entry.type === "message" && entry.message?.role === "assistant") {
					for (const part of entry.message.content) {
						if (part.type === "text") return part.text;
					}
				}
			} catch {}
		}
	} catch {}
	return "(no output)";
}

function resolveSkillPath(skillName: string, cwd: string): string | null {
	const candidates = [
		path.join(cwd, ".pi", "skills", skillName, "SKILL.md"),
		path.join(os.homedir(), ".pi", "agent", "skills", skillName, "SKILL.md"),
	];
	for (const p of candidates) {
		if (fs.existsSync(p)) return p;
	}
	return null;
}
const MAX_PARALLEL_TASKS = 8;
const MAX_CONCURRENCY = 4;
const SPAWN_STAGGER_MS = 2000;
const COLLAPSED_ITEM_COUNT = 10;

function emitSubagentRunStart(
	pi: ExtensionAPI,
	event: Parameters<typeof buildSubagentRunStartEvent>[0],
): void {
	pi.events.emit(SUBAGENT_RUN_START_EVENT, buildSubagentRunStartEvent(event));
}

function emitSubagentRunEnd(
	pi: ExtensionAPI,
	event: Parameters<typeof buildSubagentRunEndEvent>[0],
): void {
	pi.events.emit(SUBAGENT_RUN_END_EVENT, buildSubagentRunEndEvent(event));
}

function getSubagentRunStatus(result: {
	exitCode: number;
	stopReason?: string;
	errorMessage?: string;
}): "completed" | "failed" {
	if (result.exitCode !== 0) return "failed";
	if (result.stopReason === "error" || result.stopReason === "aborted") return "failed";
	if (result.errorMessage) return "failed";
	return "completed";
}

function formatTokens(count: number): string {
	if (count < 1000) return count.toString();
	if (count < 10000) return `${(count / 1000).toFixed(1)}k`;
	if (count < 1000000) return `${Math.round(count / 1000)}k`;
	return `${(count / 1000000).toFixed(1)}M`;
}

function formatUsageStats(
	usage: {
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
		cost: number;
		contextTokens?: number;
		turns?: number;
	},
	model?: string,
): string {
	const parts: string[] = [];
	if (usage.turns) parts.push(`${usage.turns} turn${usage.turns > 1 ? "s" : ""}`);
	if (usage.input) parts.push(`↑${formatTokens(usage.input)}`);
	if (usage.output) parts.push(`↓${formatTokens(usage.output)}`);
	if (usage.cacheRead) parts.push(`R${formatTokens(usage.cacheRead)}`);
	if (usage.cacheWrite) parts.push(`W${formatTokens(usage.cacheWrite)}`);
	if (usage.cost) parts.push(`$${usage.cost.toFixed(4)}`);
	if (usage.contextTokens && usage.contextTokens > 0) {
		parts.push(`ctx:${formatTokens(usage.contextTokens)}`);
	}
	if (model) parts.push(model);
	return parts.join(" ");
}

function formatToolCall(
	toolName: string,
	args: Record<string, unknown>,
	themeFg: (color: any, text: string) => string,
): string {
	const shortenPath = (p: string) => {
		const home = os.homedir();
		return p.startsWith(home) ? `~${p.slice(home.length)}` : p;
	};

	switch (toolName) {
		case "bash": {
			const command = (args.command as string) || "...";
			const preview = command.length > 60 ? `${command.slice(0, 60)}...` : command;
			return themeFg("muted", "$ ") + themeFg("toolOutput", preview);
		}
		case "read": {
			const rawPath = (args.file_path || args.path || "...") as string;
			const filePath = shortenPath(rawPath);
			const offset = args.offset as number | undefined;
			const limit = args.limit as number | undefined;
			let text = themeFg("accent", filePath);
			if (offset !== undefined || limit !== undefined) {
				const startLine = offset ?? 1;
				const endLine = limit !== undefined ? startLine + limit - 1 : "";
				text += themeFg("warning", `:${startLine}${endLine ? `-${endLine}` : ""}`);
			}
			return themeFg("muted", "read ") + text;
		}
		case "write": {
			const rawPath = (args.file_path || args.path || "...") as string;
			const filePath = shortenPath(rawPath);
			const content = (args.content || "") as string;
			const lines = content.split("\n").length;
			let text = themeFg("muted", "write ") + themeFg("accent", filePath);
			if (lines > 1) text += themeFg("dim", ` (${lines} lines)`);
			return text;
		}
		case "edit": {
			const rawPath = (args.file_path || args.path || "...") as string;
			return themeFg("muted", "edit ") + themeFg("accent", shortenPath(rawPath));
		}
		case "ls": {
			const rawPath = (args.path || ".") as string;
			return themeFg("muted", "ls ") + themeFg("accent", shortenPath(rawPath));
		}
		case "find": {
			const pattern = (args.pattern || "*") as string;
			const rawPath = (args.path || ".") as string;
			return themeFg("muted", "find ") + themeFg("accent", pattern) + themeFg("dim", ` in ${shortenPath(rawPath)}`);
		}
		case "grep": {
			const pattern = (args.pattern || "") as string;
			const rawPath = (args.path || ".") as string;
			return (
				themeFg("muted", "grep ") +
				themeFg("accent", `/${pattern}/`) +
				themeFg("dim", ` in ${shortenPath(rawPath)}`)
			);
		}
		default: {
			const argsStr = JSON.stringify(args);
			const preview = argsStr.length > 50 ? `${argsStr.slice(0, 50)}...` : argsStr;
			return themeFg("accent", toolName) + themeFg("dim", ` ${preview}`);
		}
	}
}

interface UsageStats {
	input: number;
	output: number;
	cacheRead: number;
	cacheWrite: number;
	cost: number;
	contextTokens: number;
	turns: number;
}

interface SingleResult {
	agent: string;
	agentSource: SubagentAgentSource;
	task: string;
	exitCode: number;
	messages: Message[];
	stderr: string;
	usage: UsageStats;
	model?: string;
	stopReason?: string;
	errorMessage?: string;
	step?: number;
}

interface SubagentDetails {
	mode: "single" | "parallel" | "chain";
	agentScope: AgentScope;
	projectAgentsDir: string | null;
	results: SingleResult[];
}

interface AsyncBatch {
	id: string;
	windowId: string;
	windowName: string;
	paneIds: string[];
	pendingRunIds: Set<string>;
}

function getFinalOutput(messages: Message[]): string {
	for (let i = messages.length - 1; i >= 0; i--) {
		const msg = messages[i];
		if (msg.role === "assistant") {
			for (const part of msg.content) {
				if (part.type === "text") return part.text;
			}
		}
	}
	return "";
}

type DisplayItem = { type: "text"; text: string } | { type: "toolCall"; name: string; args: Record<string, any> };

function getDisplayItems(messages: Message[]): DisplayItem[] {
	const items: DisplayItem[] = [];
	for (const msg of messages) {
		if (msg.role === "assistant") {
			for (const part of msg.content) {
				if (part.type === "text") items.push({ type: "text", text: part.text });
				else if (part.type === "toolCall") items.push({ type: "toolCall", name: part.name, args: part.arguments });
			}
		}
	}
	return items;
}

async function mapWithConcurrencyLimit<TIn, TOut>(
	items: TIn[],
	concurrency: number,
	fn: (item: TIn, index: number) => Promise<TOut>,
): Promise<TOut[]> {
	if (items.length === 0) return [];
	const limit = Math.max(1, Math.min(concurrency, items.length));
	const results: TOut[] = new Array(items.length);
	let nextIndex = 0;
	const workers = new Array(limit).fill(null).map(async () => {
		while (true) {
			const current = nextIndex++;
			if (current >= items.length) return;
			results[current] = await fn(items[current], current);
		}
	});
	await Promise.all(workers);
	return results;
}

function writePromptToTempFile(agentName: string, prompt: string): { dir: string; filePath: string } {
	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-subagent-"));
	const safeName = agentName.replace(/[^\w.-]+/g, "_");
	const filePath = path.join(tmpDir, `prompt-${safeName}.md`);
	fs.writeFileSync(filePath, prompt, { encoding: "utf-8", mode: 0o600 });
	return { dir: tmpDir, filePath };
}

type OnUpdatePayload = {
	content: Array<{ type: "text"; text: string }>;
	details: SubagentDetails;
	isError?: boolean;
};

type OnUpdateCallback = (partial: OnUpdatePayload) => void;

function buildAsyncPiCommand(
	agent: AgentConfig,
	task: string,
	defaultCwd: string,
	cwd: string | undefined,
	thinking: string | undefined,
	model: string | undefined,
	sessionFile: string,
	tempFiles: string[],
): string {
	const args: string[] = ["--session", sessionFile];
	if (model) args.push("--model", model);
	if (agent.tools && agent.tools.length > 0) args.push("--tools", agent.tools.join(","));

	const effectiveThinking = thinking ?? agent.thinking;
	if (effectiveThinking) args.push("--thinking", effectiveThinking);

	if (agent.skills && agent.skills.length > 0) {
		for (const skillName of agent.skills) {
			const skillPath = resolveSkillPath(skillName, defaultCwd);
			if (skillPath) args.push("--skill", skillPath);
		}
	}

	const autoExitPath = path.join(import.meta.dirname, "auto-exit.ts");
	if (agent.spawning === false) {
		args.push("--no-extensions", "-e", autoExitPath);
	} else {
		args.push("-e", autoExitPath);
	}

	if (agent.systemPrompt.trim()) {
		const tmp = writePromptToTempFile(agent.name, agent.systemPrompt);
		args.push("--append-system-prompt", tmp.filePath);
		tempFiles.push(tmp.filePath);
		tempFiles.push(tmp.dir);
	}

	args.push(`Task: ${task}`);

	const effectiveCwd = cwd ??
		(agent.cwd ? (path.isAbsolute(agent.cwd) ? agent.cwd : path.resolve(defaultCwd, agent.cwd)) : defaultCwd);
	return `cd ${shellEscape(effectiveCwd)} && pi ${args.map(shellEscape).join(" ")}; echo '__SUBAGENT_DONE_'$?'__'`;
}

function cleanupAsyncTempFiles(tempFiles: string[]): void {
	for (const f of tempFiles) {
		try { fs.unlinkSync(f); } catch {}
	}
}

function finishBatchRun(asyncBatches: Map<string, AsyncBatch>, run: AsyncRun): void {
	if (!run.batchId) return;
	const batch = asyncBatches.get(run.batchId);
	if (!batch) return;

	batch.pendingRunIds.delete(run.id);
	if (batch.pendingRunIds.size === 0) {
		closeWindow(batch.windowId);
		asyncBatches.delete(batch.id);
	}
}

function watchAsyncRun(
	pi: ExtensionAPI,
	asyncRuns: Map<string, AsyncRun>,
	asyncBatches: Map<string, AsyncBatch>,
	latestCtx: ExtensionContext | null,
	run: AsyncRun,
): void {
	const watcherAbort = new AbortController();
	pollForExit(run.pane, watcherAbort.signal, {
		interval: 1000,
		onTick: () => updateWidget(latestCtx, asyncRuns),
	})
		.then((exitCode) => {
			const summary = readLastAssistantMessage(run.sessionFile);

			emitSubagentRunEnd(pi, {
				id: run.id,
				agent: run.agent,
				agentSource: run.agentSource,
				task: run.task,
				execution: "async",
				startedAt: run.startedAt,
				finishedAt: Date.now(),
				status: exitCode === 0 ? "completed" : "failed",
				exitCode,
				batchId: run.batchId,
			});

			asyncRuns.delete(run.id);
			updateWidget(latestCtx, asyncRuns);

			if (run.batchId) finishBatchRun(asyncBatches, run);
			else closePane(run.pane);

			cleanupAsyncTempFiles(run.tempFiles);

			const status = exitCode === 0 ? "completed" : `failed (exit ${exitCode})`;
			pi.sendMessage(
				{
					customType: "subagent_result",
					content: `Async subagent "${run.agent}" ${status} (run: ${run.id}).\n\n${summary}`,
					display: true,
					details: { runId: run.id, agent: run.agent, task: run.task, exitCode },
				},
				{ triggerTurn: true, deliverAs: "steer" },
			);

			pi.events.emit("notify", {
				title: `Subagent done: ${run.agent}`,
				body: exitCode === 0 ? "Completed" : "Failed",
			});
		})
		.catch(() => {
			emitSubagentRunEnd(pi, {
				id: run.id,
				agent: run.agent,
				agentSource: run.agentSource,
				task: run.task,
				execution: "async",
				startedAt: run.startedAt,
				finishedAt: Date.now(),
				status: "failed",
				exitCode: 1,
				errorMessage: "Async subagent watcher failed",
				batchId: run.batchId,
			});
			asyncRuns.delete(run.id);
			updateWidget(latestCtx, asyncRuns);
			if (run.batchId) finishBatchRun(asyncBatches, run);
			else {
				try { closePane(run.pane); } catch {}
			}
			cleanupAsyncTempFiles(run.tempFiles);
		});
}

function runSingleAsyncAgent(
	pi: ExtensionAPI,
	asyncRuns: Map<string, AsyncRun>,
	asyncBatches: Map<string, AsyncBatch>,
	latestCtx: ExtensionContext | null,
	defaultCwd: string,
	agent: AgentConfig,
	task: string,
	cwd: string | undefined,
	thinking: string | undefined,
	model: string | undefined,
): { runId: string } {
	const runId = crypto.randomUUID().slice(0, 8);
	const sessionFile = path.join(os.tmpdir(), `pi-subagent-${runId}.jsonl`);
	const tempFiles = [sessionFile];
	const command = buildAsyncPiCommand(agent, task, defaultCwd, cwd, thinking, model, sessionFile, tempFiles);
	const pane = createPaneWithCommand(`${agent.name}: ${task.slice(0, 30)}`, command);

	const run: AsyncRun = {
		id: runId,
		agent: agent.name,
		agentSource: agent.source,
		task,
		startedAt: Date.now(),
		pane,
		sessionFile,
		tempFiles,
	};
	asyncRuns.set(runId, run);
	emitSubagentRunStart(pi, {
		id: run.id,
		agent: run.agent,
		agentSource: run.agentSource,
		task: run.task,
		execution: "async",
		startedAt: run.startedAt,
	});
	startWidgetRefresh(latestCtx, asyncRuns);
	watchAsyncRun(pi, asyncRuns, asyncBatches, latestCtx, run);

	return { runId };
}

function runParallelAsyncBatch(
	pi: ExtensionAPI,
	asyncRuns: Map<string, AsyncRun>,
	asyncBatches: Map<string, AsyncBatch>,
	latestCtx: ExtensionContext | null,
	defaultCwd: string,
	tasks: Array<{ agent: AgentConfig; task: string; cwd?: string }>,
	thinking: string | undefined,
	modelOverride: string | undefined,
): { batchId: string; runIds: string[]; windowName: string } {
	const batchId = crypto.randomUUID().slice(0, 8);
	const windowName = makeBatchWindowName(batchId);
	const windowId = createWindow(windowName);
	const initialPane = getWindowPanes(windowId)[0];
	const paneIds: string[] = initialPane ? [initialPane] : [];
	const runIds: string[] = [];

	for (let i = 0; i < tasks.length; i++) {
		const t = tasks[i];
		const runId = crypto.randomUUID().slice(0, 8);
		const sessionFile = path.join(os.tmpdir(), `pi-subagent-${runId}.jsonl`);
		const tempFiles = [sessionFile];
		const command = buildAsyncPiCommand(
			t.agent,
			t.task,
			defaultCwd,
			t.cwd,
			thinking,
			modelOverride ?? t.agent.model,
			sessionFile,
			tempFiles,
		);
		const name = `${t.agent.name}: ${t.task.slice(0, 30)}`;
		let pane: string;
		if (i === 0 && initialPane) {
			runCommandInPane(initialPane, name, command);
			pane = initialPane;
		} else {
			pane = createPaneInWindow(windowId, name, command);
			paneIds.push(pane);
		}

		const run: AsyncRun = {
			id: runId,
			agent: t.agent.name,
			agentSource: t.agent.source,
			task: t.task,
			startedAt: Date.now(),
			pane,
			sessionFile,
			tempFiles,
			batchId,
			windowId,
		};
		asyncRuns.set(runId, run);
		emitSubagentRunStart(pi, {
			id: run.id,
			agent: run.agent,
			agentSource: run.agentSource,
			task: run.task,
			execution: "async",
			startedAt: run.startedAt,
			batchId: run.batchId,
		});
		runIds.push(runId);
	}

	tileWindow(windowId);
	asyncBatches.set(batchId, {
		id: batchId,
		windowId,
		windowName,
		paneIds,
		pendingRunIds: new Set(runIds),
	});

	for (const runId of runIds) {
		const run = asyncRuns.get(runId);
		if (run) watchAsyncRun(pi, asyncRuns, asyncBatches, latestCtx, run);
	}
	startWidgetRefresh(latestCtx, asyncRuns);
	return { batchId, runIds, windowName };
}

async function runSingleAgent(
	pi: ExtensionAPI,
	defaultCwd: string,
	agents: AgentConfig[],
	agentName: string,
	task: string,
	cwd: string | undefined,
	thinking: string | undefined,
	model: string | undefined,
	step: number | undefined,
	signal: AbortSignal | undefined,
	onUpdate: OnUpdateCallback | undefined,
	makeDetails: (results: SingleResult[]) => SubagentDetails,
): Promise<SingleResult> {
	const agent = agents.find((a) => a.name === agentName);

	if (!agent) {
		const available = agents.map((a) => `"${a.name}"`).join(", ") || "none";
		return {
			agent: agentName,
			agentSource: "unknown",
			task,
			exitCode: 1,
			messages: [],
			stderr: `Unknown agent: "${agentName}". Available agents: ${available}.`,
			usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, contextTokens: 0, turns: 0 },
			step,
		};
	}

	const runId = crypto.randomUUID().slice(0, 8);
	const startedAt = Date.now();
	emitSubagentRunStart(pi, {
		id: runId,
		agent: agentName,
		agentSource: agent.source,
		task,
		execution: "sync",
		startedAt,
	});

	const args: string[] = ["--mode", "json", "-p", "--no-session"];
	if (model) args.push("--model", model);
	if (agent.tools && agent.tools.length > 0) args.push("--tools", agent.tools.join(","));

	// Thinking: tool param → agent frontmatter → none
	const effectiveThinking = thinking ?? agent.thinking;
	if (effectiveThinking) args.push("--thinking", effectiveThinking);

	// Skills: resolve skill names to paths, pass --skill for each
	if (agent.skills && agent.skills.length > 0) {
		for (const skillName of agent.skills) {
			const skillPath = resolveSkillPath(skillName, defaultCwd);
			if (skillPath) args.push("--skill", skillPath);
		}
	}

	// Spawning: exclude all extensions from child process
	if (agent.spawning === false) {
		args.push("--no-extensions");
	}

	let tmpPromptDir: string | null = null;
	let tmpPromptPath: string | null = null;

	const currentResult: SingleResult = {
		agent: agentName,
		agentSource: agent.source,
		task,
		exitCode: 0,
		messages: [],
		stderr: "",
		usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, contextTokens: 0, turns: 0 },
		model,
		step,
	};

	const emitUpdate = () => {
		if (onUpdate) {
			onUpdate({
				content: [{ type: "text", text: getFinalOutput(currentResult.messages) || "(running...)" }],
				details: makeDetails([currentResult]),
			});
		}
	};

	try {
		if (agent.systemPrompt.trim()) {
			const tmp = writePromptToTempFile(agent.name, agent.systemPrompt);
			tmpPromptDir = tmp.dir;
			tmpPromptPath = tmp.filePath;
			args.push("--append-system-prompt", tmpPromptPath);
		}

		args.push(`Task: ${task}`);
		let wasAborted = false;

		const exitCode = await new Promise<number>((resolve) => {
			// Cwd: tool param → agent frontmatter → parent session cwd
			let effectiveCwd = cwd ?? (agent.cwd ? (path.isAbsolute(agent.cwd) ? agent.cwd : path.resolve(defaultCwd, agent.cwd)) : defaultCwd);
			const proc = spawn("pi", args, { cwd: effectiveCwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
			let buffer = "";

			const processLine = (line: string) => {
				if (!line.trim()) return;
				let event: any;
				try {
					event = JSON.parse(line);
				} catch {
					return;
				}

				if (event.type === "message_end" && event.message) {
					const msg = event.message as Message;
					currentResult.messages.push(msg);

					if (msg.role === "assistant") {
						currentResult.usage.turns++;
						const usage = msg.usage;
						if (usage) {
							currentResult.usage.input += usage.input || 0;
							currentResult.usage.output += usage.output || 0;
							currentResult.usage.cacheRead += usage.cacheRead || 0;
							currentResult.usage.cacheWrite += usage.cacheWrite || 0;
							currentResult.usage.cost += usage.cost?.total || 0;
							currentResult.usage.contextTokens = usage.totalTokens || 0;
						}
						if (!currentResult.model && msg.model) currentResult.model = msg.model;
						if (msg.stopReason) currentResult.stopReason = msg.stopReason;
						if (msg.errorMessage) currentResult.errorMessage = msg.errorMessage;
					}
					emitUpdate();
				}

				if (event.type === "tool_result_end" && event.message) {
					currentResult.messages.push(event.message as Message);
					emitUpdate();
				}
			};

			proc.stdout.on("data", (data) => {
				buffer += data.toString();
				const lines = buffer.split("\n");
				buffer = lines.pop() || "";
				for (const line of lines) processLine(line);
			});

			proc.stderr.on("data", (data) => {
				currentResult.stderr += data.toString();
			});

			proc.on("close", (code) => {
				if (buffer.trim()) processLine(buffer);
				resolve(code ?? 0);
			});

			proc.on("error", () => {
				resolve(1);
			});

			if (signal) {
				const killProc = () => {
					wasAborted = true;
					proc.kill("SIGTERM");
					setTimeout(() => {
						if (!proc.killed) proc.kill("SIGKILL");
					}, 5000);
				};
				if (signal.aborted) killProc();
				else signal.addEventListener("abort", killProc, { once: true });
			}
		});

		currentResult.exitCode = exitCode;
		if (wasAborted) currentResult.errorMessage ??= "Subagent was aborted";
		emitSubagentRunEnd(pi, {
			id: runId,
			agent: agentName,
			agentSource: agent.source,
			task,
			execution: "sync",
			startedAt,
			finishedAt: Date.now(),
			status: getSubagentRunStatus(currentResult),
			exitCode: currentResult.exitCode,
			stopReason: currentResult.stopReason,
			errorMessage: currentResult.errorMessage,
		});
		if (wasAborted) throw new Error("Subagent was aborted");
		return currentResult;
	} finally {
		if (tmpPromptPath)
			try {
				fs.unlinkSync(tmpPromptPath);
			} catch {
				/* ignore */
			}
		if (tmpPromptDir)
			try {
				fs.rmdirSync(tmpPromptDir);
			} catch {
				/* ignore */
			}
	}
}

const TaskItem = Type.Object({
	agent: Type.String({ description: "Name of the agent to invoke" }),
	task: Type.String({ description: "Task to delegate to the agent" }),
	cwd: Type.Optional(Type.String({ description: "Working directory for the agent process" })),
});

const ChainItem = Type.Object({
	agent: Type.String({ description: "Name of the agent to invoke" }),
	task: Type.String({ description: "Task with optional {previous} placeholder for prior output" }),
	cwd: Type.Optional(Type.String({ description: "Working directory for the agent process" })),
});

const AgentScopeSchema = StringEnum(["user", "project", "both"] as const, {
	description: 'Which agent directories to use. Default: "user". Use "both" to include project-local agents.',
	default: "user",
});

const SubagentParams = Type.Object({
	agent: Type.Optional(Type.String({ description: "Name of the agent to invoke (for single mode)" })),
	task: Type.Optional(Type.String({ description: "Task to delegate (for single mode)" })),
	tasks: Type.Optional(Type.Array(TaskItem, { description: "Array of {agent, task} for parallel execution" })),
	chain: Type.Optional(Type.Array(ChainItem, { description: "Array of {agent, task} for sequential execution" })),
	agentScope: Type.Optional(AgentScopeSchema),
	confirmProjectAgents: Type.Optional(
		Type.Boolean({ description: "Prompt before running project-local agents. Default: true.", default: true }),
	),
	cwd: Type.Optional(Type.String({ description: "Working directory for the agent process (single mode)" })),
	thinking: Type.Optional(Type.String({
		description: "Override thinking level: off, minimal, low, medium, high, xhigh",
	})),
	model: Type.Optional(Type.String({
		description: "Override the agent frontmatter model. Must match one of the saved scoped models (enabledModels) in provider/model-id format, e.g. anthropic/claude-sonnet-4-6.",
	})),
	async: Type.Optional(Type.Boolean({
		description: "Run in background. Returns immediately, result steers back on completion. Requires tmux. Not supported for chains.",
		default: false,
	})),
});

export default function (pi: ExtensionAPI) {
	// Async run tracking
	const asyncRuns = new Map<string, AsyncRun>();
	const asyncBatches = new Map<string, AsyncBatch>();
	let latestCtx: ExtensionContext | null = null;

	pi.on("session_start", (_event: any, ctx: ExtensionContext) => {
		latestCtx = ctx;
	});

	pi.on("session_shutdown", () => {
		for (const batch of asyncBatches.values()) {
			try { closeWindow(batch.windowId); } catch {}
		}
		for (const run of asyncRuns.values()) {
			try { closePane(run.pane); } catch {}
		}
		stopWidgetRefresh();
		asyncRuns.clear();
		asyncBatches.clear();
		latestCtx = null;
	});

	// Shared agent registry — other extensions push agents here via subagent:register.
	// We also emit subagent:discover at execute time so late-loading extensions can respond.
	const externalAgents: AgentConfig[] = [];

	pi.events.on("subagent:register", (data: unknown) => {
		if (!Array.isArray(data)) return;
		for (const agent of data as AgentConfig[]) {
			const idx = externalAgents.findIndex((a) => a.name === agent.name);
			if (idx >= 0) externalAgents[idx] = agent;
			else externalAgents.push(agent);
		}
	});

	pi.registerTool({
		name: "subagent",
		label: "Subagent",
		description: [
			"Delegate tasks to specialized subagents with isolated context.",
			"Modes: single (agent + task), parallel (tasks array), chain (sequential with {previous} placeholder).",
			"Optional model parameter overrides the agent frontmatter model and is validated against saved scoped models from settings (enabledModels).",
			'Default agent scope is "user" (from ~/.pi/agent/agents).',
			'To enable project-local agents in .pi/agents, set agentScope: "both" (or "project").',
			"",
			"WHEN TO USE: Subagents are worth the overhead for tasks that require independent reasoning, analysis, or multi-step work (code review, planning, research, implementation).",
			"WHEN NOT TO USE: Do NOT use subagents just to read files in parallel. Reading files is fast and cheap — use the read tool directly. Spawning a subagent process for simple reads wastes time and tokens.",
			"",
			"ASYNC MODE: Pass async: true to run in tmux. Single async tasks open a temporary split beside the current pi pane. Parallel async tasks open a dedicated tmux window with one pane per task. Results steer back when done. Requires tmux. Not supported for chains.",
		].join(" "),
		parameters: SubagentParams,

		async execute(_toolCallId, params, signal, onUpdate, ctx) {
			const agentScope: AgentScope = params.agentScope ?? "user";
			// Give late-loading extensions a chance to register agents
			pi.events.emit("subagent:discover", {});
			const discovery = discoverAgents(ctx.cwd, agentScope, BUNDLED_AGENTS_DIR);
			// Merge external agents (lowest priority — discovered agents override)
			const agentMap = new Map<string, AgentConfig>();
			for (const agent of externalAgents) agentMap.set(agent.name, agent);
			for (const agent of discovery.agents) agentMap.set(agent.name, agent);
			const agents = Array.from(agentMap.values());
			const confirmProjectAgents = params.confirmProjectAgents ?? true;
			const scopedModelIds = getSavedScopedModelIds(ctx.cwd);
			const { model: selectedModel, error: modelError } = resolveModelOverride(
				scopedModelIds,
				params.model,
				undefined,
			);

			if (modelError) {
				return {
					content: [{ type: "text", text: modelError }],
					details: {
						mode: "single",
						agentScope,
						projectAgentsDir: discovery.projectAgentsDir,
						results: [],
					},
					isError: true,
				};
			}

			const hasChain = (params.chain?.length ?? 0) > 0;
			const hasTasks = (params.tasks?.length ?? 0) > 0;
			const hasSingle = Boolean(params.agent && params.task);
			const modeCount = Number(hasChain) + Number(hasTasks) + Number(hasSingle);

			const makeDetails =
				(mode: "single" | "parallel" | "chain") =>
				(results: SingleResult[]): SubagentDetails => ({
					mode,
					agentScope,
					projectAgentsDir: discovery.projectAgentsDir,
					results,
				});

			if (modeCount !== 1) {
				const available = agents.map((a) => `${a.name} (${a.source})`).join(", ") || "none";
				return {
					content: [
						{
							type: "text",
							text: `Invalid parameters. Provide exactly one mode.\nAvailable agents: ${available}`,
						},
					],
					details: makeDetails("single")([]),
				};
			}

			if ((agentScope === "project" || agentScope === "both") && confirmProjectAgents && ctx.hasUI) {
				const requestedAgentNames = new Set<string>();
				if (params.chain) for (const step of params.chain) requestedAgentNames.add(step.agent);
				if (params.tasks) for (const t of params.tasks) requestedAgentNames.add(t.agent);
				if (params.agent) requestedAgentNames.add(params.agent);

				const projectAgentsRequested = Array.from(requestedAgentNames)
					.map((name) => agents.find((a) => a.name === name))
					.filter((a): a is AgentConfig => a?.source === "project");

				if (projectAgentsRequested.length > 0) {
					const names = projectAgentsRequested.map((a) => a.name).join(", ");
					const dir = discovery.projectAgentsDir ?? "(unknown)";
					const ok = await ctx.ui.confirm(
						"Run project-local agents?",
						`Agents: ${names}\nSource: ${dir}\n\nProject agents are repo-controlled. Only continue for trusted repositories.`,
					);
					if (!ok)
						return {
							content: [{ type: "text", text: "Canceled: project-local agents not approved." }],
							details: makeDetails(hasChain ? "chain" : hasTasks ? "parallel" : "single")([]),
						};
				}
			}

			// Async mode — spawn into tmux panes, return immediately
			if (params.async) {
				if (!isTmuxAvailable()) {
					return {
						content: [{ type: "text", text: "async: true requires tmux. Start pi inside a tmux session." }],
						details: makeDetails("single")([]),
					};
				}

				if (hasChain) {
					return {
						content: [{ type: "text", text: "async: true is not supported for chains (steps depend on {previous})." }],
						details: makeDetails("chain")([]),
					};
				}

				if (hasSingle && params.agent && params.task) {
					const agent = agents.find((a) => a.name === params.agent);
					if (!agent) {
						return {
							content: [{ type: "text", text: `Unknown agent: "${params.agent}"` }],
							details: makeDetails("single")([]),
						};
					}
					const { runId } = runSingleAsyncAgent(
						pi,
						asyncRuns,
						asyncBatches,
						latestCtx,
						ctx.cwd,
						agent,
						params.task,
						params.cwd,
						params.thinking,
						selectedModel ?? agent.model,
					);
					return {
						content: [{ type: "text", text: `Started async subagent "${params.agent}" (run: ${runId})` }],
						details: makeDetails("single")([]),
					};
				}

				if (hasTasks && params.tasks) {
					const batchTasks: Array<{ agent: AgentConfig; task: string; cwd?: string }> = [];
					for (const t of params.tasks) {
						const agent = agents.find((a) => a.name === t.agent);
						if (!agent) {
							pi.sendMessage(
								{
									customType: "subagent_result",
									content: `Async subagent "${t.agent}" failed (invalid agent).\n\nUnknown agent: "${t.agent}"`,
									display: true,
									details: { runId: null, agent: t.agent, task: t.task, exitCode: 1 },
								},
								{ triggerTurn: true, deliverAs: "steer" },
							);
							continue;
						}
						batchTasks.push({ agent, task: t.task, cwd: t.cwd });
					}

					if (batchTasks.length === 0) {
						return {
							content: [{ type: "text", text: "No async subagents started." }],
							details: makeDetails("parallel")([]),
							isError: true,
						};
					}

					const { runIds, windowName } = runParallelAsyncBatch(
						pi,
						asyncRuns,
						asyncBatches,
						latestCtx,
						ctx.cwd,
						batchTasks,
						params.thinking,
						selectedModel,
					);
					return {
						content: [
							{ type: "text", text: `Started ${runIds.length} async subagents in tmux window "${windowName}"` },
						],
						details: makeDetails("parallel")([]),
					};
				}
			}

			if (params.chain && params.chain.length > 0) {
				const results: SingleResult[] = [];
				let previousOutput = "";

				for (let i = 0; i < params.chain.length; i++) {
					const step = params.chain[i];
					const taskWithContext = step.task.replace(/\{previous\}/g, previousOutput);

					// Create update callback that includes all previous results
					const chainUpdate: OnUpdateCallback | undefined = onUpdate
						? (partial) => {
								// Combine completed results with current streaming result
								const currentResult = partial.details?.results[0];
								if (currentResult) {
									const allResults = [...results, currentResult];
									onUpdate({
										content: partial.content,
										details: makeDetails("chain")(allResults),
									});
								}
							}
						: undefined;

					const result = await runSingleAgent(
						pi,
						ctx.cwd,
						agents,
						step.agent,
						taskWithContext,
						step.cwd,
						params.thinking,
						selectedModel ?? agents.find((a) => a.name === step.agent)?.model,
						i + 1,
						signal,
						chainUpdate,
						makeDetails("chain"),
					);
					results.push(result);

					const isError =
						result.exitCode !== 0 || result.stopReason === "error" || result.stopReason === "aborted";
					if (isError) {
						const errorMsg =
							result.errorMessage || result.stderr || getFinalOutput(result.messages) || "(no output)";
						return {
							content: [{ type: "text", text: `Chain stopped at step ${i + 1} (${step.agent}): ${errorMsg}` }],
							details: makeDetails("chain")(results),
							isError: true,
						};
					}
					previousOutput = getFinalOutput(result.messages);
				}
				return {
					content: [{ type: "text", text: getFinalOutput(results[results.length - 1].messages) || "(no output)" }],
					details: makeDetails("chain")(results),
				};
			}

			if (params.tasks && params.tasks.length > 0) {
				if (params.tasks.length > MAX_PARALLEL_TASKS)
					return {
						content: [
							{
								type: "text",
								text: `Too many parallel tasks (${params.tasks.length}). Max is ${MAX_PARALLEL_TASKS}.`,
							},
						],
						details: makeDetails("parallel")([]),
					};

				// Track all results for streaming updates
				const allResults: SingleResult[] = new Array(params.tasks.length);

				// Initialize placeholder results
				for (let i = 0; i < params.tasks.length; i++) {
					allResults[i] = {
						agent: params.tasks[i].agent,
						agentSource: "unknown",
						task: params.tasks[i].task,
						exitCode: -1, // -1 = still running
						messages: [],
						stderr: "",
						usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, contextTokens: 0, turns: 0 },
					};
				}

				const emitParallelUpdate = () => {
					if (onUpdate) {
						const running = allResults.filter((r) => r.exitCode === -1).length;
						const done = allResults.filter((r) => r.exitCode !== -1).length;
						onUpdate({
							content: [
								{ type: "text", text: `Parallel: ${done}/${allResults.length} done, ${running} running...` },
							],
							details: makeDetails("parallel")([...allResults]),
						});
					}
				};

				const results = await mapWithConcurrencyLimit(params.tasks, MAX_CONCURRENCY, async (t, index) => {
					// Stagger spawns to avoid pi settings file lock contention (proper-lockfile sync, no retries)
					if (index > 0) await new Promise((r) => setTimeout(r, index * SPAWN_STAGGER_MS));
					const result = await runSingleAgent(
						pi,
						ctx.cwd,
						agents,
						t.agent,
						t.task,
						t.cwd,
						params.thinking,
						selectedModel ?? agents.find((a) => a.name === t.agent)?.model,
						undefined,
						signal,
						// Per-task update callback
						(partial) => {
							if (partial.details?.results[0]) {
								allResults[index] = partial.details.results[0];
								emitParallelUpdate();
							}
						},
						makeDetails("parallel"),
					);
					allResults[index] = result;
					emitParallelUpdate();
					return result;
				});

				const successCount = results.filter((r) => r.exitCode === 0).length;
				const summaries = results.map((r) => {
					const output = getFinalOutput(r.messages);
					const status = r.exitCode === 0 ? "completed" : "failed";
					return `## [${r.agent}] ${status}\n\n${output || "(no output)"}`;
				});
				return {
					content: [
						{
							type: "text",
							text: `Parallel: ${successCount}/${results.length} succeeded\n\n${summaries.join("\n\n---\n\n")}`,
						},
					],
					details: makeDetails("parallel")(results),
				};
			}

			if (params.agent && params.task) {
				const result = await runSingleAgent(
					pi,
					ctx.cwd,
					agents,
					params.agent,
					params.task,
					params.cwd,
					params.thinking,
					selectedModel ?? agents.find((a) => a.name === params.agent)?.model,
					undefined,
					signal,
					onUpdate,
					makeDetails("single"),
				);
				const isError = result.exitCode !== 0 || result.stopReason === "error" || result.stopReason === "aborted";
				if (isError) {
					const errorMsg =
						result.errorMessage || result.stderr || getFinalOutput(result.messages) || "(no output)";
					return {
						content: [{ type: "text", text: `Agent ${result.stopReason || "failed"}: ${errorMsg}` }],
						details: makeDetails("single")([result]),
						isError: true,
					};
				}
				return {
					content: [{ type: "text", text: getFinalOutput(result.messages) || "(no output)" }],
					details: makeDetails("single")([result]),
				};
			}

			const available = agents.map((a) => `${a.name} (${a.source})`).join(", ") || "none";
			return {
				content: [{ type: "text", text: `Invalid parameters. Available agents: ${available}` }],
				details: makeDetails("single")([]),
			};
		},

		renderCall(args, theme) {
			const scope: AgentScope = args.agentScope ?? "user";
			if (args.chain && args.chain.length > 0) {
				let text =
					theme.fg("toolTitle", theme.bold("subagent ")) +
					theme.fg("accent", `chain (${args.chain.length} steps)`) +
					theme.fg("muted", ` [${scope}]`);
				for (let i = 0; i < Math.min(args.chain.length, 3); i++) {
					const step = args.chain[i];
					// Clean up {previous} placeholder for display
					const cleanTask = step.task.replace(/\{previous\}/g, "").trim();
					const preview = cleanTask.length > 40 ? `${cleanTask.slice(0, 40)}...` : cleanTask;
					text +=
						"\n  " +
						theme.fg("muted", `${i + 1}.`) +
						" " +
						theme.fg("accent", step.agent) +
						theme.fg("dim", ` ${preview}`);
				}
				if (args.chain.length > 3) text += `\n  ${theme.fg("muted", `... +${args.chain.length - 3} more`)}`;
				return new Text(text, 0, 0);
			}
			if (args.tasks && args.tasks.length > 0) {
				let text =
					theme.fg("toolTitle", theme.bold("subagent ")) +
					theme.fg("accent", `parallel (${args.tasks.length} tasks)`) +
					theme.fg("muted", ` [${scope}]`);
				for (const t of args.tasks.slice(0, 3)) {
					const preview = t.task.length > 40 ? `${t.task.slice(0, 40)}...` : t.task;
					text += `\n  ${theme.fg("accent", t.agent)}${theme.fg("dim", ` ${preview}`)}`;
				}
				if (args.tasks.length > 3) text += `\n  ${theme.fg("muted", `... +${args.tasks.length - 3} more`)}`;
				return new Text(text, 0, 0);
			}
			const agentName = args.agent || "...";
			const preview = args.task ? (args.task.length > 60 ? `${args.task.slice(0, 60)}...` : args.task) : "...";
			let text =
				theme.fg("toolTitle", theme.bold("subagent ")) +
				theme.fg("accent", agentName) +
				theme.fg("muted", ` [${scope}]`);
			text += `\n  ${theme.fg("dim", preview)}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, { expanded }, theme) {
			const details = result.details as SubagentDetails | undefined;
			if (!details || details.results.length === 0) {
				const text = result.content[0];
				return new Text(text?.type === "text" ? text.text : "(no output)", 0, 0);
			}

			const mdTheme = getMarkdownTheme();

			const renderDisplayItems = (items: DisplayItem[], limit?: number) => {
				const toShow = limit ? items.slice(-limit) : items;
				const skipped = limit && items.length > limit ? items.length - limit : 0;
				let text = "";
				if (skipped > 0) text += theme.fg("muted", `... ${skipped} earlier items\n`);
				for (const item of toShow) {
					if (item.type === "text") {
						const preview = expanded ? item.text : item.text.split("\n").slice(0, 3).join("\n");
						text += `${theme.fg("toolOutput", preview)}\n`;
					} else {
						text += `${theme.fg("muted", "→ ") + formatToolCall(item.name, item.args, theme.fg.bind(theme))}\n`;
					}
				}
				return text.trimEnd();
			};

			if (details.mode === "single" && details.results.length === 1) {
				const r = details.results[0];
				const isError = r.exitCode !== 0 || r.stopReason === "error" || r.stopReason === "aborted";
				const icon = isError ? theme.fg("error", "✗") : theme.fg("success", "✓");
				const displayItems = getDisplayItems(r.messages);
				const finalOutput = getFinalOutput(r.messages);

				if (expanded) {
					const container = new Container();
					let header = `${icon} ${theme.fg("toolTitle", theme.bold(r.agent))}${theme.fg("muted", ` (${r.agentSource})`)}`;
					if (isError && r.stopReason) header += ` ${theme.fg("error", `[${r.stopReason}]`)}`;
					container.addChild(new Text(header, 0, 0));
					if (isError && r.errorMessage)
						container.addChild(new Text(theme.fg("error", `Error: ${r.errorMessage}`), 0, 0));
					container.addChild(new Spacer(1));
					container.addChild(new Text(theme.fg("muted", "─── Task ───"), 0, 0));
					container.addChild(new Text(theme.fg("dim", r.task), 0, 0));
					container.addChild(new Spacer(1));
					container.addChild(new Text(theme.fg("muted", "─── Output ───"), 0, 0));
					if (displayItems.length === 0 && !finalOutput) {
						container.addChild(new Text(theme.fg("muted", "(no output)"), 0, 0));
					} else {
						for (const item of displayItems) {
							if (item.type === "toolCall")
								container.addChild(
									new Text(
										theme.fg("muted", "→ ") + formatToolCall(item.name, item.args, theme.fg.bind(theme)),
										0,
										0,
									),
								);
						}
						if (finalOutput) {
							container.addChild(new Spacer(1));
							container.addChild(new Markdown(finalOutput.trim(), 0, 0, mdTheme));
						}
					}
					const usageStr = formatUsageStats(r.usage, r.model);
					if (usageStr) {
						container.addChild(new Spacer(1));
						container.addChild(new Text(theme.fg("dim", usageStr), 0, 0));
					}
					return container;
				}

				let text = `${icon} ${theme.fg("toolTitle", theme.bold(r.agent))}${theme.fg("muted", ` (${r.agentSource})`)}`;
				if (isError && r.stopReason) text += ` ${theme.fg("error", `[${r.stopReason}]`)}`;
				if (isError && r.errorMessage) text += `\n${theme.fg("error", `Error: ${r.errorMessage}`)}`;
				else if (displayItems.length === 0) text += `\n${theme.fg("muted", "(no output)")}`;
				else {
					text += `\n${renderDisplayItems(displayItems, COLLAPSED_ITEM_COUNT)}`;
					if (displayItems.length > COLLAPSED_ITEM_COUNT) text += `\n${theme.fg("muted", "(Ctrl+O to expand)")}`;
				}
				const usageStr = formatUsageStats(r.usage, r.model);
				if (usageStr) text += `\n${theme.fg("dim", usageStr)}`;
				return new Text(text, 0, 0);
			}

			const aggregateUsage = (results: SingleResult[]) => {
				const total = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, turns: 0 };
				for (const r of results) {
					total.input += r.usage.input;
					total.output += r.usage.output;
					total.cacheRead += r.usage.cacheRead;
					total.cacheWrite += r.usage.cacheWrite;
					total.cost += r.usage.cost;
					total.turns += r.usage.turns;
				}
				return total;
			};

			if (details.mode === "chain") {
				const successCount = details.results.filter((r) => r.exitCode === 0).length;
				const icon = successCount === details.results.length ? theme.fg("success", "✓") : theme.fg("error", "✗");

				if (expanded) {
					const container = new Container();
					container.addChild(
						new Text(
							icon +
								" " +
								theme.fg("toolTitle", theme.bold("chain ")) +
								theme.fg("accent", `${successCount}/${details.results.length} steps`),
							0,
							0,
						),
					);

					for (const r of details.results) {
						const rIcon = r.exitCode === 0 ? theme.fg("success", "✓") : theme.fg("error", "✗");
						const displayItems = getDisplayItems(r.messages);
						const finalOutput = getFinalOutput(r.messages);

						container.addChild(new Spacer(1));
						container.addChild(
							new Text(
								`${theme.fg("muted", `─── Step ${r.step}: `) + theme.fg("accent", r.agent)} ${rIcon}`,
								0,
								0,
							),
						);
						container.addChild(new Text(theme.fg("muted", "Task: ") + theme.fg("dim", r.task), 0, 0));

						// Show tool calls
						for (const item of displayItems) {
							if (item.type === "toolCall") {
								container.addChild(
									new Text(
										theme.fg("muted", "→ ") + formatToolCall(item.name, item.args, theme.fg.bind(theme)),
										0,
										0,
									),
								);
							}
						}

						// Show final output as markdown
						if (finalOutput) {
							container.addChild(new Spacer(1));
							container.addChild(new Markdown(finalOutput.trim(), 0, 0, mdTheme));
						}

						const stepUsage = formatUsageStats(r.usage, r.model);
						if (stepUsage) container.addChild(new Text(theme.fg("dim", stepUsage), 0, 0));
					}

					const usageStr = formatUsageStats(aggregateUsage(details.results));
					if (usageStr) {
						container.addChild(new Spacer(1));
						container.addChild(new Text(theme.fg("dim", `Total: ${usageStr}`), 0, 0));
					}
					return container;
				}

				// Collapsed view
				let text =
					icon +
					" " +
					theme.fg("toolTitle", theme.bold("chain ")) +
					theme.fg("accent", `${successCount}/${details.results.length} steps`);
				for (const r of details.results) {
					const rIcon = r.exitCode === 0 ? theme.fg("success", "✓") : theme.fg("error", "✗");
					const displayItems = getDisplayItems(r.messages);
					text += `\n\n${theme.fg("muted", `─── Step ${r.step}: `)}${theme.fg("accent", r.agent)} ${rIcon}`;
					if (displayItems.length === 0) text += `\n${theme.fg("muted", "(no output)")}`;
					else text += `\n${renderDisplayItems(displayItems, 5)}`;
				}
				const usageStr = formatUsageStats(aggregateUsage(details.results));
				if (usageStr) text += `\n\n${theme.fg("dim", `Total: ${usageStr}`)}`;
				text += `\n${theme.fg("muted", "(Ctrl+O to expand)")}`;
				return new Text(text, 0, 0);
			}

			if (details.mode === "parallel") {
				const running = details.results.filter((r) => r.exitCode === -1).length;
				const successCount = details.results.filter((r) => r.exitCode === 0).length;
				const failCount = details.results.filter((r) => r.exitCode > 0).length;
				const isRunning = running > 0;
				const icon = isRunning
					? theme.fg("warning", "⏳")
					: failCount > 0
						? theme.fg("warning", "◐")
						: theme.fg("success", "✓");
				const status = isRunning
					? `${successCount + failCount}/${details.results.length} done, ${running} running`
					: `${successCount}/${details.results.length} tasks`;

				if (expanded && !isRunning) {
					const container = new Container();
					container.addChild(
						new Text(
							`${icon} ${theme.fg("toolTitle", theme.bold("parallel "))}${theme.fg("accent", status)}`,
							0,
							0,
						),
					);

					for (const r of details.results) {
						const rIcon = r.exitCode === 0 ? theme.fg("success", "✓") : theme.fg("error", "✗");
						const displayItems = getDisplayItems(r.messages);
						const finalOutput = getFinalOutput(r.messages);

						container.addChild(new Spacer(1));
						container.addChild(
							new Text(`${theme.fg("muted", "─── ") + theme.fg("accent", r.agent)} ${rIcon}`, 0, 0),
						);
						container.addChild(new Text(theme.fg("muted", "Task: ") + theme.fg("dim", r.task), 0, 0));

						// Show tool calls
						for (const item of displayItems) {
							if (item.type === "toolCall") {
								container.addChild(
									new Text(
										theme.fg("muted", "→ ") + formatToolCall(item.name, item.args, theme.fg.bind(theme)),
										0,
										0,
									),
								);
							}
						}

						// Show final output as markdown
						if (finalOutput) {
							container.addChild(new Spacer(1));
							container.addChild(new Markdown(finalOutput.trim(), 0, 0, mdTheme));
						}

						const taskUsage = formatUsageStats(r.usage, r.model);
						if (taskUsage) container.addChild(new Text(theme.fg("dim", taskUsage), 0, 0));
					}

					const usageStr = formatUsageStats(aggregateUsage(details.results));
					if (usageStr) {
						container.addChild(new Spacer(1));
						container.addChild(new Text(theme.fg("dim", `Total: ${usageStr}`), 0, 0));
					}
					return container;
				}

				// Collapsed view (or still running)
				let text = `${icon} ${theme.fg("toolTitle", theme.bold("parallel "))}${theme.fg("accent", status)}`;
				for (const r of details.results) {
					const rIcon =
						r.exitCode === -1
							? theme.fg("warning", "⏳")
							: r.exitCode === 0
								? theme.fg("success", "✓")
								: theme.fg("error", "✗");
					const displayItems = getDisplayItems(r.messages);
					text += `\n\n${theme.fg("muted", "─── ")}${theme.fg("accent", r.agent)} ${rIcon}`;
					if (displayItems.length === 0)
						text += `\n${theme.fg("muted", r.exitCode === -1 ? "(running...)" : "(no output)")}`;
					else text += `\n${renderDisplayItems(displayItems, 5)}`;
				}
				if (!isRunning) {
					const usageStr = formatUsageStats(aggregateUsage(details.results));
					if (usageStr) text += `\n\n${theme.fg("dim", `Total: ${usageStr}`)}`;
				}
				if (!expanded) text += `\n${theme.fg("muted", "(Ctrl+O to expand)")}`;
				return new Text(text, 0, 0);
			}

			const text = result.content[0];
			return new Text(text?.type === "text" ? text.text : "(no output)", 0, 0);
		},
	});

	// Renderer for async subagent completion messages
	pi.registerMessageRenderer("subagent_result", (message: any, _options: any, theme: any) => {
		const details = message.details as any;
		if (!details) return undefined;
		const icon = details.exitCode === 0 ? theme.fg("success", "✓") : theme.fg("error", "✗");
		const status = details.exitCode === 0 ? "completed" : `failed (exit ${details.exitCode})`;
		const header = `${icon} ${theme.fg("toolTitle", theme.bold(details.agent))} — ${status}`;
		const content = typeof message.content === "string" ? message.content : "";
		// Strip the header line from content since we render it ourselves
		const body = content.replace(/^Async subagent "[^"]*" [^\n]*\n\n/, "");
		const preview = body.length > 200 ? body.slice(0, 200) + "…" : body;
		const lines = [header, "", ...preview.split("\n")];
		return new Text(lines.join("\n"), 0, 0);
	});
}
