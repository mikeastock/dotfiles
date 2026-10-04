import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { Message, Usage } from "@earendil-works/pi-ai";

export const AGENT_TYPES = ["general", "poteto-agent", "comment-sicko"] as const;
export type AgentType = (typeof AGENT_TYPES)[number];

export const PARENT_MODEL_ALIASES = ["inherit-parent", "auto"] as const;

export const MAX_TASKS = 12;
export const MAX_CONCURRENCY = 6;
export const MAX_DEPTH = 2;
export const DEPTH_ENV = "PSTACK_TASK_DEPTH";
const OUTPUT_CAP_BYTES = 50 * 1024;
const MAX_PROMPT_BYTES = 100 * 1024;
const READONLY_EXCLUDED_TOOLS = ["edit", "write"];
const READONLY_NOTICE =
	"This is a read-only task. Do not create, modify, or delete files, and do not run commands that change the repository or external systems.";

export interface TaskSpec {
	description: string;
	prompt: string;
	agent?: AgentType;
	model?: string;
	readonly?: boolean;
	cwd?: string;
}

export interface ParentModel {
	model?: string;
	thinkingLevel?: string;
}

export interface TaskResult {
	description: string;
	transcript?: string;
	agent: AgentType;
	model?: string;
	status: "running" | "done" | "failed";
	output: string;
	turns: number;
	lastActivity?: string;
	usage: Usage;
	error?: string;
}

const AGENTS_DIR = fileURLToPath(new URL("./agents/", import.meta.url));

export function currentDepth(env: NodeJS.ProcessEnv = process.env): number {
	const depth = Number.parseInt(env[DEPTH_ENV] ?? "0", 10);
	return Number.isFinite(depth) && depth > 0 ? depth : 0;
}

export function stripFrontmatter(markdown: string): string {
	return markdown.replace(/^---\n[\s\S]*?\n---\n?/, "").trim();
}

export function agentSystemPrompt(agent: AgentType): string | undefined {
	if (agent === "general") return undefined;
	return stripFrontmatter(fs.readFileSync(path.join(AGENTS_DIR, `${agent}.md`), "utf8"));
}

export function resolveModel(spec: TaskSpec, parent: ParentModel): { model?: string; thinkingLevel?: string } {
	const requested = spec.model?.trim();
	if (!requested || (PARENT_MODEL_ALIASES as readonly string[]).includes(requested)) {
		return { model: parent.model, thinkingLevel: parent.thinkingLevel };
	}
	return { model: requested };
}

export interface ChildSession {
	dir: string;
	id: string;
}

export function buildChildArgs(spec: TaskSpec, parent: ParentModel, session: ChildSession, systemPromptFile?: string): string[] {
	const args = ["--mode", "json", "-p", "--session-dir", session.dir, "--session-id", session.id];
	const { model, thinkingLevel } = resolveModel(spec, parent);
	if (model) args.push("--model", model);
	if (thinkingLevel) args.push("--thinking", thinkingLevel);
	if (spec.readonly) args.push("--exclude-tools", READONLY_EXCLUDED_TOOLS.join(","));
	if (systemPromptFile) args.push("--append-system-prompt", systemPromptFile);
	args.push("--", spec.prompt);
	return args;
}

export function childSystemPrompt(spec: TaskSpec): string | undefined {
	const parts = [agentSystemPrompt(spec.agent ?? "general"), spec.readonly ? READONLY_NOTICE : undefined];
	const text = parts.filter((part): part is string => Boolean(part)).join("\n\n");
	return text || undefined;
}

export function validateTasks(tasks: TaskSpec[], depth: number): void {
	if (depth >= MAX_DEPTH) {
		throw new Error(`task: nesting limit reached (depth ${depth}). Do this work yourself instead of delegating.`);
	}
	if (tasks.length === 0) throw new Error("task: pass at least one task.");
	if (tasks.length > MAX_TASKS) throw new Error(`task: at most ${MAX_TASKS} tasks per call, got ${tasks.length}.`);
	for (const task of tasks) {
		if (Buffer.byteLength(task.prompt, "utf8") > MAX_PROMPT_BYTES) {
			throw new Error(
				`task "${task.description}": prompt exceeds ${MAX_PROMPT_BYTES / 1024} KB. Write the context to a file and pass its path.`,
			);
		}
	}
}

export function emptyUsage(): Usage {
	return {
		input: 0,
		output: 0,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens: 0,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	};
}

export function addUsage(total: Usage, usage: Usage | undefined): void {
	if (!usage) return;
	total.input += usage.input ?? 0;
	total.output += usage.output ?? 0;
	total.cacheRead += usage.cacheRead ?? 0;
	total.cacheWrite += usage.cacheWrite ?? 0;
	total.totalTokens += usage.totalTokens ?? 0;
	total.cost.input += usage.cost?.input ?? 0;
	total.cost.output += usage.cost?.output ?? 0;
	total.cost.cacheRead += usage.cost?.cacheRead ?? 0;
	total.cost.cacheWrite += usage.cost?.cacheWrite ?? 0;
	total.cost.total += usage.cost?.total ?? 0;
}

function describeToolCall(name: string, args: Record<string, unknown>): string {
	const detail = args.command ?? args.path ?? args.pattern ?? args.description ?? "";
	const text = `${name} ${String(detail)}`.trim().replace(/\s+/g, " ");
	return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}

/** Fold one `pi --mode json` event line into the running result. Returns true when the result changed. */
export function applyChildEvent(result: TaskResult, line: string): boolean {
	if (!line.trim()) return false;
	let event: { type?: string; message?: Message };
	try {
		event = JSON.parse(line);
	} catch {
		return false;
	}
	if (event.type !== "message_end" || event.message?.role !== "assistant") return false;

	const message = event.message;
	result.turns++;
	addUsage(result.usage, message.usage);
	if (message.model && !result.model) result.model = `${message.provider}/${message.model}`;
	for (const part of message.content) {
		if (part.type === "toolCall") result.lastActivity = describeToolCall(part.name, part.arguments);
	}
	const text = message.content
		.filter((part) => part.type === "text")
		.map((part) => part.text)
		.join("\n")
		.trim();
	if (text) result.output = text;
	if (message.stopReason === "error" || message.stopReason === "aborted") {
		result.error = message.errorMessage ?? `child stopped: ${message.stopReason}`;
	}
	return true;
}

export function capOutput(output: string): string {
	const bytes = Buffer.byteLength(output, "utf8");
	if (bytes <= OUTPUT_CAP_BYTES) return output;
	let truncated = output.slice(0, OUTPUT_CAP_BYTES);
	while (Buffer.byteLength(truncated, "utf8") > OUTPUT_CAP_BYTES) truncated = truncated.slice(0, -1);
	return `${truncated}\n\n[output truncated: ${bytes - Buffer.byteLength(truncated, "utf8")} bytes omitted]`;
}

function piInvocation(args: string[]): { command: string; args: string[] } {
	const script = process.argv[1];
	if (script && !script.startsWith("/$bunfs/") && fs.existsSync(script)) {
		return { command: process.execPath, args: [script, ...args] };
	}
	if (!/^(node|bun)(\.exe)?$/i.test(path.basename(process.execPath))) {
		return { command: process.execPath, args };
	}
	return { command: "pi", args };
}

/** Pi names session files `<timestamp>_<id>.jsonl`. */
export async function findTranscript(session: ChildSession): Promise<string | undefined> {
	const names = await fs.promises.readdir(session.dir).catch(() => [] as string[]);
	const name = names.find((entry) => entry.endsWith(`_${session.id}.jsonl`));
	return name ? path.join(session.dir, name) : undefined;
}

export async function runTask(
	spec: TaskSpec,
	parent: ParentModel,
	sessionDir: string,
	defaultCwd: string,
	signal: AbortSignal | undefined,
	onChange: (result: TaskResult) => void,
): Promise<TaskResult> {
	const agent = spec.agent ?? "general";
	const result: TaskResult = {
		description: spec.description,
		agent,
		model: resolveModel(spec, parent).model,
		status: "running",
		output: "",
		turns: 0,
		usage: emptyUsage(),
	};

	const systemPrompt = childSystemPrompt(spec);
	const tmpDir = systemPrompt ? await fs.promises.mkdtemp(path.join(os.tmpdir(), "pstack-task-")) : undefined;
	const systemPromptFile = tmpDir ? path.join(tmpDir, "system-prompt.md") : undefined;

	try {
		if (systemPromptFile && systemPrompt) {
			await fs.promises.writeFile(systemPromptFile, systemPrompt, { mode: 0o600 });
		}
		await fs.promises.mkdir(sessionDir, { recursive: true });
		const session = { dir: sessionDir, id: randomUUID() };
		const invocation = piInvocation(buildChildArgs(spec, parent, session, systemPromptFile));
		let stderr = "";
		let aborted = false;

		const exitCode = await new Promise<number>((resolve) => {
			const child = spawn(invocation.command, invocation.args, {
				cwd: spec.cwd ?? defaultCwd,
				env: { ...process.env, [DEPTH_ENV]: String(currentDepth() + 1) },
				stdio: ["ignore", "pipe", "pipe"],
			});
			let buffer = "";
			child.stdout.on("data", (chunk) => {
				buffer += chunk.toString();
				const lines = buffer.split("\n");
				buffer = lines.pop() ?? "";
				for (const line of lines) if (applyChildEvent(result, line)) onChange(result);
			});
			child.stderr.on("data", (chunk) => {
				stderr += chunk.toString();
			});
			child.on("close", (code) => {
				if (applyChildEvent(result, buffer)) onChange(result);
				resolve(code ?? 1);
			});
			child.on("error", (error) => {
				stderr += error.message;
				resolve(1);
			});
			const kill = () => {
				aborted = true;
				child.kill("SIGTERM");
				setTimeout(() => child.exitCode === null && child.kill("SIGKILL"), 5000).unref();
			};
			if (signal?.aborted) kill();
			else signal?.addEventListener("abort", kill, { once: true });
		});

		if (aborted) result.error = "aborted";
		else if (exitCode !== 0 && !result.error) result.error = stderr.trim() || `pi exited with code ${exitCode}`;
		result.status = result.error ? "failed" : "done";
		result.transcript = await findTranscript(session);
		onChange(result);
		return result;
	} finally {
		if (tmpDir) await fs.promises.rm(tmpDir, { recursive: true, force: true });
	}
}

export async function mapWithConcurrency<TIn, TOut>(
	items: TIn[],
	concurrency: number,
	fn: (item: TIn, index: number) => Promise<TOut>,
): Promise<TOut[]> {
	const results: TOut[] = new Array(items.length);
	let next = 0;
	const workers = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
		while (next < items.length) {
			const index = next++;
			results[index] = await fn(items[index], index);
		}
	});
	await Promise.all(workers);
	return results;
}

export function pendingResult(spec: TaskSpec): TaskResult {
	return {
		description: spec.description,
		agent: spec.agent ?? "general",
		status: "running",
		output: "",
		turns: 0,
		usage: emptyUsage(),
	};
}

export function formatBackgroundStatus(
	running: Array<{ id: string; startedAt: number; progress: TaskResult }>,
	stopped: string[],
	now: number,
): string {
	const lines = running.map(({ id, startedAt, progress }) => {
		const minutes = Math.floor((now - startedAt) / 60_000);
		const activity = progress.lastActivity ? ` · last: ${progress.lastActivity}` : "";
		return `${id}: ${progress.description} (${progress.agent}, ${minutes}m, ${progress.turns} turns)${activity}`;
	});
	return [
		...(stopped.length > 0 ? [`Stopped: ${stopped.join(", ")}`] : []),
		running.length > 0 ? `Running background tasks:\n${lines.join("\n")}` : "No background tasks running.",
	].join("\n");
}

export function formatProgress(results: TaskResult[]): string {
	const done = results.filter((result) => result.status !== "running").length;
	const lines = results.map((result, index) => {
		const icon = result.status === "running" ? "…" : result.status === "done" ? "✓" : "✗";
		const activity = result.status === "running" && result.lastActivity ? ` · ${result.lastActivity}` : "";
		return `${icon} [${index + 1}] ${result.description} (${result.agent}, ${result.model ?? "parent model"}, ${result.turns} turns)${activity}`;
	});
	return [`${done}/${results.length} tasks finished`, ...lines].join("\n");
}

export function formatFinal(results: TaskResult[]): string {
	return results
		.map((result, index) => {
			const transcript = result.transcript ? `\ntranscript: ${result.transcript}` : "";
			const header = `## [${index + 1}] ${result.description}\nagent: ${result.agent} · model: ${result.model ?? "parent model"} · status: ${result.status} · turns: ${result.turns}${transcript}`;
			const body = result.status === "failed" ? `Error: ${result.error}\n\n${result.output}`.trim() : result.output || "(no output)";
			return `${header}\n\n${capOutput(body)}`;
		})
		.join("\n\n---\n\n");
}
