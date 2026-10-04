/**
 * pstack for Pi.
 *
 * Ports the runtime pieces of poteto's pstack (https://github.com/cursor/plugins/tree/main/pstack)
 * that Cursor provides natively:
 * - `task`: Cursor's Task tool. Runs one or more subagents as isolated `pi` child processes,
 *   each with its own agent type, model, and read-only flag, in parallel. In the foreground the
 *   call blocks until all finish; in the background each report arrives later as a message.
 *   Child transcripts are kept under ~/.pi/agent/pstack/task-sessions/ for auditing.
 * - `/poteto-mode`: Cursor's sticky mode. Once the poteto-mode skill runs, a reminder rides
 *   along in the system prompt every turn until `/poteto-mode off`.
 * - `todo_write`: Cursor's TodoWrite. Playbooks open a todolist whose first items are their steps.
 * - `~/.pi/agent/pstack-models.md`: Cursor's always-applied model rule, injected every turn.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { StringEnum } from "@earendil-works/pi-ai";
import { type ExtensionAPI, type ExtensionContext, getAgentDir } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { MODE_ENTRY_TYPE, type PotetoModeState, modeReminder, modelsSection, potetoSkillInvocation, restoreModeState, sessionSection } from "./mode.ts";
import {
	AGENT_TYPES,
	MAX_CONCURRENCY,
	MAX_TASKS,
	type TaskResult,
	type TaskSpec,
	addUsage,
	currentDepth,
	inheritedReadonly,
	emptyUsage,
	formatBackgroundStatus,
	formatFinal,
	formatProgress,
	mapWithConcurrency,
	pendingResult,
	runTask,
	validateTasks,
} from "./task.ts";
import { TODO_STATUSES, type Todo, type TodoDetails, renderTodos, restoreTodos } from "./todo.ts";

const MODELS_FILE = path.join(getAgentDir(), "pstack-models.md");
const TASK_SESSIONS_DIR = path.join(getAgentDir(), "pstack", "task-sessions");

const TaskItem = Type.Object({
	description: Type.String({ description: "Short label for this subagent, shown in progress output." }),
	prompt: Type.String({
		description:
			"The complete, self-contained brief. The subagent sees nothing from this conversation. Pass file paths instead of pasting large context.",
	}),
	agent: Type.Optional(
		StringEnum(AGENT_TYPES, {
			description:
				"general (default): plain Pi agent. poteto-agent: reads the poteto-mode skill first; use for code-writing delegates inside poteto-mode playbooks. comment-sicko: deletes comments in the given scope and flags refactor targets, for the no-comments skill.",
		}),
	),
	model: Type.Optional(
		Type.String({
			description:
				'Model as "provider/id" with optional ":thinking" suffix, e.g. "anthropic/claude-opus-5-5:max". Omit, or pass "inherit-parent" or "auto", to use the current model and thinking level.',
		}),
	),
	readonly: Type.Optional(
		Type.Boolean({ description: "Disable edit and write tools and tell the subagent not to change anything. Default false." }),
	),
	cwd: Type.Optional(Type.String({ description: "Working directory for the subagent, e.g. a worktree. Default: current cwd." })),
});

export default function pstack(pi: ExtensionAPI) {
	let mode: PotetoModeState = { enabled: false };
	interface BackgroundEntry {
		controller: AbortController;
		progress: TaskResult;
		startedAt: number;
		/** Resolves to the formatted report when the subagent ends. */
		report: Promise<string>;
		/** `task_status` calls currently waiting on this task. While any wait, they receive the report instead of a message. */
		waiters: number;
		done: boolean;
	}
	const background = new Map<string, BackgroundEntry>();
	let nextBackgroundId = 1;

	const showBackground = (ctx: ExtensionContext) => {
		ctx.ui.setStatus("pstack-tasks", background.size > 0 ? `${background.size} background task(s)` : undefined);
	};

	const deliverReport = (content: string, ctx: ExtensionContext) => {
		// An idle session must wake through a user message: a custom message starts the turn without
		// before_agent_start, and Pi then drops the poteto_mode and pstack_models prompt sections.
		// A busy session gets the report at its next tool boundary (steer), not after the whole run (followUp).
		if (ctx.isIdle()) pi.sendUserMessage(content);
		else pi.sendMessage({ customType: "pstack-task", content, display: true }, { triggerTurn: true, deliverAs: "steer" });
	};

	const startBackground = (task: TaskSpec, parent: { model?: string; thinkingLevel?: string }, ctx: ExtensionContext): string => {
		const id = `bg-${nextBackgroundId++}`;
		const controller = new AbortController();
		const report = runTask(task, parent, TASK_SESSIONS_DIR, ctx.cwd, controller.signal, (result) => {
			entry.progress = result;
		}).then(
			(result) => `Background task ${id} finished.\n\n${formatFinal([result])}`,
			(error: unknown) => `Background task ${id} (${task.description}) failed to start: ${String(error)}`,
		);
		const entry: BackgroundEntry = { controller, progress: pendingResult(task), startedAt: Date.now(), report, waiters: 0, done: false };
		background.set(id, entry);
		showBackground(ctx);
		void report.then((content) => {
			entry.done = true;
			if (controller.signal.aborted) return;
			background.delete(id);
			showBackground(ctx);
			if (entry.waiters === 0) deliverReport(content, ctx);
		});
		return id;
	};

	pi.on("session_shutdown", async () => {
		for (const { controller } of background.values()) controller.abort();
		background.clear();
	});

	const setMode = (next: PotetoModeState, ctx: ExtensionContext) => {
		mode = next;
		pi.appendEntry(MODE_ENTRY_TYPE, next);
		ctx.ui.setStatus("pstack", next.enabled ? "poteto" : undefined);
	};

	const showTodos = (todos: Todo[], ctx: ExtensionContext) => {
		const open = todos.some((todo) => todo.status === "pending" || todo.status === "in_progress");
		ctx.ui.setWidget("pstack-todos", open ? renderTodos(todos) : undefined);
	};

	const restoreBranchState = (ctx: ExtensionContext) => {
		const branch = ctx.sessionManager.getBranch();
		mode = restoreModeState(branch);
		ctx.ui.setStatus("pstack", mode.enabled ? "poteto" : undefined);
		showTodos(restoreTodos(branch), ctx);
	};

	pi.on("session_start", async (_event, ctx) => restoreBranchState(ctx));
	pi.on("session_tree", async (_event, ctx) => restoreBranchState(ctx));

	pi.on("before_agent_start", async (event, ctx) => {
		const skillPath = potetoSkillInvocation(event.prompt);
		if (skillPath && (!mode.enabled || mode.skillPath !== skillPath)) {
			setMode({ enabled: true, skillPath }, ctx);
		}

		const sections = (event.systemPromptOptions.sections ??= {});
		if (mode.enabled) sections.poteto_mode = modeReminder(mode);
		// Subagent sessions share one directory across projects, so only the top-level session names its transcripts.
		const sessionFile = currentDepth() === 0 ? ctx.sessionManager.getSessionFile() : undefined;
		if (sessionFile) {
			sections.pstack_session = sessionSection(sessionFile, ctx.sessionManager.getSessionDir());
		}
		if (fs.existsSync(MODELS_FILE)) {
			sections.pstack_models = modelsSection(fs.readFileSync(MODELS_FILE, "utf8"), MODELS_FILE);
		}
	});

	pi.registerCommand("poteto-mode", {
		description: "Apply poteto-mode to a task and keep it on (sticky). `/poteto-mode off` turns it off.",
		handler: async (args, ctx) => {
			const request = args.trim();
			if (request === "on") {
				pi.sendUserMessage("/skill:poteto-mode", { expandPromptTemplates: true, deliverAs: "followUp" });
				return;
			}
			if (request === "off") {
				setMode({ ...mode, enabled: false }, ctx);
				ctx.ui.notify("Poteto mode off.", "info");
				return;
			}
			if (request === "status") {
				ctx.ui.notify(`Poteto mode is ${mode.enabled ? "on" : "off"}.`, "info");
				return;
			}
			pi.sendUserMessage(request ? `/skill:poteto-mode ${request}` : "/skill:poteto-mode", {
				expandPromptTemplates: true,
				deliverAs: "followUp",
			});
		},
	});

	pi.registerTool({
		name: "todo_write",
		label: "Todos",
		description:
			"Replace the session's todo list. Send the complete list every call, with each item's current status. Do not number items; the list is numbered for you. Keep exactly one item in_progress while working, and mark items completed as soon as they are done.",
		parameters: Type.Object({
			todos: Type.Array(
				Type.Object({
					content: Type.String({ description: "The todo, as an imperative step." }),
					status: StringEnum(TODO_STATUSES),
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const details: TodoDetails = { todos: params.todos as Todo[] };
			showTodos(details.todos, ctx);
			return { content: [{ type: "text", text: renderTodos(details.todos).join("\n") }], details };
		},
	});

	pi.registerTool({
		name: "task",
		label: "Task",
		description: [
			"Run subagents in isolated Pi processes, in parallel, and return each one's final report.",
			`Pass every independent subagent in one call (max ${MAX_TASKS}, ${MAX_CONCURRENCY} run at once); the call returns when all finish.`,
			"Each subagent starts with an empty context: its prompt must carry the whole brief and file pointers.",
			"Use a different `model` per entry for multi-model panels. Set `background: true` to keep working while they run. You own the results: review them, don't pass them through.",
		].join(" "),
		parameters: Type.Object({
			tasks: Type.Array(TaskItem, { minItems: 1, maxItems: MAX_TASKS }),
			background: Type.Optional(
				Type.Boolean({
					description:
						"Return immediately and keep working. Each subagent's report arrives later as its own message that starts a new turn. Default false: the call blocks until every subagent finishes. Ignored inside subagents and print mode.",
				}),
			),
		}),
		async execute(_toolCallId, params, signal, onUpdate, ctx) {
			const forceReadonly = inheritedReadonly();
			const tasks = (params.tasks as TaskSpec[]).map((task) => (forceReadonly ? { ...task, readonly: true } : task));
			const depth = currentDepth();
			validateTasks(tasks, depth);

			const parent = {
				model: ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined,
				thinkingLevel: pi.getThinkingLevel(),
			};

			// Print mode exits when the turn ends, and subagents run in print mode, so only a live session can wait for background reports.
			if (params.background && depth === 0 && ctx.hasUI) {
				const ids = tasks.map((task) => startBackground(task, parent, ctx));
				const lines = ids.map((id, index) => `${id}: ${tasks[index].description}`);
				return {
					content: [
						{
							type: "text",
							text: `Started ${ids.length} background task(s). Each report arrives as a separate message when it finishes.\n${lines.join("\n")}`,
						},
					],
					details: undefined,
				};
			}

			const progress = tasks.map(pendingResult);
			const report = () => onUpdate?.({ content: [{ type: "text", text: formatProgress(progress) }], details: undefined });

			const results = await mapWithConcurrency(tasks, MAX_CONCURRENCY, (task, index) =>
				runTask(task, parent, TASK_SESSIONS_DIR, ctx.cwd, signal, (result) => {
					progress[index] = result;
					report();
				}),
			);

			const usage = emptyUsage();
			for (const result of results) addUsage(usage, result.usage);
			const notes = [
				params.background ? "Ran in the foreground: background tasks need an interactive top-level session." : "",
				forceReadonly ? "Ran read-only: this subagent is read-only, so every subagent it spawns is too." : "",
			].filter(Boolean);
			return {
				content: [{ type: "text", text: [...notes, formatFinal(results)].join("\n\n") }],
				details: undefined,
				usage,
				isError: results.every((result) => result.status === "failed"),
			};
		},
	});

	pi.registerTool({
		name: "task_status",
		label: "Task status",
		description:
			"List running background subagents started with `task` (id, elapsed time, turns, last activity). `stop` ends tasks by id; a stopped task sends no report. `wait` blocks until the given tasks finish and returns their reports here instead of as later messages: use it when your next step needs a background result.",
		parameters: Type.Object({
			stop: Type.Optional(Type.Array(Type.String(), { description: "Background task ids to stop, e.g. [\"bg-3\"]." })),
			wait: Type.Optional(Type.Array(Type.String(), { description: "Background task ids to wait for, e.g. [\"bg-1\"]." })),
		}),
		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			const stopped: string[] = [];
			const unknown: string[] = [];
			for (const id of params.stop ?? []) {
				const entry = background.get(id);
				if (!entry) {
					unknown.push(id);
					continue;
				}
				entry.controller.abort();
				background.delete(id);
				stopped.push(id);
			}

			const waited = (params.wait ?? []).flatMap((id) => {
				const entry = background.get(id);
				if (!entry) unknown.push(id);
				return entry ? [entry] : [];
			});
			let reports: string[] = [];
			if (waited.length > 0) {
				for (const entry of waited) entry.waiters++;
				const aborted = new Promise<"aborted">((resolve) => {
					if (signal?.aborted) resolve("aborted");
					signal?.addEventListener("abort", () => resolve("aborted"), { once: true });
				});
				const outcome = await Promise.race([Promise.all(waited.map((entry) => entry.report)), aborted]);
				for (const entry of waited) entry.waiters--;
				if (outcome === "aborted") {
					// Reports that finished during the interrupted wait were held back for it; send them now.
					for (const entry of waited) {
						if (entry.done && entry.waiters === 0 && !entry.controller.signal.aborted) {
							void entry.report.then((content) => deliverReport(content, ctx));
						}
					}
					throw new Error("task_status: wait aborted");
				}
				reports = outcome;
			}

			showBackground(ctx);
			const now = Date.now();
			const running = [...background].map(([id, entry]) => ({ id, startedAt: entry.startedAt, progress: entry.progress }));
			const status = formatBackgroundStatus(running, stopped, unknown, now);
			return { content: [{ type: "text", text: [...reports, status].join("\n\n---\n\n") }], details: undefined };
		},
	});
}
