/**
 * Handoff extension - transfer context to a new focused session
 *
 * Instead of compacting (which is lossy), handoff extracts what matters
 * for your next task and creates a new session with a generated prompt.
 *
 * Provides both:
 * - /handoff command: user types `/handoff <goal>`
 * - handoff tool: prepares a safe `/handoff ...` command for the user to submit
 *
 * Usage:
 *   /handoff now implement this for teams as well
 *   /handoff -mode rush execute phase one of the plan
 *   /handoff -model anthropic/claude-haiku-4-5 check other places that need this fix
 *
 * The generated prompt appears as a draft in the editor for review/editing.
 */

import type { Message } from "@earendil-works/pi-ai";
import { complete } from "@earendil-works/pi-ai/compat";
import type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
	SessionEntry,
} from "@earendil-works/pi-coding-agent";
import {
	BorderedLoader,
	convertToLlm,
	serializeConversation,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import {
	buildHandoffActivityEvent,
	HANDOFF_ACTIVITY_END_EVENT,
	HANDOFF_ACTIVITY_START_EVENT,
	type HandoffActivityPhase,
} from "./events.js";
import {
	getEffectiveHandoffOptions,
	type HandoffOptions,
} from "./lib/effective-options.js";
import { loadModeSpec } from "./lib/mode-utils.js";
import { buildFinalPrompt } from "./lib/session-lineage.js";
import { prepareToolHandoff } from "./lib/tool-path.js";

const HANDOFF_GLOBAL_KEY = Symbol.for("pi-amplike-handoff-pending");
type PendingHandoffGlobal = { prompt: string; options?: HandoffOptions } | null;
function getPendingHandoffGlobal(): PendingHandoffGlobal {
	return (globalThis as any)[HANDOFF_GLOBAL_KEY] ?? null;
}
function setPendingHandoffGlobal(data: PendingHandoffGlobal) {
	if (data) {
		(globalThis as any)[HANDOFF_GLOBAL_KEY] = data;
	} else {
		delete (globalThis as any)[HANDOFF_GLOBAL_KEY];
	}
}

const CONTEXT_SUMMARY_SYSTEM_PROMPT = `You are a context transfer assistant. Given a conversation history and the user's goal for a new thread, generate a focused prompt that:

1. Summarizes relevant context from the conversation (decisions made, approaches taken, key findings)
2. Lists any relevant files that were discussed or modified
3. Clearly states the next task based on the user's goal
4. Is self-contained - the new thread should be able to proceed without the old conversation

Format your response as a prompt the user can send to start the new thread. Be concise but include all necessary context. Do not include any preamble like "Here's the prompt" - just output the prompt itself.

Example output format:
## Context
We've been working on X. Key decisions:
- Decision 1
- Decision 2

Files involved:
- path/to/file1.ts
- path/to/file2.ts

## Task
[Clear description of what to do next based on user's goal]`;

async function generateContextSummary(
	model: any,
	apiKey: string | undefined,
	headers: Record<string, string> | undefined,
	messages: any[],
	goal: string,
	signal?: AbortSignal,
): Promise<string | null> {
	const conversationText = serializeConversation(convertToLlm(messages));

	const userMessage: Message = {
		role: "user",
		content: [
			{
				type: "text",
				text: `## Conversation History\n\n${conversationText}\n\n## User's Goal for New Thread\n\n${goal}`,
			},
		],
		timestamp: Date.now(),
	};

	const response = await complete(
		model,
		{ systemPrompt: CONTEXT_SUMMARY_SYSTEM_PROMPT, messages: [userMessage] },
		{ apiKey, headers, signal },
	);

	if (response.stopReason === "aborted") {
		return null;
	}

	return response.content
		.filter((c): c is { type: "text"; text: string } => c.type === "text")
		.map((c) => c.text)
		.join("\n");
}

async function applyHandoffOptions(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	options?: HandoffOptions,
): Promise<void> {
	if (!options) return;

	if (options.mode) {
		const spec = await loadModeSpec(ctx.cwd, options.mode);
		if (spec) {
			if (spec.provider && spec.modelId) {
				const model = ctx.modelRegistry.find(spec.provider, spec.modelId);
				if (model) {
					await pi.setModel(model);
				} else {
					ctx.hasUI &&
						ctx.ui.notify(
							`Handoff: mode "${options.mode}" references unknown model ${spec.provider}/${spec.modelId}`,
							"warning",
						);
				}
			}
			if (spec.thinkingLevel) {
				pi.setThinkingLevel(spec.thinkingLevel as any);
			}
		} else {
			ctx.hasUI && ctx.ui.notify(`Handoff: unknown mode "${options.mode}"`, "warning");
		}
	}

	if (options.model) {
		const slashIdx = options.model.indexOf("/");
		if (slashIdx > 0) {
			const provider = options.model.slice(0, slashIdx);
			const modelId = options.model.slice(slashIdx + 1);
			const model = ctx.modelRegistry.find(provider, modelId);
			if (model) {
				await pi.setModel(model);
			} else {
				ctx.hasUI && ctx.ui.notify(`Handoff: unknown model ${options.model}`, "warning");
			}
		} else {
			ctx.hasUI &&
				ctx.ui.notify(
					`Handoff: invalid model format "${options.model}", expected provider/modelId`,
					"warning",
				);
		}
	}
}

const emitHandoffActivity = (
	pi: ExtensionAPI,
	eventName: string,
	phase: HandoffActivityPhase,
) => {
	pi.events.emit(eventName, buildHandoffActivityEvent({ phase }));
};

async function performHandoff(
	pi: ExtensionAPI,
	ctx: ExtensionCommandContext,
	goal: string,
	options?: HandoffOptions,
): Promise<string | undefined> {
	if (!ctx.hasUI) {
		return "Handoff requires interactive mode.";
	}

	if (!ctx.model) {
		return "No model selected.";
	}

	const branch = ctx.sessionManager.getBranch();
	const messages = branch
		.filter((entry): entry is SessionEntry & { type: "message" } => entry.type === "message")
		.map((entry) => entry.message);

	if (messages.length === 0) {
		return "No conversation to hand off.";
	}

	const currentSessionFile = ctx.sessionManager.getSessionFile();
	const effectiveOptions = getEffectiveHandoffOptions(
		options,
		ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined,
	);

	emitHandoffActivity(pi, HANDOFF_ACTIVITY_START_EVENT, "generation");

	const result = await ctx.ui.custom<string | null>((tui, theme, _kb, done) => {
		const loader = new BorderedLoader(tui, theme, `Generating handoff prompt...`);
		loader.onAbort = () => done(null);

		const doGenerate = async () => {
			const auth = await ctx.modelRegistry.getApiKeyAndHeaders(ctx.model!);
			if (!auth.ok || !auth.apiKey) {
				throw new Error(auth.ok ? `No API key for ${ctx.model!.provider}` : auth.error);
			}
			return generateContextSummary(
				ctx.model!,
				auth.apiKey,
				auth.headers,
				messages,
				goal,
				loader.signal,
			);
		};

		doGenerate()
			.then(done)
			.catch((err) => {
				console.error("Handoff generation failed:", err);
				done(null);
			});

		return loader;
	});

	emitHandoffActivity(pi, HANDOFF_ACTIVITY_END_EVENT, "generation");

	if (result === null) {
		return "Handoff cancelled.";
	}

	const finalPrompt = buildFinalPrompt({
		goal,
		summary: result,
		currentSessionFile,
	});

	setPendingHandoffGlobal({ prompt: finalPrompt, options: effectiveOptions });
	const newSessionResult = await ctx.newSession({ parentSession: currentSessionFile });
	if (newSessionResult.cancelled) {
		setPendingHandoffGlobal(null);
		return;
	}

	return undefined;
}

export default function (pi: ExtensionAPI) {
	pi.on("session_start", async (event, ctx) => {

		if (event.reason === "new") {
			const pending = getPendingHandoffGlobal();
			if (pending) {
				setPendingHandoffGlobal(null);
				setTimeout(() => {
					applyHandoffOptions(pi, ctx, pending.options)
						.catch((err) => console.error("Handoff option apply failed:", err))
						.then(() => {
							emitHandoffActivity(pi, HANDOFF_ACTIVITY_START_EVENT, "seeding");
							pi.sendUserMessage(pending.prompt);
						});
				}, 0);
			}
		}
	});

	pi.registerCommand("handoff", {
		description: "Transfer context to a new focused session (-mode <name>, -model <provider/id>)",
		handler: async (args, ctx) => {
			const options: HandoffOptions = {};
			let remaining = args;

			const modeMatch = remaining.match(/(?:^|\s)-mode\s+(\S+)/);
			if (modeMatch) {
				options.mode = modeMatch[1];
				remaining = remaining.replace(modeMatch[0], " ");
			}

			const modelMatch = remaining.match(/(?:^|\s)-model\s+(\S+)/);
			if (modelMatch) {
				options.model = modelMatch[1];
				remaining = remaining.replace(modelMatch[0], " ");
			}

			const goal = remaining.trim();
			if (!goal) {
				ctx.ui.notify(
					"Usage: /handoff [-mode <name>] [-model <provider/id>] <goal>",
					"error",
				);
				return;
			}

			const hasOptions = options.mode || options.model;
			const error = await performHandoff(pi, ctx, goal, hasOptions ? options : undefined);
			if (error) {
				ctx.ui.notify(error, "error");
			}
		},
	});

	pi.registerTool({
		name: "handoff",
		label: "Handoff",
		description:
			"Prepare a safe `/handoff ...` command in the editor for the user to submit. ONLY use this when the user explicitly asks for a handoff. Provide a goal describing what the new session should focus on.",
		parameters: Type.Object({
			goal: Type.String({ description: "The goal/task for the new session" }),
			mode: Type.Optional(
				Type.String({
					description:
						"Amplike mode name to start the new session with (e.g. 'rush', 'smart', 'deep')",
				}),
			),
			model: Type.Optional(
				Type.String({
					description:
						"Model to start the new session with, as provider/modelId (e.g. 'anthropic/claude-haiku-4-5')",
				}),
			),
		}),

		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			return prepareToolHandoff(ctx, {
				goal: params.goal,
				mode: params.mode,
				model: params.model,
			});
		},
	});
}
