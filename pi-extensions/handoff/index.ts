/**
 * Handoff extension - transfer context to a new focused session
 *
 * Instead of compacting (which is lossy), handoff extracts what matters
 * for your next task and creates a new session with a generated prompt.
 *
 * Provides both:
 * - /handoff command: user types `/handoff <goal>`
 * - handoff tool: agent can call when user explicitly requests a handoff
 *
 * Usage:
 *   /handoff now implement this for teams as well
 *   /handoff execute phase one of the plan
 *   /handoff check other places that need this fix
 */

import { complete, type Message } from "@mariozechner/pi-ai";
import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext, SessionEntry } from "@mariozechner/pi-coding-agent";
import { BorderedLoader, convertToLlm, serializeConversation } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { completePendingHandoff, finalizeGeneratedHandoff, queueToolHandoff } from "./flow.js";
import { createPendingHandoffStore } from "./pending.js";
import { buildFinalPrompt, buildInitialUserMessage } from "./prompt.js";

const SYSTEM_PROMPT = `You are a context transfer assistant. Given a conversation history and the user's goal for a new thread, generate a focused prompt that:

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

async function createHandoffSession(
	ctx: ExtensionCommandContext,
	parentSession: string | undefined,
	finalPrompt: string,
): Promise<{ cancelled: boolean }> {
	return ctx.newSession({
		parentSession,
		setup: async (sm) => {
			sm.appendMessage(buildInitialUserMessage(finalPrompt));
		},
	});
}

async function performHandoff(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	goal: string,
	pendingStore: ReturnType<typeof createPendingHandoffStore>,
	fromTool = false,
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

	const llmMessages = convertToLlm(messages);
	const conversationText = serializeConversation(llmMessages);
	const currentSessionFile = ctx.sessionManager.getSessionFile();

	const generatedPrompt = await ctx.ui.custom<string | null>((tui, theme, _kb, done) => {
		const loader = new BorderedLoader(tui, theme, `Generating handoff prompt...`);
		loader.onAbort = () => done(null);

		const doGenerate = async () => {
			const auth = await ctx.modelRegistry.getApiKeyAndHeaders(ctx.model!);
			if (!auth.ok || !auth.apiKey) {
				throw new Error(auth.ok ? `No API key for ${ctx.model!.provider}` : auth.error);
			}

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
				ctx.model!,
				{ systemPrompt: SYSTEM_PROMPT, messages: [userMessage] },
				{ apiKey: auth.apiKey, headers: auth.headers, signal: loader.signal },
			);

			if (response.stopReason === "aborted") {
				return null;
			}

			return response.content
				.filter((c): c is { type: "text"; text: string } => c.type === "text")
				.map((c) => c.text)
				.join("\n");
		};

		doGenerate()
			.then(done)
			.catch((err) => {
				console.error("Handoff generation failed:", err);
				done(null);
			});

		return loader;
	});

	const finalPrompt = buildFinalPrompt({
		goal,
		generatedPrompt: generatedPrompt ?? "",
		parentSession: currentSessionFile,
	});
	const finalized = finalizeGeneratedHandoff({ generatedPrompt, finalPrompt });
	if (!finalized.ok) {
		return "Handoff cancelled.";
	}

	if (!fromTool && "newSession" in ctx) {
		const result = await createHandoffSession(ctx as ExtensionCommandContext, currentSessionFile, finalized.finalPrompt);
		if (result.cancelled) return;
		ctx.ui.notify("Handoff created in the new session.", "info");
		return undefined;
	}

	const queued = queueToolHandoff(
		pendingStore,
		{ finalPrompt: finalized.finalPrompt, parentSession: currentSessionFile },
		(message, options) => {
			pi.sendUserMessage(message, options);
		},
	);
	if (!queued.ok) {
		return queued.error;
	}

	return undefined;
}

export default function (pi: ExtensionAPI) {
	const pendingStore = createPendingHandoffStore();

	pi.registerCommand("handoff", {
		description: "Transfer context to a new focused session",
		handler: async (args, ctx) => {
			const goal = args.trim();
			if (!goal) {
				ctx.ui.notify("Usage: /handoff <goal for new thread>", "error");
				return;
			}

			const error = await performHandoff(pi, ctx, goal, pendingStore);
			if (error) {
				ctx.ui.notify(error, "error");
			}
		},
	});

	pi.registerCommand("__handoff-complete", {
		description: "Complete a pending handoff",
		handler: async (_args, ctx) => {
			const result = await completePendingHandoff(pendingStore, async (pending) => {
				return createHandoffSession(ctx, pending.parentSession, pending.finalPrompt);
			});
			if (!result.ok) {
				ctx.ui.notify(result.error, "error");
				return;
			}
			if (!result.cancelled) {
				ctx.ui.notify("Handoff created in the new session.", "info");
			}
		},
	});

	pi.registerTool({
		name: "handoff",
		label: "Handoff",
		description:
			"Transfer context to a new focused session. ONLY use this when the user explicitly asks for a handoff. Provide a goal describing what the new session should focus on.",
		parameters: Type.Object({
			goal: Type.String({ description: "The goal/task for the new session" }),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const error = await performHandoff(pi, ctx, params.goal, pendingStore, true);
			return {
				content: [{ type: "text", text: error ?? "Queued /__handoff-complete as a follow-up command." }],
				details: { ok: error === undefined },
			};
		},
	});
}
