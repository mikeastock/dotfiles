/**
 * Handoff extension - transfer context to a new focused session
 *
 * Instead of compacting (which is lossy), handoff extracts what matters
 * for your next task and creates a new session with a generated prompt.
 *
 * Usage:
 *   /handoff now implement this for teams as well
 *   /handoff execute phase one of the plan
 *   /handoff check other places that need this fix
 *
 * Based on: https://github.com/pasky/pi-amplike
 */

import { complete, type Message } from "@mariozechner/pi-ai";
import type { ExtensionAPI, SessionEntry } from "@mariozechner/pi-coding-agent";
import { BorderedLoader, convertToLlm, serializeConversation } from "@mariozechner/pi-coding-agent";

const SYSTEM_PROMPT = `You are a context transfer assistant. Given a conversation history and the user's goal for a new thread, extract only the context needed to continue the work. Do not restate the goal or write new instructions.

Return markdown sections with concise bullets. Omit any section that has no content.

Required sections (when applicable):
- ## Context (key work done, approaches, findings)
- ## Decisions (tradeoffs, choices made)
- ## Commands Run (shell/tool invocations worth reusing)
- ## Open Questions (unknowns, blockers, follow-ups)
- ## Files (paths mentioned or modified)

Rules:
- Be concise and factual.
- Only list files that are mentioned in the conversation.
- Do not include a Task/Goal section or any preamble. The user goal will be appended separately.`;

const VAGUE_GOAL_PATTERNS = [
	/^continue$/i,
	/^continue\s+this$/i,
	/^continue\s+work$/i,
	/^continue\s+from\s+here$/i,
	/^keep\s+going$/i,
	/^go\s+on$/i,
	/^resume$/i,
	/^fix$/i,
	/^fix\s+this$/i,
	/^fix\s+it$/i,
	/^finish$/i,
	/^finish\s+this$/i,
	/^next$/i,
	/^same$/i,
	/^todo$/i,
	/^tbd$/i,
];

const isVagueGoal = (goal: string) => {
	const normalized = goal.trim().toLowerCase();
	const words = normalized.split(/\s+/).filter(Boolean);
	if (words.length < 3) {
		return true;
	}

	return VAGUE_GOAL_PATTERNS.some((pattern) => pattern.test(normalized));
};

export default function (pi: ExtensionAPI) {
	pi.registerCommand("handoff", {
		description: "Transfer context to a new focused session",
		handler: async (args, ctx) => {
			if (!ctx.hasUI) {
				ctx.ui.notify("handoff requires interactive mode", "error");
				return;
			}

			if (!ctx.model) {
				ctx.ui.notify("No model selected", "error");
				return;
			}

			const goal = args.trim();
			if (!goal) {
				ctx.ui.notify("Usage: /handoff <goal for new thread>", "error");
				return;
			}

			if (isVagueGoal(goal)) {
				ctx.ui.notify(
					"Goal looks too vague for a useful handoff. Provide a specific next task (what and where), e.g. /handoff add OAuth support to core/src/mcp/oauth.",
					"error",
				);
				return;
			}

			// Gather conversation context from current branch
			const branch = ctx.sessionManager.getBranch();
			const messages = branch
				.filter((entry): entry is SessionEntry & { type: "message" } => entry.type === "message")
				.map((entry) => entry.message);

			if (messages.length === 0) {
				ctx.ui.notify("No conversation to hand off", "error");
				return;
			}

			// Convert to LLM format and serialize
			const llmMessages = convertToLlm(messages);
			const conversationText = serializeConversation(llmMessages);
			const currentSessionFile = ctx.sessionManager.getSessionFile();

			// Generate the handoff prompt with loader UI
			const result = await ctx.ui.custom<string | null>((tui, theme, _kb, done) => {
				const loader = new BorderedLoader(tui, theme, `Generating handoff prompt...`);
				loader.onAbort = () => done(null);

				const doGenerate = async () => {
					const apiKey = await ctx.modelRegistry.getApiKey(ctx.model!);

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
						{ apiKey, signal: loader.signal },
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

			if (result === null) {
				ctx.ui.notify("Cancelled", "info");
				return;
			}

			// Create new session with parent tracking
			const newSessionResult = await ctx.newSession({
				parentSession: currentSessionFile,
			});

			if (newSessionResult.cancelled) {
				ctx.ui.notify("New session cancelled", "info");
				return;
			}

			// Build the final prompt with user's goal first for easy identification
			// Format: goal (session preview) → skill → parent ref → context → goal section
			const contextSection = result.trim();
			const goalSection = `## Goal\n${goal}`;
			const promptParts: string[] = [goal];

			if (currentSessionFile) {
				promptParts.push("/skill:session-query", `**Parent session:** \`${currentSessionFile}\``);
			}

			if (contextSection) {
				promptParts.push(contextSection);
			}

			promptParts.push(goalSection);

			// Immediately submit the handoff prompt to start the agent
			pi.sendUserMessage(promptParts.join("\n\n"));
		},
	});
}
