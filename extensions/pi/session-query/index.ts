/**
 * Session Query Extension - Query previous pi sessions
 *
 * Provides a tool the model can use to query past sessions for context,
 * decisions, code changes, or other information.
 *
 * Works with handoff: when a handoff prompt includes "Parent session: <path>",
 * the model can use this tool to look up details from that session.
 */

import { complete, type Message } from "@mariozechner/pi-ai";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import {
	SessionManager,
	convertToLlm,
	getMarkdownTheme,
	serializeConversation,
	type SessionEntry,
} from "@mariozechner/pi-coding-agent";
import { Container, Markdown, Spacer, Text } from "@mariozechner/pi-tui";
import { Type } from "@sinclair/typebox";

const QUERY_SYSTEM_PROMPT = `You are a session context assistant. Given the conversation history from a pi coding session and a question, provide a concise answer based on the session contents.

Focus on:
- Specific facts, decisions, and outcomes
- File paths and code changes mentioned
- Key context the user is asking about

Rules:
- Never return an empty answer.
- If the provided session excerpt is truncated, mention that briefly and answer from available context.
- If the answer is not in the provided context, say that clearly.

Be concise and direct.`;

const MAX_CONVERSATION_CHARS = 180_000;
const CONTEXT_HEAD_CHARS = 40_000;
const CONTEXT_TAIL_CHARS = MAX_CONVERSATION_CHARS - CONTEXT_HEAD_CHARS;

const MAX_MESSAGES_FOR_FULL_CONTEXT = 400;
const MAX_SELECTED_MESSAGES = 220;
const PINNED_HEAD_MESSAGES = 8;
const PINNED_TAIL_MESSAGES = 90;
const CONTEXT_WINDOW = 2;
const MAX_KEYWORDS = 16;

const STOP_WORDS = new Set([
	"a",
	"an",
	"and",
	"are",
	"as",
	"at",
	"be",
	"but",
	"by",
	"did",
	"do",
	"does",
	"for",
	"from",
	"had",
	"has",
	"have",
	"how",
	"i",
	"if",
	"in",
	"is",
	"it",
	"its",
	"me",
	"my",
	"no",
	"not",
	"of",
	"on",
	"or",
	"our",
	"please",
	"show",
	"that",
	"the",
	"their",
	"them",
	"there",
	"these",
	"they",
	"this",
	"to",
	"up",
	"us",
	"was",
	"we",
	"were",
	"what",
	"when",
	"where",
	"which",
	"who",
	"why",
	"with",
	"you",
	"your",
]);

type AgentMessage = Parameters<typeof convertToLlm>[0][number];

function clampConversationText(text: string): { text: string; truncated: boolean } {
	if (text.length <= MAX_CONVERSATION_CHARS) {
		return { text, truncated: false };
	}

	const omitted = text.length - MAX_CONVERSATION_CHARS;
	const clampedText = [
		"[session-query note] Session content was truncated for model context.",
		`[session-query note] Omitted approximately ${omitted} characters from the middle.`,
		"",
		text.slice(0, CONTEXT_HEAD_CHARS),
		"",
		"[...truncated middle content...]",
		"",
		text.slice(-CONTEXT_TAIL_CHARS),
	].join("\n");

	return { text: clampedText, truncated: true };
}

function parseMessagesFromJsonl(sessionPath: string): AgentMessage[] {
	try {
		const fs = require("node:fs") as typeof import("node:fs");
		const raw = fs.readFileSync(sessionPath, "utf8");
		const lines = raw.split("\n");
		const parsed: AgentMessage[] = [];

		for (const line of lines) {
			if (!line.trim()) continue;
			const entry = JSON.parse(line) as { type?: string; message?: AgentMessage };
			if (entry.type === "message" && entry.message) {
				parsed.push(entry.message);
			}
		}

		return parsed;
	} catch {
		return [];
	}
}

function extractKeywords(question: string): string[] {
	const tokens = question.toLowerCase().match(/[a-z0-9_./:-]{3,}/g) ?? [];
	const unique: string[] = [];
	for (const token of tokens) {
		if (STOP_WORDS.has(token)) continue;
		if (unique.includes(token)) continue;
		unique.push(token);
		if (unique.length >= MAX_KEYWORDS) break;
	}
	return unique;
}

function stringifyMessage(message: AgentMessage): string {
	try {
		return JSON.stringify(message).toLowerCase();
	} catch {
		return "";
	}
}

function getRole(message: AgentMessage): string {
	if (typeof message === "object" && message && "role" in message) {
		const role = (message as { role?: unknown }).role;
		if (typeof role === "string") return role;
	}
	return "";
}

function selectRelevantMessages(
	messages: AgentMessage[],
	question: string,
): { selected: AgentMessage[]; strategy: string; keywordCount: number } {
	if (messages.length <= MAX_MESSAGES_FOR_FULL_CONTEXT) {
		return { selected: messages, strategy: "full", keywordCount: 0 };
	}

	const keywords = extractKeywords(question);
	const selected = new Set<number>();

	for (let i = 0; i < Math.min(PINNED_HEAD_MESSAGES, messages.length); i++) {
		selected.add(i);
	}
	for (let i = Math.max(0, messages.length - PINNED_TAIL_MESSAGES); i < messages.length; i++) {
		selected.add(i);
	}

	const scored: Array<{ index: number; score: number }> = [];
	for (let i = 0; i < messages.length; i++) {
		const haystack = stringifyMessage(messages[i]);
		if (!haystack) continue;

		let score = 0;
		for (const keyword of keywords) {
			if (haystack.includes(keyword)) {
				score += keyword.length >= 6 ? 2 : 1;
			}
		}

		if (score > 0 && getRole(messages[i]) === "user") {
			score += 1;
		}

		if (score > 0) {
			scored.push({ index: i, score });
		}
	}

	scored.sort((a, b) => b.score - a.score || b.index - a.index);

	for (const item of scored) {
		if (selected.size >= MAX_SELECTED_MESSAGES) break;
		for (let delta = -CONTEXT_WINDOW; delta <= CONTEXT_WINDOW; delta++) {
			const idx = item.index + delta;
			if (idx < 0 || idx >= messages.length) continue;
			selected.add(idx);
			if (selected.size >= MAX_SELECTED_MESSAGES) break;
		}
	}

	for (let i = messages.length - 1; i >= 0 && selected.size < MAX_SELECTED_MESSAGES; i--) {
		selected.add(i);
	}

	const selectedIndexes = Array.from(selected).sort((a, b) => a - b);
	const filtered = selectedIndexes.map((index) => messages[index]);

	return {
		selected: filtered,
		strategy: keywords.length > 0 ? "keyword_window" : "head_tail_window",
		keywordCount: keywords.length,
	};
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "session_query",
		label: "Session Query",
		description:
			"Query a previous pi session file for context, decisions, or information. Use when you need to look up what happened in a parent session or any other session.",
		renderResult: (result, _options, theme) => {
			const container = new Container();
			const textContent = result.content.find(
				(item): item is { type: "text"; text: string } => item.type === "text",
			);

			if (textContent?.text) {
				const text = textContent.text;
				const match = text.match(/\*\*Query:\*\* (.+?)\n\n---\n\n([\s\S]+)/);

				if (match) {
					const [, query, answer] = match;
					container.addChild(new Text(theme.bold("Query: ") + theme.fg("accent", query), 0, 0));
					container.addChild(new Spacer(1));
					container.addChild(new Markdown(answer.trim(), 0, 0, getMarkdownTheme(), {
						color: (text: string) => theme.fg("toolOutput", text),
					}));
				} else {
					container.addChild(new Text(theme.fg("toolOutput", text), 0, 0));
				}
			}

			return container;
		},
		parameters: Type.Object({
			sessionPath: Type.String({
				description: "Full path to the session file (e.g., /home/user/.pi/agent/sessions/.../session.jsonl)",
			}),
			question: Type.String({
				description: "What you want to know about that session (e.g., 'What files were modified?' or 'What approach was chosen?')",
			}),
		}),

		async execute(toolCallId, params, signal, onUpdate, ctx) {
			const { sessionPath, question } = params;

			const errorResult = (text: string) => ({
				content: [{ type: "text" as const, text }],
				details: { error: true },
			});

			if (!sessionPath.endsWith(".jsonl")) {
				return errorResult(`Error: Invalid session path. Expected a .jsonl file, got: ${sessionPath}`);
			}

			try {
				const fs = await import("node:fs");
				if (!fs.existsSync(sessionPath)) {
					return errorResult(`Error: Session file not found: ${sessionPath}`);
				}
			} catch (err) {
				return errorResult(`Error checking session file: ${err}`);
			}

			onUpdate?.({
				content: [
					{
						type: "text",
						text: `Query: ${question}`,
					},
				],
				details: { status: "loading", question },
			});

			let sessionManager: SessionManager;
			try {
				sessionManager = SessionManager.open(sessionPath);
			} catch (err) {
				return errorResult(`Error loading session: ${err}`);
			}

			const branch = sessionManager.getBranch();
			let messages: AgentMessage[] = branch
				.filter((entry): entry is SessionEntry & { type: "message" } => entry.type === "message")
				.map((entry) => entry.message as AgentMessage);

			let usedJsonlFallback = false;
			if (messages.length === 0) {
				const parsedMessages = parseMessagesFromJsonl(sessionPath);
				if (parsedMessages.length > 0) {
					messages = parsedMessages;
					usedJsonlFallback = true;
				}
			}

			if (messages.length === 0) {
				return {
					content: [{ type: "text" as const, text: "Session is empty - no messages found." }],
					details: { empty: true },
				};
			}

			const { selected, strategy, keywordCount } = selectRelevantMessages(messages, question);
			const llmMessages = convertToLlm(selected);
			const conversationText = serializeConversation(llmMessages);
			const { text: boundedConversationText, truncated } = clampConversationText(conversationText);

			if (!ctx.model) {
				return errorResult("Error: No model available to analyze the session.");
			}

			try {
				const apiKey = await ctx.modelRegistry.getApiKey(ctx.model);

				const userMessage: Message = {
					role: "user",
					content: [
						{
							type: "text",
							text: `## Session Conversation\n\n${boundedConversationText}\n\n## Question\n\n${question}`,
						},
					],
					timestamp: Date.now(),
				};

				const response = await complete(
					ctx.model,
					{ systemPrompt: QUERY_SYSTEM_PROMPT, messages: [userMessage] },
					{ apiKey, signal },
				);

				if (response.stopReason === "aborted") {
					return {
						content: [{ type: "text" as const, text: "Query was cancelled." }],
						details: { cancelled: true },
					};
				}

				if (response.stopReason === "error") {
					return errorResult(`Error querying session: ${response.errorMessage || "Unknown model error"}`);
				}

				const answer = response.content
					.filter((c): c is { type: "text"; text: string } => c.type === "text")
					.map((c) => c.text)
					.join("\n")
					.trim();

				const safeAnswer =
					answer.length > 0
						? answer
						: "I could not extract a textual answer from the model response. Try a narrower question or re-run the query.";

				return {
					content: [{ type: "text" as const, text: `**Query:** ${question}\n\n---\n\n${safeAnswer}` }],
					details: {
						sessionPath,
						question,
						messageCount: messages.length,
						selectedMessageCount: selected.length,
						retrievalStrategy: strategy,
						keywordCount,
						truncated,
						usedJsonlFallback,
					},
				};
			} catch (err) {
				return errorResult(`Error querying session: ${err}`);
			}
		},
	});
}
