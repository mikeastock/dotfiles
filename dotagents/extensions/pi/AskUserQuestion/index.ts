/**
 * AskUserQuestion Extension - Let the LLM ask the user a question with options
 */

import type { ExtensionAPI, ExtensionContext, ToolRenderResultOptions, Theme } from "@mariozechner/pi-coding-agent";
import { Text } from "@mariozechner/pi-tui";
import { Type, type Static } from "@sinclair/typebox";

interface QuestionDetails {
	question: string;
	options: string[];
	answer: string | null;
	isCustom?: boolean;
}

const CUSTOM_OPTION = "✏️  Enter custom response...";

const QuestionParams = Type.Object({
	question: Type.String({ description: "The question to ask the user" }),
	options: Type.Array(Type.String(), { description: "Options for the user to choose from" }),
	allowCustom: Type.Optional(Type.Boolean({ description: "If true, adds an option for the user to enter a custom response" })),
});

type QuestionParamsType = Static<typeof QuestionParams>;

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "AskUserQuestion",
		label: "Ask User Question",
		description: "Ask the user a question and let them pick from options. Use when you need user input to proceed.",
		parameters: QuestionParams,

		async execute(_toolCallId: string, params: QuestionParamsType, _onUpdate, ctx: ExtensionContext, _signal?: AbortSignal) {
			if (!ctx.hasUI) {
				return {
					content: [{ type: "text", text: "Error: UI not available (running in non-interactive mode)" }],
					details: { question: params.question, options: params.options, answer: null },
				};
			}

			if (params.options.length === 0 && !params.allowCustom) {
				return {
					content: [{ type: "text", text: "Error: No options provided" }],
					details: { question: params.question, options: [], answer: null },
				};
			}

			// Build options list, adding custom option if allowed
			const displayOptions = params.allowCustom
				? [...params.options, CUSTOM_OPTION]
				: params.options;

			const answer = await ctx.ui.select(params.question, displayOptions);

			if (answer === undefined) {
				return {
					content: [{ type: "text", text: "User cancelled the selection" }],
					details: { question: params.question, options: params.options, answer: null },
				};
			}

			// Handle custom response
			if (answer === CUSTOM_OPTION) {
				const customAnswer = await ctx.ui.input("Enter your response", "Type your answer here...");

				if (customAnswer === undefined || customAnswer === null || customAnswer.trim() === "") {
					return {
						content: [{ type: "text", text: "User cancelled the custom response" }],
						details: { question: params.question, options: params.options, answer: null },
					};
				}

				return {
					content: [{ type: "text", text: `User entered custom response: ${customAnswer}` }],
					details: { question: params.question, options: params.options, answer: customAnswer, isCustom: true },
				};
			}

			return {
				content: [{ type: "text", text: `User selected: ${answer}` }],
				details: { question: params.question, options: params.options, answer },
			};
		},

		renderCall(args: { question: string; options?: string[]; allowCustom?: boolean }, theme: Theme) {
			let text = theme.fg("toolTitle", theme.bold("Ask User Question ")) + theme.fg("muted", args.question);
			if (args.options?.length) {
				text += `\n${theme.fg("dim", `  Options: ${args.options.join(", ")}`)}`;
			}
			if (args.allowCustom) {
				text += `\n${theme.fg("dim", `  (custom response allowed)`)}`;
			}
			return new Text(text, 0, 0);
		},

		renderResult(result, _options: ToolRenderResultOptions, theme: Theme) {
			const typedResult = result as { content: Array<{ type: string; text?: string }>; details?: QuestionDetails };
			const { details } = typedResult;
			if (!details) {
				const text = typedResult.content[0];
				return new Text(text?.type === "text" ? (text.text ?? "") : "", 0, 0);
			}

			if (details.answer === null) {
				return new Text(theme.fg("warning", "Cancelled"), 0, 0);
			}

			const prefix = details.isCustom
				? theme.fg("success", "✓ ") + theme.fg("muted", "(custom) ")
				: theme.fg("success", "✓ ");
			return new Text(prefix + theme.fg("accent", details.answer), 0, 0);
		},
	});
}
