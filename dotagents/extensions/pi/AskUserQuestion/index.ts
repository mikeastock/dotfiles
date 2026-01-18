/**
 * AskUserQuestion Extension - Ask the user questions with single/multi select or free input
 *
 * Modes:
 * - single: Pick one option from a list (with optional custom input)
 * - multi: Pick multiple options via checkboxes (with optional custom input)
 * - input: Free text input only (no options)
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { StringEnum } from "@mariozechner/pi-ai";
import { Editor, type EditorTheme, Key, matchesKey, Text, truncateToWidth } from "@mariozechner/pi-tui";
import { Type } from "@sinclair/typebox";

interface OptionWithDesc {
	label: string;
	description?: string;
}

type DisplayOption = OptionWithDesc & { isOther?: boolean };

interface QuestionDetails {
	mode: "single" | "multi" | "input";
	question: string;
	options: string[];
	answer: string | string[] | null;
	customAnswer?: string;
}

// Support both simple strings and objects with descriptions
const OptionSchema = Type.Union([
	Type.String(),
	Type.Object({
		label: Type.String({ description: "Display label for the option" }),
		description: Type.Optional(Type.String({ description: "Optional description shown below label" })),
	}),
]);

const QuestionParams = Type.Object({
	mode: StringEnum(["single", "multi", "input"] as const, {
		description: "single: pick one, multi: pick many with checkboxes, input: free text only",
	}),
	question: Type.String({ description: "The question to ask the user" }),
	options: Type.Optional(Type.Array(OptionSchema, { description: "Options for the user to choose from (ignored for input mode)" })),
	allowCustom: Type.Optional(Type.Boolean({ description: "Allow custom text input in addition to options (default: true for single/multi)" })),
});

// Normalize option to { label, description? }
function normalizeOption(opt: string | { label: string; description?: string }): OptionWithDesc {
	if (typeof opt === "string") {
		return { label: opt };
	}
	return opt;
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "AskUserQuestion",
		label: "Ask User Question",
		description: "Ask the user a question. Modes: single (pick one), multi (pick many with checkboxes), input (free text). Use when you need user input to proceed.",
		parameters: QuestionParams,

		async execute(_toolCallId, params, _onUpdate, ctx, _signal) {
			const mode = params.mode;
			const allowCustom = params.allowCustom !== false; // default true
			const options = params.options ?? [];

			if (!ctx.hasUI) {
				return {
					content: [{ type: "text", text: "Error: UI not available (running in non-interactive mode)" }],
					details: {
						mode,
						question: params.question,
						options: options.map((o) => (typeof o === "string" ? o : o.label)),
						answer: null,
					} as QuestionDetails,
				};
			}

			// Input mode: just show text input
			if (mode === "input") {
				const result = await ctx.ui.custom<{ answer: string } | null>((tui, theme, _kb, done) => {
					let cachedLines: string[] | undefined;

					const editorTheme: EditorTheme = {
						borderColor: (s) => theme.fg("accent", s),
						selectList: {
							selectedPrefix: (t) => theme.fg("accent", t),
							selectedText: (t) => theme.fg("accent", t),
							description: (t) => theme.fg("muted", t),
							scrollInfo: (t) => theme.fg("dim", t),
							noMatch: (t) => theme.fg("warning", t),
						},
					};
					const editor = new Editor(tui, editorTheme);

					editor.onSubmit = (value) => {
						const trimmed = value.trim();
						if (trimmed) {
							done({ answer: trimmed });
						}
					};

					function refresh() {
						cachedLines = undefined;
						tui.requestRender();
					}

					function handleInput(data: string) {
						if (matchesKey(data, Key.escape)) {
							done(null);
							return;
						}
						editor.handleInput(data);
						refresh();
					}

					function render(width: number): string[] {
						if (cachedLines) return cachedLines;

						const lines: string[] = [];
						const add = (s: string) => lines.push(truncateToWidth(s, width));

						add(theme.fg("accent", "─".repeat(width)));
						add(theme.fg("text", ` ${params.question}`));
						lines.push("");
						add(theme.fg("muted", " Your answer:"));
						for (const line of editor.render(width - 2)) {
							add(` ${line}`);
						}
						lines.push("");
						add(theme.fg("dim", " Enter to submit • Esc to cancel"));
						add(theme.fg("accent", "─".repeat(width)));

						cachedLines = lines;
						return lines;
					}

					return {
						render,
						invalidate: () => { cachedLines = undefined; },
						handleInput,
					};
				});

				if (!result) {
					return {
						content: [{ type: "text", text: "User cancelled" }],
						details: { mode, question: params.question, options: [], answer: null } as QuestionDetails,
					};
				}

				return {
					content: [{ type: "text", text: `User wrote: ${result.answer}` }],
					details: { mode, question: params.question, options: [], answer: result.answer } as QuestionDetails,
				};
			}

			// Single/Multi mode requires options
			if (options.length === 0 && !allowCustom) {
				return {
					content: [{ type: "text", text: "Error: No options provided and custom input disabled" }],
					details: { mode, question: params.question, options: [], answer: null } as QuestionDetails,
				};
			}

			const normalizedOptions = options.map(normalizeOption);
			const allOptions: DisplayOption[] = [...normalizedOptions];
			if (allowCustom) {
				allOptions.push({ label: "Type something.", isOther: true });
			}

			// Multi-select mode
			if (mode === "multi") {
				const result = await ctx.ui.custom<{ selected: string[]; customAnswer?: string } | null>(
					(tui, theme, _kb, done) => {
						let optionIndex = 0;
						let editMode = false;
						let customValue = "";
						const checked = new Set<number>();
						let cachedLines: string[] | undefined;

						const editorTheme: EditorTheme = {
							borderColor: (s) => theme.fg("accent", s),
							selectList: {
								selectedPrefix: (t) => theme.fg("accent", t),
								selectedText: (t) => theme.fg("accent", t),
								description: (t) => theme.fg("muted", t),
								scrollInfo: (t) => theme.fg("dim", t),
								noMatch: (t) => theme.fg("warning", t),
							},
						};
						const editor = new Editor(tui, editorTheme);

						editor.onSubmit = (value) => {
							const trimmed = value.trim();
							if (trimmed) {
								customValue = trimmed;
							}
							editMode = false;
							editor.setText("");
							refresh();
						};

						function refresh() {
							cachedLines = undefined;
							tui.requestRender();
						}

						function submit() {
							const selected = Array.from(checked)
								.filter((i) => !allOptions[i].isOther)
								.map((i) => allOptions[i].label);
							done({ selected, customAnswer: customValue || undefined });
						}

						function handleInput(data: string) {
							if (editMode) {
								if (matchesKey(data, Key.escape)) {
									editMode = false;
									editor.setText("");
									refresh();
									return;
								}
								editor.handleInput(data);
								refresh();
								return;
							}

							if (matchesKey(data, Key.up)) {
								optionIndex = Math.max(0, optionIndex - 1);
								refresh();
								return;
							}
							if (matchesKey(data, Key.down)) {
								optionIndex = Math.min(allOptions.length, optionIndex + 1); // +1 for Submit
								refresh();
								return;
							}

							// Space toggles checkbox
							if (matchesKey(data, Key.space)) {
								if (optionIndex < allOptions.length) {
									const opt = allOptions[optionIndex];
									if (opt.isOther) {
										editMode = true;
										editor.setText(customValue);
									} else if (checked.has(optionIndex)) {
										checked.delete(optionIndex);
									} else {
										checked.add(optionIndex);
									}
									refresh();
								}
								return;
							}

							// Enter submits (or opens editor for "Type something")
							if (matchesKey(data, Key.enter)) {
								if (optionIndex < allOptions.length) {
									const opt = allOptions[optionIndex];
									if (opt.isOther) {
										editMode = true;
										editor.setText(customValue);
										refresh();
										return;
									}
								}
								// Submit from any row
								submit();
								return;
							}

							if (matchesKey(data, Key.escape)) {
								done(null);
							}
						}

						function render(width: number): string[] {
							if (cachedLines) return cachedLines;

							const lines: string[] = [];
							const add = (s: string) => lines.push(truncateToWidth(s, width));

							add(theme.fg("accent", "─".repeat(width)));
							add(theme.fg("text", ` ${params.question}`));
							lines.push("");

							for (let i = 0; i < allOptions.length; i++) {
								const opt = allOptions[i];
								const selected = i === optionIndex;
								const isOther = opt.isOther === true;
								const isChecked = checked.has(i) || (isOther && customValue);
								const prefix = selected ? theme.fg("accent", "> ") : "  ";

								let checkbox: string;
								if (isOther) {
									checkbox = customValue ? theme.fg("success", "[✓]") : theme.fg("muted", "[ ]");
								} else {
									checkbox = isChecked ? theme.fg("success", "[✓]") : theme.fg("muted", "[ ]");
								}

								let label: string;
								if (isOther && editMode) {
									label = theme.fg("accent", `${opt.label} ✎`);
								} else if (isOther && customValue) {
									label = theme.fg("text", `${opt.label}`) + theme.fg("muted", ` → "${customValue}"`);
								} else if (selected) {
									label = theme.fg("accent", opt.label);
								} else {
									label = theme.fg("text", opt.label);
								}

								add(`${prefix}${checkbox} ${i + 1}. ${label}`);

								if (opt.description) {
									add(`       ${theme.fg("muted", opt.description)}`);
								}
							}

							// Submit row
							const onSubmitRow = optionIndex === allOptions.length;
							const submitPrefix = onSubmitRow ? theme.fg("accent", "> ") : "  ";
							const selectedCount = checked.size + (customValue ? 1 : 0);
							const submitLabel = onSubmitRow
								? theme.fg("accent", theme.bold("Submit"))
								: theme.fg("muted", "Submit");
							add(`${submitPrefix}  ${submitLabel}` + theme.fg("dim", ` (${selectedCount} selected)`));

							if (editMode) {
								lines.push("");
								add(theme.fg("muted", " Your answer:"));
								for (const line of editor.render(width - 2)) {
									add(` ${line}`);
								}
								lines.push("");
								add(theme.fg("dim", " Enter to confirm • Esc to go back"));
							} else {
								lines.push("");
								add(theme.fg("dim", " ↑↓ navigate • Space toggle • Enter submit • Esc cancel"));
							}
							add(theme.fg("accent", "─".repeat(width)));

							cachedLines = lines;
							return lines;
						}

						return {
							render,
							invalidate: () => { cachedLines = undefined; },
							handleInput,
						};
					},
				);

				const simpleOptions = normalizedOptions.map((o) => o.label);

				if (!result) {
					return {
						content: [{ type: "text", text: "User cancelled" }],
						details: { mode, question: params.question, options: simpleOptions, answer: null } as QuestionDetails,
					};
				}

				const allSelected = result.customAnswer
					? [...result.selected, result.customAnswer]
					: result.selected;

				if (allSelected.length === 0) {
					return {
						content: [{ type: "text", text: "User selected nothing" }],
						details: { mode, question: params.question, options: simpleOptions, answer: [], customAnswer: result.customAnswer } as QuestionDetails,
					};
				}

				return {
					content: [{ type: "text", text: `User selected: ${allSelected.join(", ")}` }],
					details: { mode, question: params.question, options: simpleOptions, answer: result.selected, customAnswer: result.customAnswer } as QuestionDetails,
				};
			}

			// Single-select mode
			const result = await ctx.ui.custom<{ answer: string; wasCustom: boolean; index?: number } | null>(
				(tui, theme, _kb, done) => {
					let optionIndex = 0;
					let editMode = false;
					let cachedLines: string[] | undefined;

					const editorTheme: EditorTheme = {
						borderColor: (s) => theme.fg("accent", s),
						selectList: {
							selectedPrefix: (t) => theme.fg("accent", t),
							selectedText: (t) => theme.fg("accent", t),
							description: (t) => theme.fg("muted", t),
							scrollInfo: (t) => theme.fg("dim", t),
							noMatch: (t) => theme.fg("warning", t),
						},
					};
					const editor = new Editor(tui, editorTheme);

					editor.onSubmit = (value) => {
						const trimmed = value.trim();
						if (trimmed) {
							done({ answer: trimmed, wasCustom: true });
						} else {
							editMode = false;
							editor.setText("");
							refresh();
						}
					};

					function refresh() {
						cachedLines = undefined;
						tui.requestRender();
					}

					function handleInput(data: string) {
						if (editMode) {
							if (matchesKey(data, Key.escape)) {
								editMode = false;
								editor.setText("");
								refresh();
								return;
							}
							editor.handleInput(data);
							refresh();
							return;
						}

						if (matchesKey(data, Key.up)) {
							optionIndex = Math.max(0, optionIndex - 1);
							refresh();
							return;
						}
						if (matchesKey(data, Key.down)) {
							optionIndex = Math.min(allOptions.length - 1, optionIndex + 1);
							refresh();
							return;
						}

						if (matchesKey(data, Key.enter)) {
							const selected = allOptions[optionIndex];
							if (selected.isOther) {
								editMode = true;
								refresh();
							} else {
								done({ answer: selected.label, wasCustom: false, index: optionIndex + 1 });
							}
							return;
						}

						if (matchesKey(data, Key.escape)) {
							done(null);
						}
					}

					function render(width: number): string[] {
						if (cachedLines) return cachedLines;

						const lines: string[] = [];
						const add = (s: string) => lines.push(truncateToWidth(s, width));

						add(theme.fg("accent", "─".repeat(width)));
						add(theme.fg("text", ` ${params.question}`));
						lines.push("");

						for (let i = 0; i < allOptions.length; i++) {
							const opt = allOptions[i];
							const selected = i === optionIndex;
							const isOther = opt.isOther === true;
							const prefix = selected ? theme.fg("accent", "> ") : "  ";

							if (isOther && editMode) {
								add(prefix + theme.fg("accent", `${i + 1}. ${opt.label} ✎`));
							} else if (selected) {
								add(prefix + theme.fg("accent", `${i + 1}. ${opt.label}`));
							} else {
								add(`  ${theme.fg("text", `${i + 1}. ${opt.label}`)}`);
							}

							if (opt.description) {
								add(`     ${theme.fg("muted", opt.description)}`);
							}
						}

						if (editMode) {
							lines.push("");
							add(theme.fg("muted", " Your answer:"));
							for (const line of editor.render(width - 2)) {
								add(` ${line}`);
							}
						}

						lines.push("");
						if (editMode) {
							add(theme.fg("dim", " Enter to submit • Esc to go back"));
						} else {
							add(theme.fg("dim", " ↑↓ navigate • Enter to select • Esc to cancel"));
						}
						add(theme.fg("accent", "─".repeat(width)));

						cachedLines = lines;
						return lines;
					}

					return {
						render,
						invalidate: () => { cachedLines = undefined; },
						handleInput,
					};
				},
			);

			const simpleOptions = normalizedOptions.map((o) => o.label);

			if (!result) {
				return {
					content: [{ type: "text", text: "User cancelled" }],
					details: { mode, question: params.question, options: simpleOptions, answer: null } as QuestionDetails,
				};
			}

			if (result.wasCustom) {
				return {
					content: [{ type: "text", text: `User wrote: ${result.answer}` }],
					details: { mode, question: params.question, options: simpleOptions, answer: result.answer, customAnswer: result.answer } as QuestionDetails,
				};
			}

			return {
				content: [{ type: "text", text: `User selected: ${result.index}. ${result.answer}` }],
				details: { mode, question: params.question, options: simpleOptions, answer: result.answer } as QuestionDetails,
			};
		},

		renderCall(args, theme) {
			const mode = args.mode || "single";
			let text = theme.fg("toolTitle", theme.bold("AskUserQuestion "));
			text += theme.fg("muted", `[${mode}] `);
			text += theme.fg("text", args.question);

			const opts = Array.isArray(args.options) ? args.options : [];
			if (opts.length && mode !== "input") {
				const labels = opts.map((o: string | { label: string }) => (typeof o === "string" ? o : o.label));
				text += `\n${theme.fg("dim", `  Options: ${labels.join(", ")}`)}`;
			}
			if (args.allowCustom !== false && mode !== "input") {
				text += theme.fg("dim", ` (+custom)`);
			}
			return new Text(text, 0, 0);
		},

		renderResult(result, _options, theme) {
			const details = result.details as QuestionDetails | undefined;
			if (!details) {
				const text = result.content[0];
				return new Text(text?.type === "text" ? text.text : "", 0, 0);
			}

			if (details.answer === null) {
				return new Text(theme.fg("warning", "Cancelled"), 0, 0);
			}

			// Multi-select
			if (details.mode === "multi") {
				const selected = Array.isArray(details.answer) ? details.answer : [];
				const parts: string[] = [];
				for (const s of selected) {
					parts.push(theme.fg("accent", s));
				}
				if (details.customAnswer) {
					parts.push(theme.fg("muted", "(wrote) ") + theme.fg("accent", details.customAnswer));
				}
				if (parts.length === 0) {
					return new Text(theme.fg("dim", "Nothing selected"), 0, 0);
				}
				return new Text(theme.fg("success", "✓ ") + parts.join(", "), 0, 0);
			}

			// Input mode
			if (details.mode === "input") {
				return new Text(
					theme.fg("success", "✓ ") + theme.fg("muted", "(wrote) ") + theme.fg("accent", String(details.answer)),
					0,
					0,
				);
			}

			// Single-select
			if (details.customAnswer) {
				return new Text(
					theme.fg("success", "✓ ") + theme.fg("muted", "(wrote) ") + theme.fg("accent", details.customAnswer),
					0,
					0,
				);
			}

			const answer = String(details.answer);
			const idx = details.options.indexOf(answer) + 1;
			const display = idx > 0 ? `${idx}. ${answer}` : answer;
			return new Text(theme.fg("success", "✓ ") + theme.fg("accent", display), 0, 0);
		},
	});
}
