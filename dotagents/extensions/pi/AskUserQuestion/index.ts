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
import {
  Answer,
  Question,
  QuestionMode,
  RenderOption,
  SelectionState,
  buildAnswer,
  buildRenderOptions,
  normalizeQuestions,
  resolveDefaults,
} from "./model";
import { wrapQuestionLines } from "./text";

interface AskUserQuestionResult {
  cancelled: boolean;
  questions: Question[];
  answers: Answer[];
}

const WAIT_EVENT = "agent-status:wait";
const WAIT_SOURCE = "AskUserQuestion";

const ModeSchema = StringEnum(["single", "multi", "input"] as const, {
  description: "single: pick one, multi: pick many with checkboxes, input: free text only",
});

const QuestionOptionSchema = Type.Object({
  value: Type.String({ description: "The value returned when selected" }),
  label: Type.String({ description: "Display label for the option" }),
  description: Type.Optional(Type.String({ description: "Optional description shown below label" })),
});

const QuestionSchema = Type.Object({
  id: Type.Optional(Type.String({ description: "Unique identifier for this question" })),
  mode: ModeSchema,
  prompt: Type.String({ description: "The full question text to display" }),
  options: Type.Optional(Type.Array(QuestionOptionSchema, { description: "Available options to choose from" })),
  allowCustom: Type.Optional(Type.Boolean({ description: "Allow custom text input (default: true)" })),
  customLabel: Type.Optional(Type.String({ description: "Label for custom input option" })),
  allowEmpty: Type.Optional(Type.Boolean({ description: "Allow empty input (default: true)" })),
  defaultValue: Type.Optional(Type.String({ description: "Default selection by value (single/input)" })),
  defaultValues: Type.Optional(Type.Array(Type.String(), { description: "Default selections by value (multi)" })),
});

const QuestionParams = Type.Object({
  questions: Type.Optional(Type.Array(QuestionSchema, { description: "Questions to ask the user" })),
  mode: Type.Optional(ModeSchema),
  question: Type.Optional(Type.String({ description: "The question to ask the user" })),
  options: Type.Optional(Type.Array(QuestionOptionSchema, { description: "Options for the user to choose from (ignored for input mode)" })),
  allowCustom: Type.Optional(Type.Boolean({ description: "Allow custom text input in addition to options (default: true for single/multi)" })),
  customLabel: Type.Optional(Type.String({ description: "Label for custom input option" })),
  allowEmpty: Type.Optional(Type.Boolean({ description: "Allow empty input (default: true)" })),
  defaultValue: Type.Optional(Type.String({ description: "Default selection by value (single/input)" })),
  defaultValues: Type.Optional(Type.Array(Type.String(), { description: "Default selections by value (multi)" })),
});

function textContent(text: string) {
  return { type: "text" as const, text };
}

function errorResult(
  message: string,
  questions: Question[] = [],
): { content: { type: "text"; text: string }[]; details: AskUserQuestionResult } {
  return {
    content: [textContent(message)],
    details: { cancelled: true, questions, answers: [] },
  };
}

function emitWait(pi: ExtensionAPI, active: boolean) {
  pi.events.emit(WAIT_EVENT, { active, source: WAIT_SOURCE });
}

function editorTheme(theme: any): EditorTheme {
  return {
    borderColor: (s) => theme.fg("accent", s),
    selectList: {
      selectedPrefix: (t) => theme.fg("accent", t),
      selectedText: (t) => theme.fg("accent", t),
      description: (t) => theme.fg("muted", t),
      scrollInfo: (t) => theme.fg("dim", t),
      noMatch: (t) => theme.fg("warning", t),
    },
  };
}

function answerLabels(answer: Answer): string[] {
  return Array.isArray(answer.label) ? answer.label : [String(answer.label ?? "")];
}

function hasCustom(answer: Answer): boolean {
  if (Array.isArray(answer.wasCustom)) {
    return answer.wasCustom.some(Boolean);
  }
  return Boolean(answer.wasCustom);
}

function formatAnswerPlain(answer: Answer): string {
  return answerLabels(answer).filter((label) => label.length > 0).join(", ");
}

function formatContentLine(question: Question, answer: Answer): string {
  const text = formatAnswerPlain(answer);
  if (question.mode === "input" || (hasCustom(answer) && !Array.isArray(answer.label))) {
    return text ? `User wrote: ${text}` : "User wrote nothing";
  }
  if (!text) {
    return "User selected nothing";
  }
  return `User selected: ${text}`;
}

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "AskUserQuestion",
    label: "Ask User Question",
    description:
      "Ask the user a question. Modes: single (pick one), multi (pick many with checkboxes), input (free text). Use when you need user input to proceed.",
    parameters: QuestionParams,

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const hasLegacy = Boolean(params.mode && params.question);
      if (!params.questions && !hasLegacy) {
        return errorResult("Error: No questions provided");
      }

      const questions = normalizeQuestions(params as unknown as { questions?: Question[] } & { mode: QuestionMode; question: string });

      if (!ctx.hasUI) {
        return errorResult("Error: UI not available (running in non-interactive mode)", questions);
      }
      if (questions.length === 0) {
        return errorResult("Error: No questions provided", questions);
      }

      const invalidQuestion = questions.find(
        (question) => question.mode !== "input" && question.options.length === 0 && !question.allowCustom,
      );
      if (invalidQuestion) {
        return errorResult(
          `Error: No options provided for ${invalidQuestion.id} and custom input disabled`,
          questions,
        );
      }

      async function askInput(question: Question): Promise<SelectionState | null> {
        const defaults = resolveDefaults(question);
        return ctx.ui.custom<SelectionState | null>((tui, theme, _kb, done) => {
          let cachedLines: string[] | undefined;
          const editor = new Editor(tui, editorTheme(theme));
          if (defaults.customValue) {
            editor.setText(defaults.customValue);
          }

          editor.onSubmit = (value) => {
            const trimmed = value.trim();
            if (!question.allowEmpty && !trimmed) {
              return;
            }
            done({ selectedIndexes: [], customValue: trimmed });
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
            for (const line of wrapQuestionLines(question.prompt, width)) {
              add(theme.fg("text", line));
            }
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
            invalidate: () => {
              cachedLines = undefined;
            },
            handleInput,
          };
        });
      }

      async function askSingle(question: Question): Promise<SelectionState | null> {
        const defaults = resolveDefaults(question);
        return ctx.ui.custom<SelectionState | null>((tui, theme, _kb, done) => {
          const options = buildRenderOptions(question);
          let optionIndex = Math.min(defaults.optionIndex, Math.max(0, options.length - 1));
          let editMode = false;
          let customValue = defaults.customValue;
          let cachedLines: string[] | undefined;

          if (customValue && question.allowCustom && options.length > 0) {
            optionIndex = options.length - 1;
          }

          const editor = new Editor(tui, editorTheme(theme));

          editor.onSubmit = (value) => {
            const trimmed = value.trim();
            if (!question.allowEmpty && !trimmed) {
              return;
            }
            customValue = trimmed;
            if (editMode) {
              done({ selectedIndexes: [], customValue });
              return;
            }
            editMode = false;
            editor.setText("");
            optionIndex = options.length > 0 ? options.length - 1 : 0;
            refresh();
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
              optionIndex = Math.min(options.length - 1, optionIndex + 1);
              refresh();
              return;
            }

            if (matchesKey(data, Key.enter)) {
              const selected = options[optionIndex];
              if (selected?.isOther) {
                editMode = true;
                editor.setText(customValue);
                refresh();
                return;
              }
              done({ selectedIndexes: [optionIndex], customValue: "" });
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
            for (const line of wrapQuestionLines(question.prompt, width)) {
              add(theme.fg("text", line));
            }
            lines.push("");

            for (let i = 0; i < options.length; i++) {
              const opt = options[i];
              const selected = i === optionIndex;
              const isOther = opt.isOther === true;
              const prefix = selected ? theme.fg("accent", "> ") : "  ";
              let label: string;

              if (isOther && customValue) {
                label = theme.fg("text", `${opt.label}`) + theme.fg("muted", ` → \"${customValue}\"`);
              } else {
                label = theme.fg(selected ? "accent" : "text", `${opt.label}`);
              }

              if (isOther && editMode) {
                label = theme.fg("accent", `${opt.label} ✎`);
              }

              add(`${prefix}${i + 1}. ${label}`);

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
              lines.push("");
              add(theme.fg("dim", " Enter to submit • Esc to go back"));
            } else {
              lines.push("");
              add(theme.fg("dim", " ↑↓ navigate • Enter to select • Esc to cancel"));
            }
            add(theme.fg("accent", "─".repeat(width)));

            cachedLines = lines;
            return lines;
          }

          return {
            render,
            invalidate: () => {
              cachedLines = undefined;
            },
            handleInput,
          };
        });
      }

      async function askMulti(question: Question): Promise<SelectionState | null> {
        const defaults = resolveDefaults(question);
        return ctx.ui.custom<SelectionState | null>((tui, theme, _kb, done) => {
          const options = buildRenderOptions(question);
          let optionIndex = Math.min(defaults.optionIndex, options.length);
          let editMode = false;
          let reviewMode = false;
          let customValue = defaults.customValue;
          const checked = new Set<number>(defaults.checkedIndexes);
          let cachedLines: string[] | undefined;

          if (customValue && question.allowCustom && options.length > 0) {
            optionIndex = options.length - 1;
          }

          const editor = new Editor(tui, editorTheme(theme));

          editor.onSubmit = (value) => {
            const trimmed = value.trim();
            if (!question.allowEmpty && !trimmed) {
              return;
            }
            customValue = trimmed;
            editMode = false;
            editor.setText("");
            refresh();
          };

          function refresh() {
            cachedLines = undefined;
            tui.requestRender();
          }

          function submit() {
            done({ selectedIndexes: Array.from(checked), customValue });
          }

          function handleInput(data: string) {
            if (reviewMode) {
              if (matchesKey(data, Key.enter)) {
                submit();
                return;
              }
              if (matchesKey(data, Key.escape)) {
                reviewMode = false;
                refresh();
                return;
              }
              return;
            }

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
              optionIndex = Math.min(options.length, optionIndex + 1); // +1 for Submit
              refresh();
              return;
            }

            if (matchesKey(data, Key.space)) {
              if (optionIndex < options.length) {
                const opt = options[optionIndex];
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

            if (matchesKey(data, Key.enter)) {
              if (optionIndex < options.length) {
                const opt = options[optionIndex];
                if (opt.isOther) {
                  editMode = true;
                  editor.setText(customValue);
                  refresh();
                  return;
                }
                if (checked.has(optionIndex)) {
                  checked.delete(optionIndex);
                } else {
                  checked.add(optionIndex);
                }
                refresh();
                return;
              }
              reviewMode = true;
              refresh();
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
            for (const line of wrapQuestionLines(question.prompt, width)) {
              add(theme.fg("text", line));
            }
            lines.push("");

            for (let i = 0; i < options.length; i++) {
              const opt = options[i];
              const selected = i === optionIndex;
              const isOther = opt.isOther === true;
              const isChecked = checked.has(i) || (isOther && customValue);
              const prefix = selected ? theme.fg("accent", "> ") : "  ";

              const checkbox = isChecked ? theme.fg("success", "[✓]") : theme.fg("muted", "[ ]");
              let label: string;
              if (isOther && editMode) {
                label = theme.fg("accent", `${opt.label} ✎`);
              } else if (isOther && customValue) {
                label = theme.fg("text", `${opt.label}`) + theme.fg("muted", ` → \"${customValue}\"`);
              } else {
                label = theme.fg(selected ? "accent" : "text", opt.label);
              }

              add(`${prefix}${checkbox} ${i + 1}. ${label}`);

              if (opt.description) {
                add(`       ${theme.fg("muted", opt.description)}`);
              }
            }

            const onSubmitRow = optionIndex === options.length;
            const submitPrefix = onSubmitRow ? theme.fg("accent", "> ") : "  ";
            const selectedCount = checked.size + (customValue ? 1 : 0);
            const submitLabel = onSubmitRow
              ? theme.fg("accent", theme.bold("Review"))
              : theme.fg("muted", "Review");
            add(`${submitPrefix}  ${submitLabel}` + theme.fg("dim", ` (${selectedCount} selected)`));

            if (reviewMode) {
              lines.push("");
              add(theme.fg("accent", theme.bold(" Review selections")));
              const selections = [
                ...Array.from(checked).map((idx) => options[idx]?.label).filter(Boolean),
                ...(customValue ? [customValue] : []),
              ];
              if (selections.length === 0) {
                add(theme.fg("dim", " (none)"));
              } else {
                for (const selection of selections) {
                  add(`  ${theme.fg("text", selection)}`);
                }
              }
              lines.push("");
              add(theme.fg("dim", " Enter to confirm • Esc to go back"));
            } else if (editMode) {
              lines.push("");
              add(theme.fg("muted", " Your answer:"));
              for (const line of editor.render(width - 2)) {
                add(` ${line}`);
              }
              lines.push("");
              add(theme.fg("dim", " Enter to confirm • Esc to go back"));
            } else {
              lines.push("");
              add(theme.fg("dim", " ↑↓ navigate • Space toggle • Enter review • Esc cancel"));
            }
            add(theme.fg("accent", "─".repeat(width)));

            cachedLines = lines;
            return lines;
          }

          return {
            render,
            invalidate: () => {
              cachedLines = undefined;
            },
            handleInput,
          };
        });
      }

      async function runSingleQuestion(question: Question) {
        if (question.mode !== "input" && question.options.length === 0 && !question.allowCustom) {
          return errorResult("Error: No options provided and custom input disabled", [question]);
        }

        let selection: SelectionState | null = null;
        if (question.mode === "input") {
          selection = await askInput(question);
        } else if (question.mode === "multi") {
          selection = await askMulti(question);
        } else {
          selection = await askSingle(question);
        }

        if (!selection) {
          return {
            content: [textContent("User cancelled")],
            details: { cancelled: true, questions: [question], answers: [] },
          };
        }

        const answer = buildAnswer(question, selection);
        return {
          content: [textContent(formatContentLine(question, answer))],
          details: { cancelled: false, questions: [question], answers: [answer] },
        };
      }

      async function runQuestionnaire(allQuestions: Question[]) {
        const totalTabs = allQuestions.length + 1;
        const result = await ctx.ui.custom<AskUserQuestionResult>((tui, theme, _kb, done) => {
          let currentTab = 0;
          let optionIndex = 0;
          let editMode = false;
          let reviewMode = false;
          let customValue = "";
          let checked = new Set<number>();
          let cachedLines: string[] | undefined;
          const answers = new Map<string, Answer>();

          const editor = new Editor(tui, editorTheme(theme));

          function refresh() {
            cachedLines = undefined;
            tui.requestRender();
          }

          function currentQuestion(): Question | undefined {
            return allQuestions[currentTab];
          }

          function currentOptions(question?: Question): RenderOption[] {
            if (!question) return [];
            return buildRenderOptions(question);
          }

          function allAnswered(): boolean {
            return allQuestions.every((q) => answers.has(q.id));
          }

          function saveAnswer(question: Question) {
            const state: SelectionState = { selectedIndexes: Array.from(checked), customValue };
            answers.set(question.id, buildAnswer(question, state));
          }

          function applyAnswerToState(question: Question, answer: Answer) {
            if (question.mode === "input") {
              customValue = String(answer.value ?? "");
              return;
            }
            if (Array.isArray(answer.value)) {
              checked = new Set<number>();
              const customEntries: string[] = [];
              const customFlags = Array.isArray(answer.wasCustom) ? answer.wasCustom : [];
              answer.value.forEach((value, index) => {
                const isCustom = customFlags[index];
                if (isCustom) {
                  customEntries.push(String(value));
                  return;
                }
                const optionIndex = question.options.findIndex((opt) => opt.value === value);
                if (optionIndex >= 0) {
                  checked.add(optionIndex);
                }
              });
              customValue = customEntries.join(", ");
              return;
            }

            if (answer.wasCustom) {
              customValue = String(answer.value ?? "");
              return;
            }
            const idx = question.options.findIndex((opt) => opt.value === answer.value);
            if (idx >= 0) {
              optionIndex = idx;
            }
          }

          function loadQuestionState(question: Question) {
            const defaults = resolveDefaults(question);
            optionIndex = Math.min(defaults.optionIndex, Math.max(0, question.options.length - 1));
            checked = new Set(defaults.checkedIndexes);
            customValue = defaults.customValue;
            editMode = false;
            reviewMode = false;

            const answer = answers.get(question.id);
            if (answer) {
              applyAnswerToState(question, answer);
            }

            if (customValue && question.allowCustom) {
              optionIndex = buildRenderOptions(question).length - 1;
            }

            editor.setText(customValue || "");
          }

          function advanceAfterAnswer() {
            if (currentTab < allQuestions.length - 1) {
              currentTab += 1;
              loadQuestionState(allQuestions[currentTab]);
            } else {
              currentTab = allQuestions.length;
            }
            refresh();
          }

          editor.onSubmit = (value) => {
            const question = currentQuestion();
            if (!question) return;
            const trimmed = value.trim();
            if (!question.allowEmpty && !trimmed) {
              return;
            }
            customValue = trimmed;
            if (question.mode === "input") {
              saveAnswer(question);
              advanceAfterAnswer();
              editor.setText("");
              return;
            }
            editMode = false;
            editor.setText("");
            refresh();
          };

          loadQuestionState(allQuestions[0]);

          function submit(cancelled: boolean) {
            done({
              cancelled,
              questions: allQuestions,
              answers: Array.from(answers.values()),
            });
          }

          function handleInput(data: string) {
            const question = currentQuestion();
            const isSubmitTab = currentTab === allQuestions.length;
            if (isSubmitTab) {
              if (matchesKey(data, Key.enter) && allAnswered()) {
                submit(false);
              } else if (matchesKey(data, Key.escape)) {
                submit(true);
              }
              return;
            }

            if (!question) return;

            const isInputQuestion = question.mode === "input";

            if (isInputQuestion || editMode) {
              if (matchesKey(data, Key.escape)) {
                if (editMode) {
                  editMode = false;
                  editor.setText("");
                  refresh();
                } else {
                  submit(true);
                }
                return;
              }
              editor.handleInput(data);
              refresh();
              return;
            }

            if (reviewMode) {
              if (matchesKey(data, Key.enter)) {
                saveAnswer(question);
                reviewMode = false;
                advanceAfterAnswer();
                return;
              }
              if (matchesKey(data, Key.escape)) {
                reviewMode = false;
                refresh();
                return;
              }
              return;
            }

            if (matchesKey(data, Key.tab) || matchesKey(data, Key.right)) {
              currentTab = (currentTab + 1) % totalTabs;
              if (currentTab < allQuestions.length) {
                loadQuestionState(allQuestions[currentTab]);
              }
              refresh();
              return;
            }
            if (matchesKey(data, Key.shift("tab")) || matchesKey(data, Key.left)) {
              currentTab = (currentTab - 1 + totalTabs) % totalTabs;
              if (currentTab < allQuestions.length) {
                loadQuestionState(allQuestions[currentTab]);
              }
              refresh();
              return;
            }

            const options = currentOptions(question);
            const maxIndex = question.mode === "multi" ? options.length : options.length - 1;

            if (matchesKey(data, Key.up)) {
              optionIndex = Math.max(0, optionIndex - 1);
              refresh();
              return;
            }
            if (matchesKey(data, Key.down)) {
              optionIndex = Math.min(maxIndex, optionIndex + 1);
              refresh();
              return;
            }

            if (question.mode === "single") {
              if (matchesKey(data, Key.enter)) {
                const selected = options[optionIndex];
                if (selected?.isOther) {
                  editMode = true;
                  editor.setText(customValue);
                  refresh();
                  return;
                }
                saveAnswer(question);
                advanceAfterAnswer();
                return;
              }
            }

            if (question.mode === "multi") {
              if (matchesKey(data, Key.space)) {
                if (optionIndex < options.length) {
                  const opt = options[optionIndex];
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

              if (matchesKey(data, Key.enter)) {
                if (optionIndex < options.length) {
                  const opt = options[optionIndex];
                  if (opt.isOther) {
                    editMode = true;
                    editor.setText(customValue);
                    refresh();
                    return;
                  }
                  if (checked.has(optionIndex)) {
                    checked.delete(optionIndex);
                  } else {
                    checked.add(optionIndex);
                  }
                  refresh();
                  return;
                }
                reviewMode = true;
                refresh();
                return;
              }
            }

            if (matchesKey(data, Key.escape)) {
              submit(true);
            }
          }

          function render(width: number): string[] {
            if (cachedLines) return cachedLines;

            const lines: string[] = [];
            const add = (s: string) => lines.push(truncateToWidth(s, width));

            add(theme.fg("accent", "─".repeat(width)));

            const isMulti = allQuestions.length > 1;
            if (isMulti) {
              const tabs: string[] = ["← "];
              for (let i = 0; i < allQuestions.length; i++) {
                const isActive = i === currentTab;
                const isAnswered = answers.has(allQuestions[i].id);
                const label = allQuestions[i].id;
                const box = isAnswered ? "■" : "□";
                const color = isAnswered ? "success" : "muted";
                const text = ` ${box} ${label} `;
                const styled = isActive
                  ? theme.bg("selectedBg", theme.fg("text", text))
                  : theme.fg(color, text);
                tabs.push(`${styled} `);
              }
              const canSubmit = allAnswered();
              const isSubmitTab = currentTab === allQuestions.length;
              const submitText = " ✓ Submit ";
              const submitStyled = isSubmitTab
                ? theme.bg("selectedBg", theme.fg("text", submitText))
                : theme.fg(canSubmit ? "success" : "dim", submitText);
              tabs.push(`${submitStyled} →`);
              add(` ${tabs.join("")}`);
              lines.push("");
            }

            if (currentTab === allQuestions.length) {
              add(theme.fg("accent", theme.bold(" Ready to submit")));
              lines.push("");
              for (const question of allQuestions) {
                const answer = answers.get(question.id);
                if (answer) {
                  const summary = formatAnswerPlain(answer) || "(none)";
                  add(`${theme.fg("muted", ` ${question.id}: `)}${theme.fg("text", summary)}`);
                }
              }
              lines.push("");
              if (allAnswered()) {
                add(theme.fg("success", " Press Enter to submit"));
              } else {
                const missing = allQuestions
                  .filter((q) => !answers.has(q.id))
                  .map((q) => q.id)
                  .join(", ");
                add(theme.fg("warning", ` Unanswered: ${missing}`));
              }
            } else {
              const question = currentQuestion();
              if (question) {
                const options = currentOptions(question);
                for (const line of wrapQuestionLines(question.prompt, width)) {
                  add(theme.fg("text", line));
                }
                lines.push("");

                if (question.mode === "input") {
                  add(theme.fg("muted", " Your answer:"));
                  for (const line of editor.render(width - 2)) {
                    add(` ${line}`);
                  }
                  lines.push("");
                  add(theme.fg("dim", " Enter to submit • Esc to cancel"));
                } else if (question.mode === "single") {
                  for (let i = 0; i < options.length; i++) {
                    const opt = options[i];
                    const selected = i === optionIndex;
                    const isOther = opt.isOther === true;
                    const prefix = selected ? theme.fg("accent", "> ") : "  ";
                    let label: string;

                    if (isOther && customValue) {
                      label = theme.fg("text", `${opt.label}`) + theme.fg("muted", ` → \"${customValue}\"`);
                    } else {
                      label = theme.fg(selected ? "accent" : "text", opt.label);
                    }

                    if (isOther && editMode) {
                      label = theme.fg("accent", `${opt.label} ✎`);
                    }

                    add(`${prefix}${i + 1}. ${label}`);

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
                    lines.push("");
                    add(theme.fg("dim", " Enter to submit • Esc to go back"));
                  }
                } else {
                  for (let i = 0; i < options.length; i++) {
                    const opt = options[i];
                    const selected = i === optionIndex;
                    const isOther = opt.isOther === true;
                    const isChecked = checked.has(i) || (isOther && customValue);
                    const prefix = selected ? theme.fg("accent", "> ") : "  ";
                    const checkbox = isChecked ? theme.fg("success", "[✓]") : theme.fg("muted", "[ ]");
                    let label: string;

                    if (isOther && editMode) {
                      label = theme.fg("accent", `${opt.label} ✎`);
                    } else if (isOther && customValue) {
                      label = theme.fg("text", `${opt.label}`) + theme.fg("muted", ` → \"${customValue}\"`);
                    } else {
                      label = theme.fg(selected ? "accent" : "text", opt.label);
                    }

                    add(`${prefix}${checkbox} ${i + 1}. ${label}`);
                    if (opt.description) {
                      add(`       ${theme.fg("muted", opt.description)}`);
                    }
                  }

                  const onSubmitRow = optionIndex === options.length;
                  const submitPrefix = onSubmitRow ? theme.fg("accent", "> ") : "  ";
                  const selectedCount = checked.size + (customValue ? 1 : 0);
                  const submitLabel = onSubmitRow
                    ? theme.fg("accent", theme.bold("Review"))
                    : theme.fg("muted", "Review");
                  add(`${submitPrefix}  ${submitLabel}` + theme.fg("dim", ` (${selectedCount} selected)`));

                  if (reviewMode) {
                    lines.push("");
                    add(theme.fg("accent", theme.bold(" Review selections")));
                    const selections = [
                      ...Array.from(checked).map((idx) => options[idx]?.label).filter(Boolean),
                      ...(customValue ? [customValue] : []),
                    ];
                    if (selections.length === 0) {
                      add(theme.fg("dim", " (none)"));
                    } else {
                      for (const selection of selections) {
                        add(`  ${theme.fg("text", selection)}`);
                      }
                    }
                    lines.push("");
                    add(theme.fg("dim", " Enter to confirm • Esc to go back"));
                  } else if (editMode) {
                    lines.push("");
                    add(theme.fg("muted", " Your answer:"));
                    for (const line of editor.render(width - 2)) {
                      add(` ${line}`);
                    }
                    lines.push("");
                    add(theme.fg("dim", " Enter to confirm • Esc to go back"));
                  }
                }
              }
            }

            lines.push("");
            if (!editMode && !reviewMode) {
              const help = isMulti
                ? " Tab/←→ navigate • ↑↓ select • Enter confirm • Esc cancel"
                : " ↑↓ navigate • Enter select • Esc cancel";
              add(theme.fg("dim", help));
            }
            add(theme.fg("accent", "─".repeat(width)));

            cachedLines = lines;
            return lines;
          }

          return {
            render,
            invalidate: () => {
              cachedLines = undefined;
            },
            handleInput,
          };
        });

        if (result.cancelled) {
          return {
            content: [textContent("User cancelled the questionnaire")],
            details: result,
          };
        }

        const answerLines = result.answers.map((answer) => {
          const label = formatAnswerPlain(answer) || "(none)";
          return `${answer.id}: ${label}`;
        });

        return {
          content: [textContent(answerLines.join("\n"))],
          details: result,
        };
      }

      emitWait(pi, true);
      try {
        if (questions.length === 1) {
          return await runSingleQuestion(questions[0]);
        }

        return await runQuestionnaire(questions);
      } finally {
        emitWait(pi, false);
      }
    },

    renderCall(args, theme) {
      const questions = Array.isArray(args.questions) ? (args.questions as Question[]) : [];
      const count = questions.length;
      let text = theme.fg("toolTitle", theme.bold("AskUserQuestion "));
      if (count > 0) {
        text += theme.fg("muted", `${count} question${count === 1 ? "" : "s"}`);
        const labels = questions.map((q) => q.id).join(", ");
        if (labels) {
          text += theme.fg("dim", ` (${truncateToWidth(labels, 40)})`);
        }
      } else if (args.question) {
        const mode = args.mode || "single";
        text += theme.fg("muted", `[${mode}]`);
        const questionLines = wrapQuestionLines(String(args.question), 80);
        if (questionLines.length > 0) {
          text += theme.fg("text", questionLines[0]);
          if (questionLines.length > 1) {
            text += `\n${questionLines.slice(1).map((line) => theme.fg("text", line)).join("\n")}`;
          }
        }
      }

      const options = Array.isArray(args.options) ? (args.options as Array<{ label: string }>) : [];
      if (options.length && !questions.length) {
        const labels = options.map((opt) => opt.label);
        text += `\n${theme.fg("dim", `  Options: ${truncateToWidth(labels.join(", "), 60)}`)}`;
      }
      if (args.allowCustom !== false && !questions.length && args.mode !== "input") {
        text += theme.fg("dim", " (+custom)");
      }
      return new Text(text, 0, 0);
    },

    renderResult(result, _options, theme) {
      const details = result.details as AskUserQuestionResult | undefined;
      if (!details) {
        const text = result.content[0];
        return new Text(text?.type === "text" ? text.text : "", 0, 0);
      }

      if (details.cancelled) {
        return new Text(theme.fg("warning", "Cancelled"), 0, 0);
      }

      const lines = details.answers.map((answer) => {
        const labels = answerLabels(answer);
        const customFlags = Array.isArray(answer.wasCustom) ? answer.wasCustom : [answer.wasCustom];
        const prefix = theme.fg("success", "✓ ") + theme.fg("accent", answer.id) + theme.fg("text", ": ");
        if (labels.length === 0) {
          return prefix + theme.fg("dim", "(none)");
        }
        const parts = labels.map((label, index) => {
          if (customFlags[index]) {
            return theme.fg("muted", "(wrote) ") + theme.fg("accent", label);
          }
          return theme.fg("accent", label);
        });
        return prefix + parts.join(", ");
      });

      return new Text(lines.join("\n"), 0, 0);
    },
  });
}
