# AskUserQuestion redesign

## Summary

Upgrade `AskUserQuestion` to a unified question model with richer option metadata, multi-question support, defaults, configurable custom input, and consistent results. This is a breaking schema change: options must be `{ value, label, description? }` objects.

## Goals

- Use a single `Question` shape for single and multi-question flows.
- Separate display labels from returned values.
- Support defaults by value for single and multi-select.
- Allow configurable custom input label and empty input rules.
- Provide a consistent result shape with `cancelled`, `id`, `wasCustom`, and `index`.
- Keep UI readable with truncation and a review step for multi-select.

## Non-goals

- Backward compatibility for string-only options.
- Persisting answers across tool calls.
- Advanced validation beyond empty checks.

## Proposed API

```ts
interface QuestionOption {
  value: string;
  label: string;
  description?: string;
}

interface Question {
  id: string;
  mode: "single" | "multi" | "input";
  prompt: string;
  options?: QuestionOption[]; // required for single/multi
  allowCustom?: boolean; // default true
  customLabel?: string; // default "Type something."
  allowEmpty?: boolean; // default true (input/custom)
  defaultValue?: string; // single/input
  defaultValues?: string[]; // multi
}

interface Answer {
  id: string;
  mode: "single" | "multi" | "input";
  value: string | string[];
  label: string | string[];
  wasCustom: boolean | boolean[];
  index?: number | number[]; // 1-based for option selections
}

interface AskUserQuestionResult {
  cancelled: boolean;
  questions: Question[];
  answers: Answer[];
}
```

Top-level params accept either `questions: Question[]` or the legacy single-question fields (`mode`, `question`, `options`, etc.). The latter are normalized into a single `Question` with `id = "q1"`.

## Data flow

1. Validate UI availability and presence of at least one question.
2. Normalize questions, apply defaults (`allowCustom = true`, `customLabel = "Type something."`, `allowEmpty = true`).
3. Preselect defaults by value:
   - Single/input: set selection or prefill custom input when `defaultValue` doesn’t match an option (if custom allowed).
   - Multi: pre-check options whose values match `defaultValues`; unmatched values become custom input if allowed.
4. Render either single-question UI (one question) or tabbed multi-question UI with a Submit tab.
5. Return `AskUserQuestionResult` with `cancelled` and normalized `answers`.

## UI behavior

- **Single question**:
  - `single`: list + Enter select; custom option opens editor.
  - `multi`: checkbox list + Submit row; after Submit show a review screen (selections + custom input) with Enter confirm or Esc to return.
  - `input`: editor only; if `allowEmpty` is false, reject empty submit.
- **Multi-question**:
  - Tab/arrow navigation between questions and Submit tab.
  - Each question uses its mode’s UI, including the multi-select review step.
  - Submit tab blocks submission until all questions are answered.
- **Rendering polish**:
  - Truncate option labels in `renderCall` and summary strings.

## Error handling

- Use a helper to return error results with `cancelled: true` and empty answers.
- If no UI: return error result.
- If options are missing for `single`/`multi`: return error result.
- For `allowEmpty: false` inputs, keep the editor open until non-empty input is provided.
- If the user cancels via Esc, return `cancelled: true` and any partial answers gathered so far.

## Testing and validation

- Run `./tests/test-pi-extensions.sh` to type-check the extension.
- Manual smoke checks:
  - Single input with `allowEmpty: false`.
  - Single select with `defaultValue`.
  - Multi select with `defaultValues` and custom input.
  - Multi-question tab navigation + Submit summary.
  - Cancel flow returns `cancelled: true`.
