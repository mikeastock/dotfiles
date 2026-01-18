# AskUserQuestion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a unified AskUserQuestion model with multi-question support, defaults, configurable custom input, and consistent results.

**Architecture:** Extract pure model helpers (normalization, defaults, answer building) into `extensions/pi/AskUserQuestion/model.ts` and drive UI state from those helpers. Use a lightweight TypeScript test script (run via `tsx`) to enforce TDD on model behavior. Update `index.ts` to use the new schema, tabbed questionnaire UI, and a review step for multi-select.

**Tech Stack:** TypeScript, TypeBox, pi-tui, Node assert, tsx.

---

### Task 1: Add test runner + baseline normalization test

**Files:**
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`
- Create: `tests/askuserquestion.test.ts`
- Create: `extensions/pi/AskUserQuestion/model.ts`

**Step 1: Install tsx for TypeScript test execution**

Run:
```bash
pnpm add -D tsx
```
Expected: `tsx` added to `devDependencies` and `pnpm-lock.yaml` updated.

**Step 2: Write failing test for question normalization**

Create `tests/askuserquestion.test.ts`:
```ts
import assert from "node:assert/strict";
import { normalizeQuestions } from "../extensions/pi/AskUserQuestion/model";

const result = normalizeQuestions({
  mode: "single",
  question: "Pick one",
  options: [{ value: "a", label: "A" }],
});

assert.equal(result.length, 1);
assert.equal(result[0].id, "q1");
assert.equal(result[0].prompt, "Pick one");
assert.equal(result[0].mode, "single");
assert.equal(result[0].allowCustom, true);
assert.equal(result[0].customLabel, "Type something.");
assert.equal(result[0].allowEmpty, true);
```

**Step 3: Run test to verify it fails**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: FAIL with “Cannot find module '../extensions/pi/AskUserQuestion/model'”.

**Step 4: Write minimal implementation**

Create `extensions/pi/AskUserQuestion/model.ts`:
```ts
export type QuestionMode = "single" | "multi" | "input";

export interface QuestionOption {
  value: string;
  label: string;
  description?: string;
}

export interface Question {
  id: string;
  mode: QuestionMode;
  prompt: string;
  options: QuestionOption[];
  allowCustom: boolean;
  customLabel: string;
  allowEmpty: boolean;
  defaultValue?: string;
  defaultValues?: string[];
}

interface SingleParams {
  mode: QuestionMode;
  question: string;
  options?: QuestionOption[];
  allowCustom?: boolean;
  customLabel?: string;
  allowEmpty?: boolean;
  defaultValue?: string;
  defaultValues?: string[];
}

export function normalizeQuestions(params: SingleParams & { questions?: Question[] }): Question[] {
  if (Array.isArray(params.questions) && params.questions.length > 0) {
    return params.questions.map((q, i) => ({
      ...q,
      id: q.id || `q${i + 1}`,
      allowCustom: q.allowCustom !== false,
      customLabel: q.customLabel || "Type something.",
      allowEmpty: q.allowEmpty !== false ? true : false,
    }));
  }

  const opts = params.options ?? [];
  return [
    {
      id: "q1",
      mode: params.mode,
      prompt: params.question,
      options: opts,
      allowCustom: params.allowCustom !== false,
      customLabel: params.customLabel || "Type something.",
      allowEmpty: params.allowEmpty !== false ? true : false,
      defaultValue: params.defaultValue,
      defaultValues: params.defaultValues,
    },
  ];
}
```

**Step 5: Run test to verify it passes**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: PASS (exit code 0).

**Step 6: Commit**

Run:
```bash
git add package.json pnpm-lock.yaml tests/askuserquestion.test.ts extensions/pi/AskUserQuestion/model.ts
git commit -m "test: add AskUserQuestion normalization test"
```

---

### Task 2: Add default and custom-label helpers

**Files:**
- Modify: `tests/askuserquestion.test.ts`
- Modify: `extensions/pi/AskUserQuestion/model.ts`

**Step 1: Write failing tests for defaults and render options**

Append to `tests/askuserquestion.test.ts`:
```ts
import { buildRenderOptions, resolveDefaults } from "../extensions/pi/AskUserQuestion/model";

const question = {
  id: "q1",
  mode: "multi",
  prompt: "Pick many",
  options: [
    { value: "a", label: "A" },
    { value: "b", label: "B" },
    { value: "c", label: "C" },
  ],
  allowCustom: true,
  customLabel: "Other",
  allowEmpty: true,
  defaultValues: ["a", "x"],
};

const renderOptions = buildRenderOptions(question);
assert.equal(renderOptions[renderOptions.length - 1].label, "Other");
assert.equal(renderOptions[renderOptions.length - 1].isOther, true);

const defaults = resolveDefaults(question);
assert.deepEqual(defaults.checkedIndexes, [0]);
assert.equal(defaults.customValue, "x");
```

**Step 2: Run tests to verify failure**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: FAIL with “buildRenderOptions is not a function”.

**Step 3: Implement helpers**

Update `extensions/pi/AskUserQuestion/model.ts`:
```ts
export interface RenderOption extends QuestionOption {
  isOther?: boolean;
}

export function buildRenderOptions(question: Question): RenderOption[] {
  const options: RenderOption[] = [...question.options];
  if (question.allowCustom) {
    options.push({ value: "__other__", label: question.customLabel, isOther: true });
  }
  return options;
}

export function resolveDefaults(question: Question): {
  optionIndex: number;
  checkedIndexes: number[];
  customValue: string;
} {
  if (question.mode === "single") {
    const idx = question.defaultValue
      ? question.options.findIndex((opt) => opt.value === question.defaultValue)
      : -1;
    const unmatched = question.defaultValue && idx === -1 && question.allowCustom ? question.defaultValue : "";
    return { optionIndex: Math.max(0, idx), checkedIndexes: [], customValue: unmatched };
  }

  if (question.mode === "multi") {
    const defaults = question.defaultValues ?? [];
    const matched = defaults
      .map((value) => question.options.findIndex((opt) => opt.value === value))
      .filter((index) => index >= 0);
    const unmatched = defaults.filter((value) => !question.options.some((opt) => opt.value === value));
    return {
      optionIndex: 0,
      checkedIndexes: matched,
      customValue: question.allowCustom ? unmatched.join(", ") : "",
    };
  }

  return { optionIndex: 0, checkedIndexes: [], customValue: question.defaultValue ?? "" };
}
```

**Step 4: Run tests to verify pass**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: PASS.

**Step 5: Commit**

Run:
```bash
git add tests/askuserquestion.test.ts extensions/pi/AskUserQuestion/model.ts
git commit -m "feat: add AskUserQuestion default helpers"
```

---

### Task 3: Add answer-building helper

**Files:**
- Modify: `tests/askuserquestion.test.ts`
- Modify: `extensions/pi/AskUserQuestion/model.ts`

**Step 1: Write failing tests for answer construction**

Append to `tests/askuserquestion.test.ts`:
```ts
import { buildAnswer } from "../extensions/pi/AskUserQuestion/model";

const singleQuestion = {
  id: "q1",
  mode: "single",
  prompt: "Pick one",
  options: [{ value: "a", label: "A" }],
  allowCustom: true,
  customLabel: "Other",
  allowEmpty: true,
};

const multiQuestion = {
  ...singleQuestion,
  id: "q2",
  mode: "multi",
  options: [
    { value: "a", label: "A" },
    { value: "b", label: "B" },
  ],
};

const singleAnswer = buildAnswer(singleQuestion, { selectedIndexes: [0], customValue: "" });
assert.equal(singleAnswer.value, "a");
assert.equal(singleAnswer.label, "A");
assert.equal(singleAnswer.wasCustom, false);
assert.equal(singleAnswer.index, 1);

const multiAnswer = buildAnswer(multiQuestion, { selectedIndexes: [0, 1], customValue: "x" });
assert.deepEqual(multiAnswer.value, ["a", "b", "x"]);
assert.deepEqual(multiAnswer.label, ["A", "B", "x"]);
assert.deepEqual(multiAnswer.wasCustom, [false, false, true]);
assert.deepEqual(multiAnswer.index, [1, 2]);
```

**Step 2: Run tests to verify failure**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: FAIL with “buildAnswer is not a function”.

**Step 3: Implement buildAnswer**

Update `extensions/pi/AskUserQuestion/model.ts`:
```ts
export interface SelectionState {
  selectedIndexes: number[];
  customValue: string;
}

export interface Answer {
  id: string;
  mode: QuestionMode;
  value: string | string[];
  label: string | string[];
  wasCustom: boolean | boolean[];
  index?: number | number[];
}

export function buildAnswer(question: Question, state: SelectionState): Answer {
  if (question.mode === "input") {
    const value = state.customValue;
    return { id: question.id, mode: question.mode, value, label: value, wasCustom: true };
  }

  const selectedOptions = state.selectedIndexes.map((idx) => question.options[idx]);
  const optionValues = selectedOptions.map((opt) => opt.value);
  const optionLabels = selectedOptions.map((opt) => opt.label);
  const optionIndexes = state.selectedIndexes.map((idx) => idx + 1);

  if (question.mode === "single") {
    if (state.customValue) {
      return { id: question.id, mode: question.mode, value: state.customValue, label: state.customValue, wasCustom: true };
    }
    return {
      id: question.id,
      mode: question.mode,
      value: optionValues[0],
      label: optionLabels[0],
      wasCustom: false,
      index: optionIndexes[0],
    };
  }

  const values = state.customValue ? [...optionValues, state.customValue] : optionValues;
  const labels = state.customValue ? [...optionLabels, state.customValue] : optionLabels;
  const wasCustom = state.customValue
    ? [...optionValues.map(() => false), true]
    : optionValues.map(() => false);
  return {
    id: question.id,
    mode: question.mode,
    value: values,
    label: labels,
    wasCustom,
    index: optionIndexes,
  };
}
```

**Step 4: Run tests to verify pass**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: PASS.

**Step 5: Commit**

Run:
```bash
git add tests/askuserquestion.test.ts extensions/pi/AskUserQuestion/model.ts
git commit -m "feat: add AskUserQuestion answer builder"
```

---

### Task 4: Update AskUserQuestion schema and normalization

**Files:**
- Modify: `extensions/pi/AskUserQuestion/index.ts`
- Modify: `extensions/pi/AskUserQuestion/model.ts`

**Step 1: Write failing test for legacy params normalization**

Append to `tests/askuserquestion.test.ts`:
```ts
const normalized = normalizeQuestions({
  mode: "input",
  question: "Free text",
  allowEmpty: false,
});
assert.equal(normalized[0].mode, "input");
assert.equal(normalized[0].allowEmpty, false);
```

**Step 2: Run tests to verify failure**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: FAIL if allowEmpty is not respected.

**Step 3: Update normalizeQuestions to respect allowEmpty false**

Update `normalizeQuestions`:
```ts
allowEmpty: q.allowEmpty !== false,
```
and in the legacy normalization:
```ts
allowEmpty: params.allowEmpty !== false,
```

**Step 4: Run tests to verify pass**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: PASS.

**Step 5: Update AskUserQuestion schema + types**

Modify `extensions/pi/AskUserQuestion/index.ts`:
- Replace the old `options` schema with `QuestionOptionSchema` and add `QuestionSchema` and `questions` array.
- Update parameters to accept either `questions` or legacy fields.
- Remove string-only option support.

**Step 6: Commit**

Run:
```bash
git add tests/askuserquestion.test.ts extensions/pi/AskUserQuestion/index.ts extensions/pi/AskUserQuestion/model.ts
git commit -m "refactor: unify AskUserQuestion params"
```

---

### Task 5: Implement UI updates and result shape

**Files:**
- Modify: `extensions/pi/AskUserQuestion/index.ts`

**Step 1: Write a failing test for answer shape**

Append to `tests/askuserquestion.test.ts`:
```ts
const inputQuestion = {
  id: "q3",
  mode: "input",
  prompt: "Type",
  options: [],
  allowCustom: true,
  customLabel: "Other",
  allowEmpty: true,
};
const inputAnswer = buildAnswer(inputQuestion, { selectedIndexes: [], customValue: "hello" });
assert.equal(inputAnswer.value, "hello");
assert.equal(inputAnswer.wasCustom, true);
```

**Step 2: Run tests to verify failure**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: FAIL if buildAnswer does not handle input mode.

**Step 3: Implement UI changes in `index.ts`**

- Normalize params via `normalizeQuestions`.
- Use `buildRenderOptions` and `resolveDefaults` to seed selection state.
- Add tabbed multi-question UI (questionnaire-style) and Submit tab.
- For multi-select questions, add a review screen before confirming.
- Enforce `allowEmpty` by keeping editor open until non-empty when false.
- Use `buildAnswer` to produce `Answer` objects and return `{ cancelled, questions, answers }`.

**Step 4: Run tests to verify pass**

Run:
```bash
pnpm exec tsx tests/askuserquestion.test.ts
```
Expected: PASS.

**Step 5: Commit**

Run:
```bash
git add extensions/pi/AskUserQuestion/index.ts tests/askuserquestion.test.ts
git commit -m "feat: update AskUserQuestion UI flow"
```

---

### Task 6: Update renderers + validation

**Files:**
- Modify: `extensions/pi/AskUserQuestion/index.ts`

**Step 1: Update renderCall to truncate labels**

Use `truncateToWidth` on option labels and show `questions` count for multi-question inputs.

**Step 2: Update renderResult for new answer shape**

- Show `cancelled` when true.
- Display multi-select arrays and custom entries using `wasCustom`.

**Step 3: Run type-check**

Run:
```bash
./tests/test-pi-extensions.sh
```
Expected: PASS.

**Step 4: Manual smoke checks**

- Single input with `allowEmpty: false`.
- Single select with `defaultValue`.
- Multi select with `defaultValues` + custom input + review screen.
- Multi-question tab navigation and Submit summary.

**Step 5: Commit**

Run:
```bash
git add extensions/pi/AskUserQuestion/index.ts
git commit -m "refactor: refresh AskUserQuestion rendering"
```

---

Plan complete and saved to `docs/plans/2026-01-18-askuserquestion-implementation.md`. Two execution options:

1. **Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

2. **Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

Which approach?
