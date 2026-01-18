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

interface RawQuestion {
  id?: string;
  mode: QuestionMode;
  prompt: string;
  options?: QuestionOption[];
  allowCustom?: boolean;
  customLabel?: string;
  allowEmpty?: boolean;
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
  questions?: RawQuestion[];
}

function normalizeQuestion(question: RawQuestion, index: number): Question {
  return {
    id: question.id ?? `q${index + 1}`,
    mode: question.mode,
    prompt: question.prompt,
    options: question.options ?? [],
    allowCustom: question.allowCustom !== false,
    customLabel: question.customLabel || "Type something.",
    allowEmpty: question.allowEmpty !== false,
    defaultValue: question.defaultValue,
    defaultValues: question.defaultValues,
  };
}

export function normalizeQuestions(params: SingleParams): Question[] {
  if (Array.isArray(params.questions) && params.questions.length > 0) {
    return params.questions.map(normalizeQuestion);
  }

  return [
    normalizeQuestion(
      {
        id: "q1",
        mode: params.mode,
        prompt: params.question,
        options: params.options ?? [],
        allowCustom: params.allowCustom,
        customLabel: params.customLabel,
        allowEmpty: params.allowEmpty,
        defaultValue: params.defaultValue,
        defaultValues: params.defaultValues,
      },
      0,
    ),
  ];
}

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
