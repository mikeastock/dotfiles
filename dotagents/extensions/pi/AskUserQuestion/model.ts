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
