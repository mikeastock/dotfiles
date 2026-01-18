import assert from "node:assert/strict";
import {
  normalizeQuestions,
  buildRenderOptions,
  resolveDefaults,
  buildAnswer,
} from "../extensions/pi/AskUserQuestion/model";
import { wrapQuestionLines } from "../extensions/pi/AskUserQuestion/text";

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

const normalized = normalizeQuestions({
  mode: "input",
  question: "Free text",
  allowEmpty: false,
});
assert.equal(normalized[0].mode, "input");
assert.equal(normalized[0].allowEmpty, false);

const longPrompt = "This is a long question that should wrap across lines";
const wrapped = wrapQuestionLines(longPrompt, 20, "");
assert.ok(wrapped.length > 1);
const combined = wrapped.join(" ").replace(/\s+/g, " ").trim();
assert.equal(combined, longPrompt);
