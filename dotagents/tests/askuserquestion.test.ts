import assert from "node:assert/strict";
import { normalizeQuestions, buildRenderOptions, resolveDefaults } from "../extensions/pi/AskUserQuestion/model";

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
