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
