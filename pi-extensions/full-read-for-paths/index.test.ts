import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { normalizeReadInputForFullReadPaths } from "./index.js";

describe("normalizeReadInputForFullReadPaths", () => {
	it("removes offset and limit when a matching path is read partially", () => {
		const input = { path: "docs/design/example.md", offset: 20, limit: 50 };

		const changed = normalizeReadInputForFullReadPaths(input, "/repo", [/\/repo\/docs\/design\//]);

		assert.equal(changed, true);
		assert.deepEqual(input, { path: "docs/design/example.md" });
	});

	it("removes offset and limit for README files by default", () => {
		const input = { path: "README.md", offset: 1, limit: 20 };

		const changed = normalizeReadInputForFullReadPaths(input, "/repo");

		assert.equal(changed, true);
		assert.deepEqual(input, { path: "README.md" });
	});

	it("leaves full reads and non-matching paths unchanged", () => {
		const fullRead = { path: "docs/design/example.md" };
		const partialNonMatch = { path: "src/index.ts", offset: 10, limit: 5 };

		assert.equal(normalizeReadInputForFullReadPaths(fullRead, "/repo", [/\/repo\/docs\/design\//]), false);
		assert.equal(normalizeReadInputForFullReadPaths(partialNonMatch, "/repo", [/\/repo\/docs\/design\//]), false);
		assert.deepEqual(fullRead, { path: "docs/design/example.md" });
		assert.deepEqual(partialNonMatch, { path: "src/index.ts", offset: 10, limit: 5 });
	});
});
