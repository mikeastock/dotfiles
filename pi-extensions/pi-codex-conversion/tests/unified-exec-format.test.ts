import test from "node:test";
import assert from "node:assert/strict";
import { formatUnifiedExecResult } from "../src/tools/unified-exec-format.ts";

test("formatUnifiedExecResult matches codex-style response text", () => {
	const text = formatUnifiedExecResult(
		{
			chunk_id: "abc123",
			wall_time_seconds: 0.5,
			output: "hello\nworld",
			exit_code: 0,
			original_token_count: 3,
		},
		"printf hello",
	);

	assert.equal(
		text,
		[
			"Command: printf hello",
			"Chunk ID: abc123",
			"Wall time: 0.5000 seconds",
			"Process exited with code 0",
			"Original token count: 3",
			"Output:",
			"hello\nworld",
		].join("\n"),
	);
});
