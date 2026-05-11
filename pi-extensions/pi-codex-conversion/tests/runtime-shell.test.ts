import test from "node:test";
import assert from "node:assert/strict";
import { CODEX_FALLBACK_SHELL, getCodexRuntimeShell, isFishShell } from "../src/adapter/runtime-shell.ts";

test("getCodexRuntimeShell coerces fish to bash and preserves non-fish shells", () => {
	assert.equal(isFishShell("/usr/bin/fish"), true);
	assert.equal(isFishShell("fish"), true);
	assert.equal(isFishShell("/bin/bash"), false);

	assert.equal(getCodexRuntimeShell("/usr/bin/fish"), CODEX_FALLBACK_SHELL);
	assert.equal(getCodexRuntimeShell("fish"), CODEX_FALLBACK_SHELL);
	assert.equal(getCodexRuntimeShell("/bin/zsh"), "/bin/zsh");
	assert.equal(getCodexRuntimeShell(undefined), CODEX_FALLBACK_SHELL);
});
