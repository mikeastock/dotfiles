import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildTerraformApplyPrompt } from "./index.js";

const RPC_TITLE_MAX_LENGTH = 160;
const RPC_MESSAGE_MAX_LENGTH = 8192;

describe("buildTerraformApplyPrompt", () => {
	it("keeps the title within RPC host limits and shows the full command in the message", () => {
		const command =
			'export OP_SERVICE_ACCOUNT_TOKEN="$(cat /data/workspace/1password-service-tokens/bizops-infra-devbox-token)"\nmise run terraform -- apply -input=false plan.tfplan';
		const prompt = buildTerraformApplyPrompt(command);

		assert.ok(prompt.title.length <= RPC_TITLE_MAX_LENGTH);
		assert.ok(!prompt.title.includes("\n"));
		assert.equal(prompt.message, command);
	});

	it("truncates huge commands so the message stays within RPC host limits", () => {
		const command = `terraform apply ${"-var=x ".repeat(3_000)}`;
		const prompt = buildTerraformApplyPrompt(command);

		assert.ok(prompt.message.length <= RPC_MESSAGE_MAX_LENGTH);
		assert.ok(prompt.message.startsWith("terraform apply -var=x"));
		assert.match(prompt.message, /truncated/);
	});
});
