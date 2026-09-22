/**
 * Terraform Apply Gate Extension
 *
 * Prompts for explicit confirmation before running terraform/tf apply commands.
 * Prevents accidental infrastructure changes by requiring user approval.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const PROMPT_TITLE = "🏗️ Terraform apply — modify infrastructure?";
const PROMPT_MESSAGE_MAX_LENGTH = 8000;

// Keep the dialog title short and put the command in the message body.
// RPC hosts such as BB cap dialog titles (160 chars) and cancel longer ones,
// which silently turned long commands into "blocked by user".
export function buildTerraformApplyPrompt(command: string): { title: string; message: string } {
	const message =
		command.length > PROMPT_MESSAGE_MAX_LENGTH
			? `${command.slice(0, PROMPT_MESSAGE_MAX_LENGTH)}\n… (truncated, ${command.length} chars total)`
			: command;
	return { title: PROMPT_TITLE, message };
}

export default function (pi: ExtensionAPI) {
	// Match terraform apply or tf apply (with optional flags before/after)
	const terraformApplyPatterns = [
		/\b(terraform|tf)\s+apply\b/i,
		/\b(terraform|tf)\s+.*\bapply\b/i,
	];

	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;

		const command = event.input.command as string;
		const isTerraformApply = terraformApplyPatterns.some((p) => p.test(command));

		if (isTerraformApply) {
			if (!ctx.hasUI) {
				// In non-interactive mode, block by default
				return { block: true, reason: "Terraform apply blocked (no UI for confirmation)" };
			}

			const prompt = buildTerraformApplyPrompt(command);
			const allowed = await ctx.ui.confirm(prompt.title, prompt.message);

			if (!allowed) {
				ctx.ui.notify("Terraform apply cancelled", "info");
				return { block: true, reason: "Terraform apply blocked by user" };
			}
		}

		return undefined;
	});
}
