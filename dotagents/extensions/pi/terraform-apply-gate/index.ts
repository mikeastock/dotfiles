/**
 * Terraform Apply Gate Extension
 *
 * Prompts for explicit confirmation before running terraform/tf apply commands.
 * Prevents accidental infrastructure changes by requiring user approval.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const WAIT_EVENT = "agent-status:wait";
const WAIT_SOURCE = "terraform-apply-gate";

function emitWait(pi: ExtensionAPI, active: boolean) {
	pi.events.emit(WAIT_EVENT, { active, source: WAIT_SOURCE });
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

			emitWait(pi, true);
			let choice: string | undefined;
			try {
				choice = await ctx.ui.select(
					`🏗️ Terraform Apply Detected:\n\n  ${command}\n\nThis will modify infrastructure. Proceed?`,
					["Yes, apply changes", "No, cancel"],
				);
			} finally {
				emitWait(pi, false);
			}

			if (choice !== "Yes, apply changes") {
				ctx.ui.notify("Terraform apply cancelled", "info");
				return { block: true, reason: "Terraform apply blocked by user" };
			}
		}

		return undefined;
	});
}
