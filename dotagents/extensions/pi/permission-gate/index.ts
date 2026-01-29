/**
 * Permission Gate Extension
 *
 * Prompts for confirmation before running potentially dangerous bash commands.
 * Patterns checked: rm -rf, sudo, chmod/chown 777, heroku sensitive commands
 *
 * SSH commands are excluded since they run on remote machines.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const WAIT_EVENT = "agent-status:wait";
const WAIT_SOURCE = "permission-gate";

function emitWait(pi: ExtensionAPI, active: boolean) {
	pi.events.emit(WAIT_EVENT, { active, source: WAIT_SOURCE });
}

export default function (pi: ExtensionAPI) {
	const dangerousPatterns = [
		// File system destructive operations
		/\brm\s+(-rf?|--recursive)/i,
		/\bsudo\b/i,
		/\b(chmod|chown)\b.*777/i,

		// Heroku database commands (direct access, resets, data movement)
		/\bheroku\s+pg:psql\b/i,
		/\bheroku\s+pg:reset\b/i,
		/\bheroku\s+pg:push\b/i,
		/\bheroku\s+pg:pull\b/i,
		/\bheroku\s+pg:copy\b/i,
		/\bheroku\s+pg:kill\b/i,
		/\bheroku\s+pg:killall\b/i,

		// Heroku destructive app operations
		/\bheroku\s+apps:destroy\b/i,
		/\bheroku\s+addons:destroy\b/i,
		/\bheroku\s+domains:clear\b/i,

		// Heroku config and release operations
		/\bheroku\s+config:set\b/i,
		/\bheroku\s+config:unset\b/i,
		/\bheroku\s+releases:rollback\b/i,

		// Heroku run (can execute arbitrary code on dyno)
		/\bheroku\s+run\b/i,
	];

	// Pattern to detect SSH commands (ssh user@host ... or ssh host ...)
	const sshPattern = /^\s*ssh\s+/i;

	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;

		const command = event.input.command as string;

		// Skip SSH commands - they run on remote machines
		if (sshPattern.test(command)) {
			return undefined;
		}

		const isDangerous = dangerousPatterns.some((p) => p.test(command));

		if (isDangerous) {
			if (!ctx.hasUI) {
				// In non-interactive mode, block by default
				return { block: true, reason: "Dangerous command blocked (no UI for confirmation)" };
			}

			emitWait(pi, true);
			let choice: string | undefined;
			try {
				choice = await ctx.ui.select(`⚠️ Dangerous command:\n\n ${command}\n\nAllow?`, ["Yes", "No"]);
			} finally {
				emitWait(pi, false);
			}

			if (choice !== "Yes") {
				return { block: true, reason: "Blocked by user" };
			}
		}

		return undefined;
	});
}
