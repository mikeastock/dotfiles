import type { HandoffOptions } from "./effective-options.js";

export type ToolHandoffParams = {
	goal: string;
} & HandoffOptions;

export type ToolHandoffContext = {
	hasUI: boolean;
	ui: {
		setEditorText(text: string): void;
		notify(message: string, type?: "info" | "warning" | "error"): void;
	};
};

export function buildHandoffCommand(params: ToolHandoffParams): string {
	const parts = ["/handoff"];
	if (params.mode) {
		parts.push(`-mode ${params.mode}`);
	}
	if (params.model) {
		parts.push(`-model ${params.model}`);
	}
	parts.push(params.goal);
	return parts.join(" ");
}

export function prepareToolHandoff(ctx: ToolHandoffContext, params: ToolHandoffParams) {
	if (!ctx.hasUI) {
		return {
			content: [
				{
					type: "text" as const,
					text: "Handoff via the handoff tool requires interactive mode. Run `/handoff ...` in an interactive Pi session.",
				},
			],
			details: { ok: false },
		};
	}

	const command = buildHandoffCommand(params);
	ctx.ui.setEditorText(command);
	ctx.ui.notify("Handoff command ready in editor. Submit to continue.", "info");
	return {
		content: [
			{
				type: "text" as const,
				text: "Prepared a `/handoff ...` command in the editor. Submit it to create the new session safely.",
			},
		],
		details: {
			ok: true,
			command,
			requiresUserSubmit: true,
		},
	};
}
