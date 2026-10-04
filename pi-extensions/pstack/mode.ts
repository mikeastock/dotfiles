export const MODE_ENTRY_TYPE = "pstack-poteto-mode";

export interface PotetoModeState {
	enabled: boolean;
	skillPath?: string;
}

// Only Pi's own `/skill:poteto-mode` expansion counts: it puts the block first, at the installed skill path.
// A block quoted later in a prompt (a pasted transcript, a subagent report) must not switch the mode on or
// point the per-turn reminder at an arbitrary file.
const SKILL_BLOCK = /^<skill name="poteto-mode" location="([^"]+\/poteto-mode\/SKILL\.md)">/;

/** Returns the skill path when the prompt is an expanded `/skill:poteto-mode` invocation. */
export function potetoSkillInvocation(prompt: string): string | undefined {
	return prompt.match(SKILL_BLOCK)?.[1];
}

export function restoreModeState(entries: ReadonlyArray<{ type: string; customType?: string; data?: unknown }>): PotetoModeState {
	let state: PotetoModeState = { enabled: false };
	for (const entry of entries) {
		if (entry.type === "custom" && entry.customType === MODE_ENTRY_TYPE && entry.data) {
			state = entry.data as PotetoModeState;
		}
	}
	return state;
}

export function modeReminder(state: PotetoModeState): string {
	const skill = state.skillPath ? `\`${state.skillPath}\`` : "the poteto-mode skill (`/skill:poteto-mode`)";
	return [
		"Poteto mode is on for this session (sticky across turns).",
		`New task? If a playbook matches or the task needs rigor, apply ${skill}: read it in full if it is not already in context, then follow it.`,
		"Casual turn, or the user opts out in their own words: don't apply it.",
		"The user can turn the mode off with `/poteto-mode off`.",
	].join("\n");
}

export function sessionSection(sessionFile: string, sessionDir: string): string {
	return [
		`Current Pi session transcript: \`${sessionFile}\` (JSONL, one entry per line).`,
		`This workspace's session transcripts: \`${sessionDir}\`. pstack skills that read transcripts stay inside this directory.`,
	].join("\n");
}

export function modelsSection(content: string, filePath: string): string {
	return [
		`pstack per-role model choices from \`${filePath}\` (written by the setup-pstack skill).`,
		"These override the model defaults named in pstack skills. Pass the value as the `model` of a `task` entry; `inherit-parent` or `auto` means omit `model`.",
		"",
		content.trim(),
	].join("\n");
}
