export type HandoffOptions = {
	mode?: string;
	model?: string;
};

export function getEffectiveHandoffOptions(
	options: HandoffOptions | undefined,
	currentModel: string | undefined,
): HandoffOptions | undefined {
	if (options?.mode || options?.model) return options;
	if (!currentModel) return options;
	return { ...options, model: currentModel };
}
