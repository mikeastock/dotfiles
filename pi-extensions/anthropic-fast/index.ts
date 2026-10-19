import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// Anthropic fast mode is a request field, which models.json cannot set for anthropic-messages.
// The `anthropic-fast` provider in ~/.pi/agent/models.json selects it; this adds the field.
// https://platform.claude.com/docs/en/build-with-claude/fast-mode
const PROVIDER = "anthropic-fast";

export default function anthropicFastExtension(pi: ExtensionAPI): void {
	pi.on("before_provider_request", (event, ctx) => {
		if (ctx.model?.provider !== PROVIDER) return;
		if (typeof event.payload !== "object" || event.payload === null) return;
		return { ...event.payload, speed: "fast" };
	});
}
