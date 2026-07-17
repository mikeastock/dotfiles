import { resolve } from "node:path";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type, type Static } from "typebox";

import {
	shareArtifactFromHostPath,
	shareArtifactFromHtml,
	type ShareArtifactResult,
} from "./artifact-share.js";
import { createArtifactRuntimeConfig, type ArtifactRuntimeConfig } from "./config.js";

const shareArtifactSchema = Type.Object({
	label: Type.Optional(Type.String({ description: "Brief description of what you're sharing." })),
	path: Type.Optional(
		Type.String({ description: "Path to a local .html file or directory containing index.html." }),
	),
	html: Type.Optional(Type.String({ description: "Inline HTML content to publish as index.html." })),
});

type ShareArtifactParams = Static<typeof shareArtifactSchema>;

type NormalizedShareArtifactInput = { kind: "path"; path: string } | { kind: "html"; html: string };

export function normalizeShareArtifactInput(
	params: Pick<ShareArtifactParams, "path" | "html">,
): NormalizedShareArtifactInput {
	const path =
		typeof params.path === "string" && params.path.trim()
			? params.path.trim().replace(/^@/, "")
			: undefined;
	const html = typeof params.html === "string" && params.html.trim() ? params.html : undefined;

	if (Boolean(path) === Boolean(html)) {
		throw new Error("share_artifact requires exactly one of path or html.");
	}

	return path ? { kind: "path", path } : { html: html!, kind: "html" };
}

async function shareArtifact(
	params: ShareArtifactParams,
	ctx: { cwd: string },
	runtimeConfig: ArtifactRuntimeConfig,
	signal?: AbortSignal,
): Promise<ShareArtifactResult> {
	const input = normalizeShareArtifactInput(params);
	if (input.kind === "html") {
		return shareArtifactFromHtml({
			baseUrl: runtimeConfig.baseUrl,
			html: input.html,
			signal,
			upload: runtimeConfig.upload,
		});
	}

	return shareArtifactFromHostPath({
		baseUrl: runtimeConfig.baseUrl,
		hostPath: resolve(ctx.cwd, input.path),
		signal,
		upload: runtimeConfig.upload,
	});
}

export default function buildrArtifacts(pi: ExtensionAPI) {
	const runtimeConfigFactory = () => createArtifactRuntimeConfig(process.env);

	pi.registerTool({
		name: "share_artifact",
		label: "Share Artifact",
		description:
			"Share an HTML artifact and return a shareable URL. Uploads inline HTML, an .html file, or a directory containing index.html to Buildr artifact storage.",
		promptSnippet: "Share browser-viewable HTML artifacts and return a URL.",
		promptGuidelines: [
			"Use share_artifact when the user asks to create, publish, or share an HTML report, dashboard, prototype, or other browser-viewable artifact.",
		],
		parameters: shareArtifactSchema,
		async execute(_toolCallId, params, signal, onUpdate, ctx) {
			onUpdate?.({ content: [{ type: "text", text: "Uploading artifact..." }], details: {} });
			const result = await shareArtifact(params, ctx, runtimeConfigFactory(), signal);
			return {
				content: [{ type: "text" as const, text: result.url }],
				details: { label: params.label, slug: result.slug, url: result.url },
			};
		},
	});

	pi.registerCommand("share_artifact", {
		description: "Upload an HTML artifact and show the shareable URL",
		handler: async (args, ctx) => {
			const trimmedArgs = args.trim();
			const params: ShareArtifactParams = trimmedArgs
				? { path: trimmedArgs }
				: { html: await requireInlineHtml(ctx) };

			const result = await shareArtifact(params, ctx, runtimeConfigFactory());
			const message = `Artifact shared: ${result.url}`;
			ctx.ui.notify(message, "info");
			pi.sendMessage({
				customType: "buildr-artifacts",
				content: message,
				details: result,
				display: true,
			});
		},
	});
}

async function requireInlineHtml(ctx: {
	hasUI?: boolean;
	ui: { editor(title: string, initial?: string): Promise<string | undefined> };
}): Promise<string> {
	if (!ctx.hasUI) {
		throw new Error("/share_artifact with no path requires an interactive UI to enter inline HTML.");
	}

	const html = await ctx.ui.editor(
		"HTML artifact",
		"<!doctype html>\n<html>\n<body>\n\n</body>\n</html>\n",
	);
	if (!html?.trim()) {
		throw new Error("No HTML provided.");
	}
	return html;
}

export const _test = { normalizeShareArtifactInput };
