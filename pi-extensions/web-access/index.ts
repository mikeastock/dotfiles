import { StringEnum } from "@earendil-works/pi-ai";
import {
	DEFAULT_MAX_BYTES,
	DEFAULT_MAX_LINES,
	formatSize,
	truncateHead,
	type AgentToolResult,
	type ExtensionAPI,
	type Theme,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Type } from "typebox";
import { fetchPages, search, type FetchedPage, type SearchResponse } from "./exa.ts";
import { fetchGitHub, removeClones } from "./github.ts";

const LIMITS = `Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}; the full text is then saved to a file you can read.`;
const READ_ONLY_WEB = { readOnlyHint: true, openWorldHint: true };

interface WebDetails {
	summary: string;
	fullOutputPath?: string;
}

/** Keep model-facing output within Pi's limits; save the complete text to a file when it overflows. */
function toolResult(text: string, summary: string) {
	const truncation = truncateHead(text, { maxLines: DEFAULT_MAX_LINES, maxBytes: DEFAULT_MAX_BYTES });
	if (!truncation.truncated) return { content: [{ type: "text" as const, text }], details: { summary } as WebDetails };

	const fullOutputPath = join(mkdtempSync(join(tmpdir(), "pi-web-")), "output.md");
	writeFileSync(fullOutputPath, text);
	const note = `\n\n[Truncated: showing ${truncation.outputLines} of ${truncation.totalLines} lines. Full output: ${fullOutputPath}]`;
	return {
		content: [{ type: "text" as const, text: truncation.content + note }],
		details: { summary, fullOutputPath } as WebDetails,
	};
}

function nonEmpty(single: string | undefined, many: string[] | undefined): string[] {
	return [...(many ?? []), ...(single ? [single] : [])].map((s) => s.trim()).filter(Boolean);
}

function formatSearch(query: string, response: SearchResponse): string {
	const lines = response.notices.map((notice) => `Notice: ${notice}`);
	if (response.results.length === 0) lines.push("No results.");
	response.results.forEach((r, i) => {
		const date = r.publishedDate ? ` (${r.publishedDate.slice(0, 10)})` : "";
		lines.push(`### ${i + 1}. ${r.title}${date}\n${r.url}${r.excerpt ? `\n\n${r.excerpt}` : ""}`);
	});
	return `## ${query}\n\n${lines.join("\n\n")}`;
}

function formatPage({ url, page, error }: FetchedPage): string {
	return page ? `# ${page.title}\n${page.url}\n\n${page.text}` : `# ${url}\n\nError: ${error}`;
}

function renderCall(label: string, items: string[], theme: Theme) {
	const shown = items.length > 1 ? `${items[0]} (+${items.length - 1} more)` : (items[0] ?? "");
	return new Text(theme.fg("toolTitle", theme.bold(`${label} `)) + theme.fg("accent", shown), 0, 0);
}

/** One summary line; the expanded view adds the start of the model-facing text. Errors have no details and show their message. */
function renderResult(result: AgentToolResult<unknown>, expanded: boolean, theme: Theme) {
	const body = result.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
	const details = result.details as WebDetails | undefined;
	if (!details) return new Text(theme.fg("error", body), 0, 0);

	const saved = details.fullOutputPath ? ` · full output: ${details.fullOutputPath}` : "";
	const preview = expanded ? `\n${theme.fg("dim", body.split("\n").slice(0, 40).join("\n"))}` : "";
	return new Text(theme.fg("muted", details.summary + saved) + preview, 0, 0);
}

export default function (pi: ExtensionAPI) {
	pi.on("session_shutdown", () => removeClones());

	pi.registerTool({
		name: "web_search",
		label: "Web Search",
		description:
			"Search the web with Exa. Returns ranked sources with URLs, publish dates, and query-relevant excerpts. " +
			"Pass several phrasings in 'queries' to search different angles in parallel. " +
			"Use fetch_content to read a full page. " +
			LIMITS,
		promptSnippet: "Search the web for current information, documentation, and sources",
		annotations: READ_ONLY_WEB,
		parameters: Type.Object({
			query: Type.Optional(Type.String({ description: "Search query." })),
			queries: Type.Optional(Type.Array(Type.String(), { description: "Several queries searched in parallel, each with its own results." })),
			objective: Type.Optional(
				Type.String({
					maxLength: 4096,
					description: "Goal for this search: which documents should rank first, which to exclude, and what facts to extract.",
				}),
			),
			numResults: Type.Optional(Type.Integer({ minimum: 1, maximum: 20, description: "Results per query (default 5)." })),
			recency: Type.Optional(StringEnum(["day", "week", "month", "year"] as const, { description: "Only pages published within this window." })),
			domains: Type.Optional(
				Type.Array(Type.String(), {
					description: "Restrict to domains or paths (example.com, example.com/docs, *.example.com). Prefix with - to exclude.",
				}),
			),
		}),

		async execute(_toolCallId, params, signal) {
			const queries = nonEmpty(params.query, params.queries);
			if (queries.length === 0) throw new Error("Provide 'query' or 'queries'.");

			const settled = await Promise.allSettled(
				queries.map((query) =>
					search(query, {
						numResults: params.numResults,
						objective: params.objective,
						recency: params.recency,
						domains: params.domains,
						signal,
					}),
				),
			);
			signal?.throwIfAborted();

			const failures = settled.filter((s) => s.status === "rejected");
			if (failures.length === queries.length) throw (failures[0] as PromiseRejectedResult).reason;

			const sections = settled.map((s, i) =>
				s.status === "fulfilled" ? formatSearch(queries[i], s.value) : `## ${queries[i]}\n\nError: ${s.reason instanceof Error ? s.reason.message : s.reason}`,
			);
			const sources = settled.reduce((n, s) => n + (s.status === "fulfilled" ? s.value.results.length : 0), 0);
			const failed = failures.length > 0 ? `, ${failures.length} failed` : "";
			return toolResult(sections.join("\n\n---\n\n"), `${sources} sources from ${queries.length} queries${failed}`);
		},

		renderCall: (args, theme) => renderCall("search", nonEmpty(args.query, args.queries), theme),
		renderResult: (result, { expanded }, theme) => renderResult(result, expanded, theme),
	});

	pi.registerTool({
		name: "fetch_content",
		label: "Fetch Content",
		description:
			"Read web pages as clean text via Exa (cached, with a live crawl when the page is not cached). " +
			"GitHub repository, tree, and blob URLs are shallow-cloned instead, returning the local clone path, file list, and README or file content. " +
			LIMITS,
		promptSnippet: "Read web pages, docs, and GitHub repositories as text",
		annotations: READ_ONLY_WEB,
		parameters: Type.Object({
			url: Type.Optional(Type.String({ description: "URL to fetch." })),
			urls: Type.Optional(Type.Array(Type.String(), { description: "Several URLs fetched together." })),
			fresh: Type.Optional(Type.Boolean({ description: "Skip Exa's cache and crawl the live page. Slower; use when cached content may be stale." })),
		}),

		async execute(_toolCallId, params, signal) {
			const urls = nonEmpty(params.url, params.urls);
			if (urls.length === 0) throw new Error("Provide 'url' or 'urls'.");

			const invalid = urls.filter((url) => !URL.canParse(url));
			if (invalid.length > 0) throw new Error(`Invalid URL: ${invalid.join(", ")}`);

			const github = await Promise.all(urls.map((url) => fetchGitHub(url, signal)));
			const rest = urls.filter((_, i) => !github[i]);
			const fetched = rest.length > 0 ? await fetchPages(rest, { fresh: params.fresh, signal }) : [];

			const pages = urls.map((url, i): FetchedPage => {
				const page = github[i];
				return page ? { url, page } : fetched.find((f) => f.url === url)!;
			});
			const ok = pages.filter((p) => p.page).length;
			if (ok === 0) throw new Error(pages.map((p) => `${p.url}: ${p.error}`).join("\n"));

			const text = pages.map(formatPage).join("\n\n---\n\n");
			return toolResult(text, `${ok}/${urls.length} pages, ${formatSize(Buffer.byteLength(text))}`);
		},

		renderCall: (args, theme) => renderCall("fetch", nonEmpty(args.url, args.urls), theme),
		renderResult: (result, { expanded }, theme) => renderResult(result, expanded, theme),
	});
}
