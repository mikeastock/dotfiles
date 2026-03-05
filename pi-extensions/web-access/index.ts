import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Text } from "@mariozechner/pi-tui";
import { Type } from "@sinclair/typebox";
import { StringEnum } from "@mariozechner/pi-ai";
import { searchWithExa, parseDomainFilters } from "./exa.js";
import { fetchAllContent } from "./extract.js";
import { clearCloneCache } from "./github-extract.js";

interface SearchResult {
	title: string;
	url: string;
	text: string;
}

function formatSearchSummary(results: SearchResult[], answer: string): string {
	let output = answer ? `${answer}\n\n---\n\n**Sources:**\n` : "";
	output += results.map((r, i) => `${i + 1}. ${r.title}\n   ${r.url}`).join("\n\n");
	return output;
}

export default function (pi: ExtensionAPI) {
	// --- Session lifecycle ---

	pi.on("session_start", async () => clearCloneCache());
	pi.on("session_switch", async () => clearCloneCache());
	pi.on("session_fork", async () => clearCloneCache());
	pi.on("session_tree", async () => clearCloneCache());
	pi.on("session_shutdown", () => clearCloneCache());

	// --- Tools ---

	pi.registerTool({
		name: "web_search",
		label: "Web Search",
		description:
			"Search the web using Exa AI. Returns semantically relevant results with source citations. " +
			"For comprehensive research, prefer queries (plural) with 2-4 varied angles over a single query. " +
			"When includeContent is true, full page text is returned inline with each result.",
		parameters: Type.Object({
			query: Type.Optional(Type.String({ description: "Single search query. For research tasks, prefer 'queries' with multiple varied angles instead." })),
			queries: Type.Optional(Type.Array(Type.String(), { description: "Multiple queries searched in sequence, each returning its own results." })),
			numResults: Type.Optional(Type.Number({ description: "Results per query (default: 5, max: 20)" })),
			includeContent: Type.Optional(Type.Boolean({ description: "Return full page text for each result (default: false, returns snippets)" })),
			recencyFilter: Type.Optional(
				StringEnum(["day", "week", "month", "year"], { description: "Filter by recency" }),
			),
			domainFilter: Type.Optional(Type.Array(Type.String(), { description: "Limit to domains (prefix with - to exclude)" })),
		}),

		async execute(_toolCallId, params, signal, onUpdate) {
			const queryList = params.queries ?? (params.query ? [params.query] : []);
			if (queryList.length === 0) {
				return {
					content: [{ type: "text", text: "Error: No query provided. Use 'query' or 'queries' parameter." }],
					details: { error: "No query provided" },
				};
			}

			const domainFilters = params.domainFilter ? parseDomainFilters(params.domainFilter) : null;

			interface QueryResultData {
				query: string;
				answer: string;
				results: SearchResult[];
				error: string | null;
			}

			const searchResults: QueryResultData[] = [];

			for (let i = 0; i < queryList.length; i++) {
				const query = queryList[i];
				onUpdate?.({
					content: [{ type: "text", text: `Searching ${i + 1}/${queryList.length}: "${query}"...` }],
					details: { phase: "search", progress: i / queryList.length, currentQuery: query },
				});

				try {
					const response = await searchWithExa(query, {
						numResults: params.numResults,
						includeContent: params.includeContent,
						recencyFilter: params.recencyFilter,
						includeDomains: domainFilters?.include,
						excludeDomains: domainFilters?.exclude,
						signal,
					});

					const results: SearchResult[] = response.results.map(r => ({
						title: r.title,
						url: r.url,
						text: r.text,
					}));

					searchResults.push({ query, answer: response.answer, results, error: null });
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					searchResults.push({ query, answer: "", results: [], error: message });
				}
			}

			const sc = searchResults.filter(r => !r.error).length;
			const tr = searchResults.reduce((sum, r) => sum + r.results.length, 0);

			let output = "";
			for (const { query, answer, results, error } of searchResults) {
				if (queryList.length > 1) output += `## Query: "${query}"\n\n`;
				if (error) output += `Error: ${error}\n\n`;
				else if (results.length === 0) output += "No results found.\n\n";
				else output += formatSearchSummary(results, answer) + "\n\n";
			}

			return {
				content: [{ type: "text", text: output.trim() }],
				details: {
					queries: queryList,
					queryCount: queryList.length,
					successfulQueries: sc,
					totalResults: tr,
				},
			};
		},

		renderCall(args, theme) {
			const { query, queries } = args as { query?: string; queries?: string[] };
			const queryList = queries ?? (query ? [query] : []);
			if (queryList.length === 0) {
				return new Text(theme.fg("toolTitle", theme.bold("search ")) + theme.fg("error", "(no query)"), 0, 0);
			}
			if (queryList.length === 1) {
				const display = queryList[0].length > 60 ? queryList[0].slice(0, 57) + "..." : queryList[0];
				return new Text(theme.fg("toolTitle", theme.bold("search ")) + theme.fg("accent", `"${display}"`), 0, 0);
			}
			const lines = [theme.fg("toolTitle", theme.bold("search ")) + theme.fg("accent", `${queryList.length} queries`)];
			for (const q of queryList.slice(0, 5)) {
				const display = q.length > 50 ? q.slice(0, 47) + "..." : q;
				lines.push(theme.fg("muted", `  "${display}"`));
			}
			if (queryList.length > 5) {
				lines.push(theme.fg("muted", `  ... and ${queryList.length - 5} more`));
			}
			return new Text(lines.join("\n"), 0, 0);
		},

		renderResult(result, { expanded, isPartial }, theme) {
			const details = result.details as {
				queryCount?: number;
				successfulQueries?: number;
				totalResults?: number;
				error?: string;
				phase?: string;
				progress?: number;
				currentQuery?: string;
			};

			if (isPartial) {
				const progress = details?.progress ?? 0;
				const bar = "\u2588".repeat(Math.floor(progress * 10)) + "\u2591".repeat(10 - Math.floor(progress * 10));
				const query = details?.currentQuery || "";
				const display = query.length > 40 ? query.slice(0, 37) + "..." : query;
				return new Text(theme.fg("accent", `[${bar}] ${display}`), 0, 0);
			}

			if (details?.error) {
				return new Text(theme.fg("error", `Error: ${details.error}`), 0, 0);
			}

			const queryInfo = details?.queryCount === 1 ? "" : `${details?.successfulQueries}/${details?.queryCount} queries, `;
			const statusLine = theme.fg("success", `${queryInfo}${details?.totalResults ?? 0} sources`);

			if (!expanded) {
				const textContent = result.content.find((c) => c.type === "text")?.text || "";
				const firstLine = (textContent.split("\n").find(l => l.trim() && !l.startsWith("[") && !l.startsWith("#") && !l.startsWith("---"))?.trim() || "").replace(/\*\*/g, "");
				const preview = firstLine.length > 80 ? firstLine.slice(0, 77) + "..." : firstLine;
				if (preview) {
					return new Text(statusLine + "\n" + theme.fg("dim", preview), 0, 0);
				}
				return new Text(statusLine, 0, 0);
			}

			const lines = [statusLine];
			const textContent = result.content.find((c) => c.type === "text")?.text || "";
			const preview = textContent.length > 500 ? textContent.slice(0, 500) + "..." : textContent;
			lines.push(theme.fg("dim", preview));

			return new Text(lines.join("\n"), 0, 0);
		},
	});

	pi.registerTool({
		name: "fetch_content",
		label: "Fetch Content",
		description:
			"Fetch URL(s) and extract readable content as markdown. " +
			"GitHub URLs are cloned locally for full file access. " +
			"All other URLs are extracted via Exa AI's content parser.",
		parameters: Type.Object({
			url: Type.Optional(Type.String({ description: "Single URL to fetch" })),
			urls: Type.Optional(Type.Array(Type.String(), { description: "Multiple URLs (parallel)" })),
			forceClone: Type.Optional(Type.Boolean({
				description: "Force cloning large GitHub repositories that exceed the size threshold",
			})),
		}),

		async execute(_toolCallId, params, signal, onUpdate) {
			const urlList = params.urls ?? (params.url ? [params.url] : []);
			if (urlList.length === 0) {
				return {
					content: [{ type: "text", text: "Error: No URL provided." }],
					details: { error: "No URL provided" },
				};
			}

			onUpdate?.({
				content: [{ type: "text", text: `Fetching ${urlList.length} URL(s)...` }],
				details: { phase: "fetch", progress: 0 },
			});

			const fetchResults = await fetchAllContent(urlList, signal, {
				forceClone: params.forceClone,
			});
			const successful = fetchResults.filter((r) => !r.error).length;
			const totalChars = fetchResults.reduce((sum, r) => sum + r.content.length, 0);

			if (urlList.length === 1) {
				const result = fetchResults[0];
				if (result.error) {
					return {
						content: [{ type: "text", text: `Error: ${result.error}` }],
						details: { urls: urlList, urlCount: 1, successful: 0, error: result.error },
					};
				}

				return {
					content: [{ type: "text", text: result.content }],
					details: {
						urls: urlList, urlCount: 1, successful: 1,
						totalChars: result.content.length, title: result.title,
					},
				};
			}

			let output = "";
			for (const { url, title, content, error } of fetchResults) {
				output += `## ${title || url}\n`;
				output += `URL: ${url}\n\n`;
				if (error) {
					output += `Error: ${error}\n\n`;
				} else {
					output += `${content}\n\n`;
				}
				output += "---\n\n";
			}

			return {
				content: [{ type: "text", text: output.trim() }],
				details: { urls: urlList, urlCount: urlList.length, successful, totalChars },
			};
		},

		renderCall(args, theme) {
			const { url, urls } = args as { url?: string; urls?: string[] };
			const urlList = urls ?? (url ? [url] : []);
			if (urlList.length === 0) {
				return new Text(theme.fg("toolTitle", theme.bold("fetch ")) + theme.fg("error", "(no URL)"), 0, 0);
			}
			if (urlList.length === 1) {
				const display = urlList[0].length > 60 ? urlList[0].slice(0, 57) + "..." : urlList[0];
				return new Text(theme.fg("toolTitle", theme.bold("fetch ")) + theme.fg("accent", display), 0, 0);
			}
			const lines = [theme.fg("toolTitle", theme.bold("fetch ")) + theme.fg("accent", `${urlList.length} URLs`)];
			for (const u of urlList.slice(0, 5)) {
				const display = u.length > 60 ? u.slice(0, 57) + "..." : u;
				lines.push(theme.fg("muted", "  " + display));
			}
			if (urlList.length > 5) {
				lines.push(theme.fg("muted", `  ... and ${urlList.length - 5} more`));
			}
			return new Text(lines.join("\n"), 0, 0);
		},

		renderResult(result, { expanded, isPartial }, theme) {
			const details = result.details as {
				urlCount?: number;
				successful?: number;
				totalChars?: number;
				error?: string;
				title?: string;
				phase?: string;
				progress?: number;
			};

			if (isPartial) {
				const progress = details?.progress ?? 0;
				const bar = "\u2588".repeat(Math.floor(progress * 10)) + "\u2591".repeat(10 - Math.floor(progress * 10));
				return new Text(theme.fg("accent", `[${bar}] ${details?.phase || "fetching"}`), 0, 0);
			}

			if (details?.error) {
				return new Text(theme.fg("error", `Error: ${details.error}`), 0, 0);
			}

			if (details?.urlCount === 1) {
				const title = details?.title || "Untitled";
				const statusLine = theme.fg("success", title) + theme.fg("muted", ` (${details?.totalChars ?? 0} chars)`);

				const textContent = result.content.find((c) => c.type === "text")?.text || "";
				if (!expanded) {
					const brief = textContent.length > 200 ? textContent.slice(0, 200) + "..." : textContent;
					return new Text(statusLine + "\n" + theme.fg("dim", brief), 0, 0);
				}
				const preview = textContent.length > 500 ? textContent.slice(0, 500) + "..." : textContent;
				return new Text(statusLine + "\n" + theme.fg("dim", preview), 0, 0);
			}

			const countColor = (details?.successful ?? 0) > 0 ? "success" : "error";
			const statusLine = theme.fg(countColor, `${details?.successful}/${details?.urlCount} URLs`) + theme.fg("muted", ` (${details?.totalChars ?? 0} chars)`);
			if (!expanded) return new Text(statusLine, 0, 0);
			const textContent = result.content.find((c) => c.type === "text")?.text || "";
			const preview = textContent.length > 500 ? textContent.slice(0, 500) + "..." : textContent;
			return new Text(statusLine + "\n" + theme.fg("dim", preview), 0, 0);
		},
	});
}
