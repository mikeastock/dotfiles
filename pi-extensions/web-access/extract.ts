import pLimit from "p-limit";
import { extractGitHub } from "./github-extract.js";
import { fetchContents, type ExaContentsResult } from "./exa.js";

const CONCURRENT_LIMIT = 3;
const fetchLimit = pLimit(CONCURRENT_LIMIT);

export interface ExtractedContent {
	url: string;
	title: string;
	content: string;
	error: string | null;
}

export interface ExtractOptions {
	forceClone?: boolean;
}

export function extractHeadingTitle(text: string): string | null {
	const match = text.match(/^#{1,2}\s+(.+)/m);
	if (!match) return null;
	const cleaned = match[1].replace(/\*+/g, "").trim();
	return cleaned || null;
}

function exaResultToContent(r: ExaContentsResult): ExtractedContent {
	if (!r.text) {
		return { url: r.url, title: r.title, content: "", error: "Exa returned no content for this URL" };
	}
	return { url: r.url, title: r.title || extractHeadingTitle(r.text) || r.url, content: r.text, error: null };
}

export async function extractContent(
	url: string,
	signal?: AbortSignal,
	options?: ExtractOptions,
): Promise<ExtractedContent> {
	if (signal?.aborted) {
		return { url, title: "", content: "", error: "Aborted" };
	}

	try {
		new URL(url);
	} catch {
		return { url, title: "", content: "", error: "Invalid URL" };
	}

	// GitHub URLs get cloned locally
	try {
		const ghResult = await extractGitHub(url, signal, options?.forceClone);
		if (ghResult) return ghResult;
	} catch {}

	// Everything else goes through Exa /contents
	try {
		const response = await fetchContents([url], { signal });
		const result = response.results[0];
		if (result) return exaResultToContent(result);

		const status = response.statuses.find(s => s.id === url);
		const error = status ? `Exa: ${status.status}` : "Exa returned no results";
		return { url, title: "", content: "", error };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { url, title: "", content: "", error: message };
	}
}

export async function fetchAllContent(
	urls: string[],
	signal?: AbortSignal,
	options?: ExtractOptions,
): Promise<ExtractedContent[]> {
	// Separate GitHub URLs from regular URLs
	const githubUrls: string[] = [];
	const regularUrls: string[] = [];

	for (const url of urls) {
		try {
			const parsed = new URL(url);
			if (parsed.hostname === "github.com") {
				githubUrls.push(url);
			} else {
				regularUrls.push(url);
			}
		} catch {
			regularUrls.push(url);
		}
	}

	const results: ExtractedContent[] = [];

	// GitHub URLs: extract individually (cloning)
	const ghResults = await Promise.all(
		githubUrls.map(url => fetchLimit(() => extractContent(url, signal, options)))
	);
	results.push(...ghResults);

	// Regular URLs: batch through Exa /contents
	if (regularUrls.length > 0) {
		try {
			const response = await fetchContents(regularUrls, { signal });
			const statusMap = new Map(response.statuses.map(s => [s.id, s.status]));

			for (const url of regularUrls) {
				const result = response.results.find(r => r.url === url);
				if (result) {
					results.push(exaResultToContent(result));
				} else {
					const status = statusMap.get(url);
					results.push({
						url,
						title: "",
						content: "",
						error: status ? `Exa: ${status}` : "Exa returned no content",
					});
				}
			}
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			for (const url of regularUrls) {
				results.push({ url, title: "", content: "", error: message });
			}
		}
	}

	return results;
}
