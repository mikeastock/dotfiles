import { getApiKey, API_BASE, DEFAULT_MODEL } from "./gemini-api.js";
import { isPerplexityAvailable, searchWithPerplexity, type SearchResult, type SearchResponse, type SearchOptions } from "./perplexity.js";

export type SearchProvider = "auto" | "perplexity" | "gemini";

export interface FullSearchOptions extends SearchOptions {
	provider?: SearchProvider;
}

export async function search(query: string, options: FullSearchOptions = {}): Promise<SearchResponse> {
	const provider = options.provider ?? "auto";

	if (provider === "perplexity") {
		return searchWithPerplexity(query, options);
	}

	if (provider === "gemini") {
		const result = await searchWithGeminiApi(query, options);
		if (result) return result;
		throw new Error("Gemini search unavailable. Set GEMINI_API_KEY in ~/.pi/web-search.json");
	}

	// Auto: prefer Perplexity, fall back to Gemini API
	if (isPerplexityAvailable()) {
		return searchWithPerplexity(query, options);
	}

	const geminiResult = await searchWithGeminiApi(query, options);
	if (geminiResult) return geminiResult;

	throw new Error(
		"No search provider available. Set one of:\n" +
		"  1. perplexityApiKey in ~/.pi/web-search.json\n" +
		"  2. GEMINI_API_KEY in ~/.pi/web-search.json"
	);
}

async function searchWithGeminiApi(query: string, options: SearchOptions = {}): Promise<SearchResponse | null> {
	const apiKey = getApiKey();
	if (!apiKey) return null;

	try {
		const body = {
			contents: [{ parts: [{ text: query }] }],
			tools: [{ google_search: {} }],
		};

		const res = await fetch(`${API_BASE}/models/${DEFAULT_MODEL}:generateContent?key=${apiKey}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(body),
			signal: AbortSignal.any([
				AbortSignal.timeout(60000),
				...(options.signal ? [options.signal] : []),
			]),
		});

		if (!res.ok) {
			const errorText = await res.text();
			throw new Error(`Gemini API error ${res.status}: ${errorText.slice(0, 300)}`);
		}

		const data = await res.json() as GeminiSearchResponse;

		const answer = data.candidates?.[0]?.content?.parts
			?.map(p => p.text).filter(Boolean).join("\n") ?? "";

		const metadata = data.candidates?.[0]?.groundingMetadata;
		const results = await resolveGroundingChunks(metadata?.groundingChunks, options.signal);

		if (!answer && results.length === 0) return null;
		return { answer, results };
	} catch {
		return null;
	}
}

async function resolveGroundingChunks(
	chunks: GroundingChunk[] | undefined,
	signal?: AbortSignal,
): Promise<SearchResult[]> {
	if (!chunks?.length) return [];

	const results: SearchResult[] = [];
	for (const chunk of chunks) {
		if (!chunk.web) continue;
		const title = chunk.web.title || "";
		let url = chunk.web.uri || "";

		if (url.includes("vertexaisearch.cloud.google.com/grounding-api-redirect")) {
			const resolved = await resolveRedirect(url, signal);
			if (resolved) url = resolved;
		}

		if (url) results.push({ title, url, snippet: "" });
	}
	return results;
}

async function resolveRedirect(proxyUrl: string, signal?: AbortSignal): Promise<string | null> {
	try {
		const res = await fetch(proxyUrl, {
			method: "HEAD",
			redirect: "manual",
			signal: AbortSignal.any([
				AbortSignal.timeout(5000),
				...(signal ? [signal] : []),
			]),
		});
		return res.headers.get("location") || null;
	} catch {
		return null;
	}
}

interface GeminiSearchResponse {
	candidates?: Array<{
		content?: { parts?: Array<{ text?: string }> };
		groundingMetadata?: {
			groundingChunks?: GroundingChunk[];
		};
	}>;
}

interface GroundingChunk {
	web?: { uri?: string; title?: string };
}
