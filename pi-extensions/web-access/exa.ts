import { setTimeout as sleep } from "node:timers/promises";

const EXA_API = "https://api.exa.ai";
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_ATTEMPTS = 3;
const HIGHLIGHT_CHARS = 2_000;

export interface SearchOptions {
	numResults?: number;
	objective?: string;
	recency?: "day" | "week" | "month" | "year";
	domains?: string[];
	signal?: AbortSignal;
}

export interface SearchResult {
	title: string;
	url: string;
	publishedDate?: string;
	excerpt: string;
}

export interface SearchResponse {
	results: SearchResult[];
	notices: string[];
}

export interface Page {
	url: string;
	title: string;
	text: string;
}

export interface FetchedPage {
	url: string;
	page?: Page;
	error?: string;
}

const RECENCY_DAYS = { day: 1, week: 7, month: 30, year: 365 };

async function exaRequest<T>(path: string, body: object, signal?: AbortSignal): Promise<T> {
	const apiKey = process.env.EXA_API_KEY;
	if (!apiKey) throw new Error("EXA_API_KEY is not set. Get a key at https://dashboard.exa.ai/api-keys");

	const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
	const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;

	for (let attempt = 1; ; attempt++) {
		const response = await fetch(`${EXA_API}${path}`, {
			method: "POST",
			headers: { "x-api-key": apiKey, "Content-Type": "application/json" },
			body: JSON.stringify(body),
			signal: requestSignal,
		});
		if (response.ok) return (await response.json()) as T;

		const retryable = response.status === 429 || response.status >= 500;
		if (retryable && attempt < MAX_ATTEMPTS) {
			await sleep(1_000 * attempt, undefined, { signal: requestSignal });
			continue;
		}
		throw new Error(`Exa ${path} failed with HTTP ${response.status}: ${(await response.text()).slice(0, 300)}`);
	}
}

/** Split "-example.com" entries into excludeDomains, the rest into includeDomains. */
function domainFilters(domains: string[] = []) {
	const include = domains.filter((d) => !d.startsWith("-"));
	const exclude = domains.filter((d) => d.startsWith("-")).map((d) => d.slice(1));
	return {
		...(include.length > 0 && { includeDomains: include }),
		...(exclude.length > 0 && { excludeDomains: exclude }),
	};
}

export async function search(query: string, options: SearchOptions = {}): Promise<SearchResponse> {
	const startPublishedDate = options.recency
		? new Date(Date.now() - RECENCY_DAYS[options.recency] * 86_400_000).toISOString()
		: undefined;

	const data = await exaRequest<{
		results?: Array<{ title?: string; url: string; publishedDate?: string; highlights?: string[] }>;
		notices?: Array<{ message: string }>;
	}>(
		"/search",
		{
			query,
			type: "auto",
			numResults: options.numResults ?? 5,
			...(options.objective && { objective: options.objective }),
			...(startPublishedDate && { startPublishedDate }),
			...domainFilters(options.domains),
			contents: { highlights: { maxCharacters: HIGHLIGHT_CHARS } },
		},
		options.signal,
	);

	return {
		results: (data.results ?? []).map((r) => ({
			title: r.title || r.url,
			url: r.url,
			publishedDate: r.publishedDate ?? undefined,
			excerpt: (r.highlights ?? []).join("\n…\n").trim(),
		})),
		notices: (data.notices ?? []).map((n) => n.message),
	};
}

/** Fetch page text for many URLs in one Exa request. Per-URL failures are reported, not thrown. */
export async function fetchPages(urls: string[], options: { fresh?: boolean; signal?: AbortSignal } = {}): Promise<FetchedPage[]> {
	const data = await exaRequest<{
		results?: Array<{ id: string; url: string; title?: string; text?: string }>;
		statuses?: Array<{ id: string; status: string; error?: { tag?: string; httpStatusCode?: number } }>;
	}>(
		"/contents",
		{ urls, text: true, ...(options.fresh && { maxAgeHours: 0 }) },
		options.signal,
	);

	const results = new Map((data.results ?? []).map((r) => [r.id, r]));
	const statuses = new Map((data.statuses ?? []).map((s) => [s.id, s]));

	return urls.map((url) => {
		const result = results.get(url);
		if (result?.text) {
			return { url, page: { url: result.url, title: result.title || result.url, text: result.text } };
		}
		const error = statuses.get(url)?.error;
		return { url, error: error ? `${error.tag ?? "error"} (HTTP ${error.httpStatusCode ?? "?"})` : "no content returned" };
	});
}
