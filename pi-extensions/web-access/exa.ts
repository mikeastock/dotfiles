import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const EXA_SEARCH_URL = "https://api.exa.ai/search";
const EXA_CONTENTS_URL = "https://api.exa.ai/contents";
const DEFAULT_TIMEOUT_MS = 30000;
const CONFIG_PATH = join(homedir(), ".pi", "web-search.json");

export interface ExaSearchResult {
	title: string;
	url: string;
	text: string;
	publishedDate?: string;
}

export interface ExaSearchResponse {
	query: string;
	answer: string;
	results: ExaSearchResult[];
}

export interface ExaContentsResult {
	url: string;
	title: string;
	text: string;
	author?: string;
	publishedDate?: string;
}

export interface ExaContentsResponse {
	results: ExaContentsResult[];
	statuses: Array<{ id: string; status: string }>;
}

export interface SearchOptions {
	numResults?: number;
	includeDomains?: string[];
	excludeDomains?: string[];
	startPublishedDate?: string;
	endPublishedDate?: string;
	includeContent?: boolean;
	signal?: AbortSignal;
}

export interface ContentsOptions {
	signal?: AbortSignal;
}

interface WebSearchConfig {
	exaApiKey?: string;
}

let cachedConfig: WebSearchConfig | null = null;

function loadConfig(): WebSearchConfig {
	if (cachedConfig) return cachedConfig;
	if (existsSync(CONFIG_PATH)) {
		try {
			cachedConfig = JSON.parse(readFileSync(CONFIG_PATH, "utf-8")) as WebSearchConfig;
			return cachedConfig;
		} catch {
			cachedConfig = {};
		}
	} else {
		cachedConfig = {};
	}
	return cachedConfig;
}

function getApiKey(): string {
	const config = loadConfig();
	const key = process.env.EXA_API_KEY || config.exaApiKey;
	if (!key) {
		throw new Error(
			"Exa API key not found. Either:\n" +
			`  1. Create ${CONFIG_PATH} with { "exaApiKey": "your-key" }\n` +
			"  2. Set EXA_API_KEY environment variable\n" +
			"Get a key at https://exa.ai"
		);
	}
	return key;
}

export function isExaAvailable(): boolean {
	const config = loadConfig();
	return Boolean(process.env.EXA_API_KEY || config.exaApiKey);
}

function recencyToDate(recency: string): string {
	const now = new Date();
	switch (recency) {
		case "day": now.setDate(now.getDate() - 1); break;
		case "week": now.setDate(now.getDate() - 7); break;
		case "month": now.setMonth(now.getMonth() - 1); break;
		case "year": now.setFullYear(now.getFullYear() - 1); break;
		default: return "";
	}
	return now.toISOString();
}

export function parseDomainFilters(domains: string[]): { include: string[]; exclude: string[] } {
	const include: string[] = [];
	const exclude: string[] = [];
	for (const d of domains) {
		if (d.startsWith("-")) {
			exclude.push(d.slice(1));
		} else {
			include.push(d);
		}
	}
	return { include, exclude };
}

export async function searchWithExa(
	query: string,
	options: SearchOptions & { recencyFilter?: string } = {},
): Promise<ExaSearchResponse> {
	const apiKey = getApiKey();
	const numResults = Math.min(options.numResults ?? 5, 20);
	const includeContent = options.includeContent ?? false;

	const body: Record<string, unknown> = {
		query,
		numResults,
		type: "auto",
		contents: includeContent ? { text: true } : { text: { maxCharacters: 300 } },
	};

	if (options.includeDomains?.length) body.includeDomains = options.includeDomains;
	if (options.excludeDomains?.length) body.excludeDomains = options.excludeDomains;
	if (options.startPublishedDate) body.startPublishedDate = options.startPublishedDate;
	if (options.endPublishedDate) body.endPublishedDate = options.endPublishedDate;

	if ((options as { recencyFilter?: string }).recencyFilter) {
		const date = recencyToDate((options as { recencyFilter?: string }).recencyFilter!);
		if (date) body.startPublishedDate = date;
	}

	const response = await fetch(EXA_SEARCH_URL, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"x-api-key": apiKey,
			Accept: "application/json",
		},
		body: JSON.stringify(body),
		signal: options.signal ?? AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
	});

	if (!response.ok) {
		const errorText = await response.text();
		throw new Error(`Exa search error ${response.status}: ${errorText.slice(0, 300)}`);
	}

	const data = await response.json() as { results?: Array<{ title?: string; url?: string; text?: string; publishedDate?: string }> };

	const results: ExaSearchResult[] = (data.results ?? []).map(r => ({
		title: r.title ?? "",
		url: r.url ?? "",
		text: r.text ?? "",
		publishedDate: r.publishedDate,
	}));

	// Exa /search doesn't return a synthesized answer — build a summary from snippets
	const answer = results.length > 0
		? results
			.filter(r => r.text)
			.slice(0, 3)
			.map((r, i) => `${i + 1}. **${r.title}**: ${r.text.slice(0, 200).trim()}${r.text.length > 200 ? "..." : ""}`)
			.join("\n\n")
		: "";

	return { query, answer, results };
}

export async function fetchContents(
	urls: string[],
	options: ContentsOptions = {},
): Promise<ExaContentsResponse> {
	const apiKey = getApiKey();

	const response = await fetch(EXA_CONTENTS_URL, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"x-api-key": apiKey,
			Accept: "application/json",
		},
		body: JSON.stringify({
			urls,
			text: true,
			livecrawl: "fallback",
		}),
		signal: options.signal ?? AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
	});

	if (!response.ok) {
		const errorText = await response.text();
		throw new Error(`Exa contents error ${response.status}: ${errorText.slice(0, 300)}`);
	}

	const data = await response.json() as {
		results?: Array<{ url?: string; title?: string; text?: string; author?: string; publishedDate?: string }>;
		statuses?: Array<{ id: string; status: string }>;
	};

	const results: ExaContentsResult[] = (data.results ?? []).map(r => ({
		url: r.url ?? "",
		title: r.title ?? "",
		text: r.text ?? "",
		author: r.author,
		publishedDate: r.publishedDate,
	}));

	return {
		results,
		statuses: data.statuses ?? [],
	};
}
