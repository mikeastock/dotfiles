#!/usr/bin/env node
import { xFetch } from "./x-lib.mjs";

const args = parseArgs(process.argv.slice(2));

if (!args.query) {
  console.error("Usage: x-search.mjs --query '<x search query>' [--max 25] [--json] [--all]");
  process.exit(2);
}

const max = clamp(Number.parseInt(args.max || "10", 10), 1, 100);
const endpoint = args.all
  ? "https://api.twitter.com/2/tweets/search/all"
  : "https://api.twitter.com/2/tweets/search/recent";
const params = new URLSearchParams({
  query: args.query,
  max_results: String(Math.max(10, Math.min(max, 100))),
  "tweet.fields": "id,text,author_id,created_at,conversation_id,public_metrics,lang,possibly_sensitive,referenced_tweets,entities",
  expansions: "author_id",
  "user.fields": "id,name,username,verified,public_metrics"
});

try {
  const response = await xFetch(`${endpoint}?${params.toString()}`);
  const body = await response.json().catch(async () => ({ text: await response.text() }));

  if (!response.ok) {
    console.error(`X search failed (${response.status}): ${JSON.stringify(body)}`);
    process.exit(1);
  }

  const normalized = normalizeSearchResponse(body, max);

  if (args.json) {
    console.log(JSON.stringify(normalized, null, 2));
  } else {
    printMarkdown(normalized);
  }
} catch (caught) {
  console.error(caught instanceof Error ? caught.message : String(caught));
  process.exit(1);
}

function normalizeSearchResponse(body, maxResults) {
  const usersById = new Map((body.includes?.users || []).map((user) => [user.id, user]));
  const posts = (body.data || []).slice(0, maxResults).map((tweet) => {
    const author = usersById.get(tweet.author_id);
    const username = author?.username || tweet.author_id || "unknown";
    return {
      id: tweet.id,
      url: `https://x.com/${username}/status/${tweet.id}`,
      text: tweet.text || "",
      created_at: tweet.created_at,
      author: author
        ? {
            id: author.id,
            name: author.name,
            username: author.username,
            verified: author.verified
          }
        : undefined,
      public_metrics: tweet.public_metrics
    };
  });

  return {
    meta: body.meta || {},
    count: posts.length,
    posts,
    errors: body.errors || []
  };
}

function printMarkdown(result) {
  if (result.count === 0) {
    console.log("No X posts found.");
    return;
  }

  for (const post of result.posts) {
    const handle = post.author?.username ? `@${post.author.username}` : "@unknown";
    const date = post.created_at || "unknown date";
    console.log(`- ${date} ${handle}`);
    console.log(`  ${post.url}`);
    console.log(`  ${post.text.replace(/\s+/g, " ").trim()}`);
    console.log("");
  }
}

function parseArgs(argv) {
  const parsed = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--json") {
      parsed.json = true;
    } else if (arg === "--all") {
      parsed.all = true;
    } else if (arg === "--query" || arg === "-q") {
      parsed.query = argv[++index];
    } else if (arg === "--max" || arg === "-n") {
      parsed.max = argv[++index];
    } else if (!parsed.query) {
      parsed.query = arg;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, value));
}
