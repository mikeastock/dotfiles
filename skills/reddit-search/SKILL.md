---
name: reddit-search
description: Search Reddit threads through the Gemini API with Google Search grounding. Use when the user asks "what does Reddit say", wants community or homelab opinions and experiences, or Reddit fetching is blocked or ordinary web search misses relevant threads.
agents: [amp, claude, codex, pi]
---

# Reddit Search

Use Gemini to find Reddit experiences and resolve grounded sources to real thread URLs.
This works when the agent cannot fetch reddit.com directly.

## Prerequisites and usage

Requires Python 3.11+, network access, and `GEMINI_API_KEY` in the environment. Never
print or log the key, put it in a URL, or pass it as a command-line argument. If it is
missing, ask the user to configure it securely using the environment's credential flow.

Run the bundled script relative to this skill's directory:

```bash
python3 <skill-dir>/scripts/search.py \
  --subreddit homelab --subreddit selfhosted \
  "What experiences do Reddit users report with online versus line-interactive UPSes at home, including noise, heat, reliability, and monitoring?"

# Multiple quoted questions run sequentially, one API request per question.
python3 <skill-dir>/scripts/search.py "First question?" "Second question?"

# UTF-8 file or stdin: one question per nonempty line.
python3 <skill-dir>/scripts/search.py --file /tmp/reddit-questions.txt
python3 <skill-dir>/scripts/search.py --file - < /tmp/reddit-questions.txt

# Default model: gemini-3.8-flash. Inspect availability before choosing an override.
python3 <skill-dir>/scripts/search.py --list-models
python3 <skill-dir>/scripts/search.py --model MODEL_ID "Question?"
```

Omitting questions also reads stdin when piped. Repeat `--subreddit` for hints, with
or without `r/`; choose names relevant to the topic. For homelab research, candidates
include r/homelab, r/selfhosted, r/sysadmin, r/HomeServer, r/DataHoarder,
r/LocalLLaMA, and r/homelabsales. Without hints, Gemini chooses and names subreddits.

Allow a long-running tool call: each API request has a 300-second timeout and can
take a minute or more. Wait for the running process before starting another query.

The script prints Markdown: Gemini's answer, deduplicated resolved Reddit thread
URLs, then `webSearchQueries`. It saves each raw API response to a private temporary
`gemini-reddit-*.json` file and prints that path to stderr. Keep raw files out of git;
remove them when no longer needed. Exit 1 means a request or local error; exit 2 means
at least one answer is empty or has no resolved Reddit threads. Inspect output even
on exit 2; lack of supporting sources is a result to report.

## Ask neutral questions

Describe the decision, context, constraints, and dimensions to compare. Ask for
positive and negative experiences. Give competing options equal treatment rather
than naming the option already favored as "the best".

- Ask: "How do homelab users compare Eaton 9PX, APC SRT, and CyberPower OL UPSes for
  fan noise, battery replacement, reliability, and NUT/USB monitoring?"
- Avoid: "Why is Eaton 9PX the best homelab UPS?"

The script's preamble asks Google Search to use ONLY reddit.com threads, report
what users actually said with short quotes, subreddit and approximate date, include
negative experiences, and explicitly identify points lacking a supporting Reddit
thread instead of filling them in from general knowledge. This is a prompt constraint;
check the returned sources because Gemini can still include unsupported claims.

## Verify and report

1. Read the answer alongside the resolved source list and search queries. Check that
   each cited thread slug and subreddit match the claim. A mismatch is a reason to
   omit the claim or refine the search, not to treat the citation as evidence.
2. Thread URLs are verifiable, but quoted text is Gemini's summary. Attribute any
   quote as **"per Gemini's summary of [thread](REDDIT_URL)"**, never as verified
   verbatim unless you independently read the original comment. Approximate dates
   also need attribution or independent checking.
3. Report the relevant experiences with direct Reddit links near each claim, include
   disagreements and negative reports, and distinguish anecdotal reports from your
   inference. State explicitly when no Reddit thread supports a point. A resolved URL
   alone does not verify the claim or establish community consensus.

Use resolved Reddit URLs instead of Google's grounding redirect links in the final
answer. Gemini can also invent post IDs in its inline links: match subreddit and
thread slug to the resolved list and use that resolved URL. Omit claims whose cited
thread cannot be matched. If a thread can be fetched through an available browser or
Reddit tool, check the original comments; if fetching is blocked, retain the summary attribution.
Keep quotes short and use paraphrases for the rest.

## API mechanics

The stdlib script sends `POST` to
`https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent`
with `x-goog-api-key` authentication and `"tools": [{"google_search": {}}]`.
`--list-models` uses `GET /v1beta/models`, including pagination, and lists models
supporting `generateContent`. Availability alone does not prove grounding support;
check the search queries and sources returned by a real query.

Sources come from `candidates[0].groundingMetadata.groundingChunks[].web.uri`.
For `vertexaisearch.cloud.google.com/grounding-api-redirect/...` links, the script
requests the URL **without following redirects**, reads `Location`, and accepts only
Reddit `/r/.../comments/...` thread URLs. It sends no API key when resolving sources,
removes tracking and comment IDs for deduplication, and preserves thread slugs.
Unresolved or non-Reddit sources are counted separately, not presented as evidence.

References: [Agent Skills format](https://agentskills.io/specification),
[Google Search grounding](https://ai.google.dev/gemini-api/docs/google-search),
[generateContent](https://ai.google.dev/api/generate-content),
[model listing](https://ai.google.dev/api/models).
