#!/usr/bin/env node
/**
 * Discover local agent sessions and write normalized Letta trajectory JSON
 * under <root>/normalized/<source>/. Vendored from the local trajectories
 * pipeline for skill-doctor; the data root is parameterized.
 *
 * --root PATH is required. The @letta-ai/trajectory package is loaded from
 * <root>/node_modules (see ../ingest.sh).
 *
 * Usage:
 *   node normalize.mjs --root PATH [--source NAME]... [--days N] [--limit N] [--force] [--dry-run]
 */
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import { loadTrajectoryPackage, resolveRoot } from "./root.mjs";

const ROOT = resolveRoot(process.argv.slice(2));
const OUT_ROOT = join(ROOT, "normalized");
const MANIFEST_PATH = join(ROOT, "state", "last-run.json");
const WANT_HELP = process.argv.slice(2).some((a) => a === "--help" || a === "-h");
const {
  listTrajectories,
  normalizeCheckpoint,
  normalizeTranscript,
  NormalizationError,
  PACKAGE,
} = WANT_HELP ? {} : await loadTrajectoryPackage(ROOT);

const LISTABLE_SOURCES = [
  "claude-code",
  "codex",
  "droid",
  "deepagents",
  "grok-build",
  "hermes",
  "letta-code",
  "openclaw",
  "openhands",
  "pi",
  "omp",
];
const DISCOVERED_SOURCES = ["cursor", "opencode"];
const DEFAULT_SOURCES = [...LISTABLE_SOURCES, ...DISCOVERED_SOURCES];
const SQLITE_SOURCES = new Set(["hermes", "opencode", "deepagents"]);

function parseArgs(argv) {
  const opts = {
    sources: [],
    limit: null,
    days: null,
    force: false,
    dryRun: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") opts.help = true;
    else if (arg === "--force") opts.force = true;
    else if (arg === "--dry-run") opts.dryRun = true;
    else if (arg === "--root") i += 1;
    else if (arg === "--source" || arg === "-s") {
      const value = argv[++i];
      if (!value) throw new Error("--source requires a value");
      if (value === "all") opts.sources.push(...DEFAULT_SOURCES);
      else opts.sources.push(value);
    } else if (arg === "--days") {
      const value = Number(argv[++i]);
      if (!Number.isFinite(value) || value < 1) {
        throw new Error("--days requires a positive integer");
      }
      opts.days = Math.floor(value);
    } else if (arg === "--limit" || arg === "-n") {
      const value = Number(argv[++i]);
      if (!Number.isFinite(value) || value < 1) {
        throw new Error("--limit requires a positive integer");
      }
      opts.limit = Math.floor(value);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (opts.sources.length === 0) opts.sources = [...DEFAULT_SOURCES];
  opts.sources = [...new Set(opts.sources)];
  return opts;
}

function usage() {
  console.log(`Normalize local agent sessions to trajectory JSON.

Usage:
  node normalize.mjs [options]

Options:
  --root <path>         Data root (required)
  --days <n>            Only sessions updated in the last n days (skips undated ones)
  -s, --source <name>   Source to process (repeatable, or "all").
                        Default: ${DEFAULT_SOURCES.join(", ")}
  -n, --limit <n>       Max sessions per source (newest first)
  --force               Re-normalize even when output looks current
  --dry-run             List work without writing
  -h, --help            Show this help

Output:
  ${OUT_ROOT}/<source>/<id>.json
`);
}

function safeId(id) {
  return String(id).replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 200);
}

function sha256Hex(text) {
  return createHash("sha256").update(text).digest("hex");
}

function summarizeDiagnostics(diagnostics) {
  const counts = {};
  for (const d of diagnostics) {
    counts[d.code] = (counts[d.code] ?? 0) + (d.count ?? 1);
  }
  return counts;
}

function isoFromEpoch(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return undefined;
  }
  const ms = value < 1e11 ? value * 1000 : value;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

async function walkFiles(dir, predicate, depth = 8) {
  if (depth < 0) return [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isFile() && predicate(full, entry.name)) out.push(full);
    else if (entry.isDirectory()) {
      out.push(...(await walkFiles(full, predicate, depth - 1)));
    }
  }
  return out;
}

function openSqliteReadOnly(path) {
  return new DatabaseSync(path, { readOnly: true });
}

async function listCursor() {
  const base = join(homedir(), ".cursor", "projects");
  const files = await walkFiles(
    base,
    (full, name) => name.endsWith(".jsonl") && full.includes("/agent-transcripts/"),
    10,
  );
  const items = [];
  for (const path of files) {
    const facts = await stat(path);
    const stem = basename(path, ".jsonl");
    const project = path.slice(base.length + 1).split("/")[0] ?? "cursor";
    items.push({
      id: `${project}__${stem}`,
      path,
      updatedAt: facts.mtime.toISOString(),
      sizeBytes: facts.size,
    });
  }
  items.sort((a, b) => (b.updatedAt ?? "").localeCompare(a.updatedAt ?? ""));
  return items;
}

async function listOpenCode() {
  const path = join(homedir(), ".local", "share", "opencode", "opencode.db");
  try {
    await stat(path);
  } catch {
    return [];
  }
  const db = openSqliteReadOnly(path);
  try {
    const rows = db
      .prepare(
        "SELECT id, title, directory, time_created, time_updated FROM session",
      )
      .all();
    return rows
      .map((row) => ({
        id: String(row.id),
        path,
        title: typeof row.title === "string" && row.title ? row.title : undefined,
        updatedAt: isoFromEpoch(row.time_updated) ?? isoFromEpoch(row.time_created),
        directory: typeof row.directory === "string" ? row.directory : undefined,
        timeCreated: row.time_created,
        timeUpdated: row.time_updated,
      }))
      .sort((a, b) => (b.updatedAt ?? "").localeCompare(a.updatedAt ?? ""));
  } finally {
    db.close();
  }
}

async function listAll(source) {
  if (source === "cursor") return listCursor();
  if (source === "opencode") return listOpenCode();

  const items = [];
  let cursor;
  do {
    const page = await listTrajectories({
      source,
      limit: 1000,
      cursor,
    });
    items.push(...page.items);
    cursor = page.nextCursor;
  } while (cursor);
  return items;
}

function exportOpenCodeTranscript(item) {
  const db = openSqliteReadOnly(item.path);
  try {
    const session = db
      .prepare(
        "SELECT id, title, directory, time_created, time_updated FROM session WHERE id = ?",
      )
      .get(item.id);
    if (!session) {
      throw new Error(`OpenCode session not found: ${item.id}`);
    }
    const messages = db
      .prepare(
        "SELECT id, data, time_created FROM message WHERE session_id = ? ORDER BY time_created, id",
      )
      .all(item.id);
    const parts = db
      .prepare(
        "SELECT message_id, data, time_created, id FROM part WHERE session_id = ? ORDER BY time_created, id",
      )
      .all(item.id);
    const partsByMessage = new Map();
    for (const part of parts) {
      const list = partsByMessage.get(part.message_id) ?? [];
      list.push(JSON.parse(part.data));
      partsByMessage.set(part.message_id, list);
    }
    const document = {
      info: {
        id: session.id,
        title: session.title,
        directory: session.directory,
        time: {
          created: session.time_created,
          updated: session.time_updated,
        },
      },
      messages: messages.map((row) => {
        const info = JSON.parse(row.data);
        if (info.id == null) info.id = row.id;
        return {
          info,
          parts: partsByMessage.get(row.id) ?? [],
        };
      }),
    };
    return JSON.stringify(document);
  } finally {
    db.close();
  }
}

function exportHermesTranscript(item) {
  const db = openSqliteReadOnly(item.path);
  try {
    const session =
      db.prepare("SELECT * FROM sessions WHERE id = ?").get(item.id) ?? {};
    const messages = db
      .prepare(
        "SELECT * FROM messages WHERE session_id = ? ORDER BY id",
      )
      .all(item.id);
    return JSON.stringify({ session, messages });
  } finally {
    db.close();
  }
}

async function exportOpenHandsTranscript(item) {
  const facts = await stat(item.path);
  if (facts.isFile()) return readFile(item.path, "utf8");
  const files = (await walkFiles(item.path, (_full, name) => name.endsWith(".json"), 4))
    .sort();
  const events = [];
  for (const file of files) {
    const raw = await readFile(file, "utf8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) events.push(...parsed);
    else events.push(parsed);
  }
  return JSON.stringify(events);
}

async function exportGrokBuildTranscript(item) {
  const chat = await readFile(item.path, "utf8");
  if (grokChatHasAssistant(chat)) return chat;
  try {
    const updates = await readFile(join(dirname(item.path), "updates.jsonl"), "utf8");
    if (updates.trim()) {
      return JSON.stringify({ chat_history: chat, updates });
    }
  } catch {
    // No sibling update stream.
  }
  return chat;
}

function grokChatHasAssistant(chat) {
  for (const line of chat.split("\n")) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      if (row && row.type === "assistant") return true;
    } catch {
      // Ignore malformed lines; the adapter will diagnose them.
    }
  }
  return false;
}

async function shouldSkip(outPath, sourcePath, sourceSizeBytes, sourceSha256, force) {
  if (force) return false;
  try {
    const raw = await readFile(outPath, "utf8");
    const existing = JSON.parse(raw);
    if (
      existing?.provenance?.sourcePath === sourcePath &&
      existing?.provenance?.sourceSizeBytes === sourceSizeBytes
    ) {
      return true;
    }
    if (sourceSha256 && existing?.provenance?.sourceSha256 === sourceSha256) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

async function normalizeOne(source, item, { force, dryRun }) {
  const id = safeId(item.id);
  const outPath = join(OUT_ROOT, source, `${id}.json`);
  let sourceSizeBytes = item.sizeBytes;
  if (sourceSizeBytes == null && item.path && !SQLITE_SOURCES.has(source)) {
    try {
      sourceSizeBytes = (await stat(item.path)).size;
    } catch {
      sourceSizeBytes = undefined;
    }
  }

  if (
    sourceSizeBytes != null &&
    (await shouldSkip(outPath, item.path, sourceSizeBytes, null, force))
  ) {
    return { status: "skipped", id, outPath, sourceSizeBytes };
  }

  if (dryRun) {
    return { status: "would_write", id, outPath, sourceSizeBytes };
  }

  let result;
  let sourceSha256 = null;
  let transcript = null;

  try {
    if (source === "deepagents") {
      result = await normalizeCheckpoint({
        source: "deepagents",
        checkpoint: { threadId: item.id, path: item.path },
      });
      sourceSha256 = sha256Hex(`${item.path}#${item.id}#${item.updatedAt ?? ""}`);
    } else {
      if (source === "opencode") transcript = exportOpenCodeTranscript(item);
      else if (source === "hermes") transcript = exportHermesTranscript(item);
      else if (source === "openhands") {
        transcript = await exportOpenHandsTranscript(item);
      } else if (source === "grok-build") {
        transcript = await exportGrokBuildTranscript(item);
      } else {
        transcript = await readFile(item.path, "utf8");
      }
      sourceSizeBytes = Buffer.byteLength(transcript);
      sourceSha256 = sha256Hex(transcript);
      if (await shouldSkip(outPath, item.path, sourceSizeBytes, sourceSha256, force)) {
        return { status: "skipped", id, outPath, sourceSizeBytes };
      }
      result = normalizeTranscript({ source, transcript });
    }
  } catch (err) {
    if (err instanceof NormalizationError) {
      return {
        status: "error",
        id,
        outPath,
        sourceSizeBytes,
        error: `${err.code}: ${err.message}`,
      };
    }
    return {
      status: "error",
      id,
      outPath,
      sourceSizeBytes,
      error: err.message ?? String(err),
    };
  }

  const payload = {
    provenance: {
      source,
      id: item.id,
      sourcePath: item.path,
      sourceTitle: item.title ?? null,
      sourceUpdatedAt: item.updatedAt ?? null,
      sourceSizeBytes,
      sourceSha256,
      normalizedAt: new Date().toISOString(),
      package: PACKAGE,
    },
    diagnostics: result.diagnostics,
    diagnosticCounts: summarizeDiagnostics(result.diagnostics),
    recordCount: result.records.length,
    records: result.records,
  };

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

  return {
    status: "written",
    id,
    outPath,
    sourceSizeBytes,
    recordCount: result.records.length,
    diagnosticCounts: payload.diagnosticCounts,
  };
}

async function processSource(source, opts) {
  console.log(`\n== ${source} ==`);
  let items;
  try {
    items = await listAll(source);
  } catch (err) {
    console.error(`  list failed: ${err.message ?? err}`);
    return {
      source,
      listed: 0,
      written: 0,
      skipped: 0,
      errors: 1,
      errorSamples: [`list: ${err.message ?? err}`],
    };
  }

  if (opts.cutoff) {
    items = items.filter((item) => item.updatedAt && item.updatedAt >= opts.cutoff);
  }
  if (opts.limit != null) items = items.slice(0, opts.limit);
  console.log(`  listed ${items.length} session(s)`);

  const summary = {
    source,
    listed: items.length,
    written: 0,
    skipped: 0,
    would_write: 0,
    errors: 0,
    errorSamples: [],
    bytesIn: 0,
    recordsOut: 0,
  };

  for (const item of items) {
    const result = await normalizeOne(source, item, opts);
    summary.bytesIn += result.sourceSizeBytes ?? 0;

    if (result.status === "written") {
      summary.written += 1;
      summary.recordsOut += result.recordCount ?? 0;
      process.stdout.write(".");
    } else if (result.status === "skipped") {
      summary.skipped += 1;
    } else if (result.status === "would_write") {
      summary.would_write += 1;
    } else if (result.status === "error") {
      summary.errors += 1;
      if (summary.errorSamples.length < 10) {
        summary.errorSamples.push(`${result.id}: ${result.error}`);
      }
      process.stdout.write("E");
    }
  }

  if (items.length > 0) process.stdout.write("\n");
  console.log(
    `  written=${summary.written} skipped=${summary.skipped}` +
      (opts.dryRun ? ` would_write=${summary.would_write}` : "") +
      ` errors=${summary.errors}`,
  );
  if (summary.errorSamples.length) {
    for (const sample of summary.errorSamples) {
      console.log(`  ! ${sample}`);
    }
  }

  return summary;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    usage();
    return;
  }

  console.log(`Trajectory normalizer`);
  console.log(`  root: ${ROOT}`);
  console.log(`  out:  ${OUT_ROOT}`);
  console.log(`  package: ${PACKAGE}`);
  console.log(`  sources: ${opts.sources.join(", ")}`);
  if (opts.days != null) {
    opts.cutoff = new Date(Date.now() - opts.days * 86400000).toISOString();
    console.log(`  days: ${opts.days} (since ${opts.cutoff})`);
  }
  if (opts.limit != null) console.log(`  limit: ${opts.limit}`);
  if (opts.force) console.log(`  force: true`);
  if (opts.dryRun) console.log(`  dry-run: true`);

  const startedAt = new Date().toISOString();
  const bySource = [];
  for (const source of opts.sources) {
    bySource.push(await processSource(source, opts));
  }

  const totals = bySource.reduce(
    (acc, s) => {
      acc.listed += s.listed;
      acc.written += s.written;
      acc.skipped += s.skipped;
      acc.errors += s.errors;
      acc.bytesIn += s.bytesIn ?? 0;
      acc.recordsOut += s.recordsOut ?? 0;
      return acc;
    },
    { listed: 0, written: 0, skipped: 0, errors: 0, bytesIn: 0, recordsOut: 0 },
  );

  const finishedAt = new Date().toISOString();
  console.log(`\nDone in ${startedAt} → ${finishedAt}`);
  console.log(
    `Totals: listed=${totals.listed} written=${totals.written} skipped=${totals.skipped} errors=${totals.errors}`,
  );

  if (!opts.dryRun) {
    await mkdir(dirname(MANIFEST_PATH), { recursive: true });
    await writeFile(
      MANIFEST_PATH,
      `${JSON.stringify(
        {
          startedAt,
          finishedAt,
          package: PACKAGE,
          sources: opts.sources,
          limit: opts.limit,
          days: opts.days,
          force: opts.force,
          outRoot: OUT_ROOT,
          bySource,
          totals,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    console.log(`Manifest: ${relative(ROOT, MANIFEST_PATH)}`);
  }

  if (totals.errors > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
