#!/usr/bin/env node
/**
 * Combine normalized per-session trajectories into one unified history index.
 * Vendored from the local trajectories pipeline for skill-doctor. Writes:
 *   <root>/state/history.jsonl   one session row, newest-updated first
 *   <root>/state/history.json    source counts plus the same rows
 *
 * Usage: node combine.mjs --root PATH
 */
import { createWriteStream } from "node:fs";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { finished } from "node:stream/promises";
import { resolveRoot } from "./root.mjs";

const ROOT = resolveRoot(process.argv.slice(2));
const OUT_ROOT = join(ROOT, "normalized");
const STATE_DIR = join(ROOT, "state");
const HISTORY_JSONL = join(STATE_DIR, "history.jsonl");
const HISTORY_JSON = join(STATE_DIR, "history.json");

async function listJsonFiles(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
  return entries
    .filter((e) => e.isFile() && e.name.endsWith(".json"))
    .map((e) => join(dir, e.name));
}

function sessionRow(source, filePath, doc, bytes) {
  const records = Array.isArray(doc.records) ? doc.records : [];
  const meta = records.find((r) => r && r.role === "meta") ?? {};
  let firstTimestamp = null;
  let lastTimestamp = null;
  const roleCounts = {};
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const role = typeof record.role === "string" ? record.role : "unknown";
    roleCounts[role] = (roleCounts[role] ?? 0) + 1;
    const ts = typeof record.timestamp === "string" ? record.timestamp : null;
    if (!ts) continue;
    if (firstTimestamp == null || ts < firstTimestamp) firstTimestamp = ts;
    if (lastTimestamp == null || ts > lastTimestamp) lastTimestamp = ts;
  }
  const provenance = doc.provenance ?? {};
  return {
    source,
    id: provenance.id ?? null,
    file: filePath,
    sourcePath: provenance.sourcePath ?? null,
    sourceTitle: provenance.sourceTitle ?? null,
    sourceUpdatedAt: provenance.sourceUpdatedAt ?? null,
    sourceSizeBytes: provenance.sourceSizeBytes ?? null,
    sourceSha256: provenance.sourceSha256 ?? null,
    normalizedAt: provenance.normalizedAt ?? null,
    package: provenance.package ?? null,
    recordCount: doc.recordCount ?? records.length,
    diagnosticCounts: doc.diagnosticCounts ?? {},
    roleCounts,
    firstTimestamp,
    lastTimestamp,
    cwd: meta.cwd ?? null,
    model: meta.model ?? null,
    gitBranch: meta.git_branch ?? null,
    bytes,
  };
}

async function main() {
  let sources;
  try {
    sources = (await readdir(OUT_ROOT, { withFileTypes: true }))
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
  } catch (err) {
    if (err.code === "ENOENT") {
      console.log(`No normalized/ directory yet at ${OUT_ROOT}`);
      process.exitCode = 1;
      return;
    }
    throw err;
  }

  const sessions = [];
  const bySource = {};
  for (const source of sources) {
    const files = await listJsonFiles(join(OUT_ROOT, source));
    const summary = {
      source,
      files: 0,
      records: 0,
      bytes: 0,
      sourceBytes: 0,
    };
    for (const file of files) {
      const st = await stat(file);
      let doc;
      try {
        doc = JSON.parse(await readFile(file, "utf8"));
      } catch {
        continue;
      }
      const row = sessionRow(source, file, doc, st.size);
      sessions.push(row);
      summary.files += 1;
      summary.records += row.recordCount;
      summary.bytes += st.size;
      summary.sourceBytes += row.sourceSizeBytes ?? 0;
    }
    bySource[source] = summary;
  }

  sessions.sort((a, b) => {
    const left = a.sourceUpdatedAt ?? a.lastTimestamp ?? "";
    const right = b.sourceUpdatedAt ?? b.lastTimestamp ?? "";
    if (left !== right) return left < right ? 1 : -1;
    if (a.source !== b.source) return a.source.localeCompare(b.source);
    return String(a.id).localeCompare(String(b.id));
  });

  await mkdir(STATE_DIR, { recursive: true });
  const jsonl = createWriteStream(HISTORY_JSONL, { encoding: "utf8" });
  for (const row of sessions) {
    jsonl.write(`${JSON.stringify(row)}\n`);
  }
  jsonl.end();
  await finished(jsonl);

  const builtAt = new Date().toISOString();
  const totals = Object.values(bySource).reduce(
    (acc, s) => {
      acc.files += s.files;
      acc.records += s.records;
      acc.bytes += s.bytes;
      acc.sourceBytes += s.sourceBytes;
      return acc;
    },
    { files: 0, records: 0, bytes: 0, sourceBytes: 0 },
  );

  const payload = {
    builtAt,
    outRoot: OUT_ROOT,
    historyJsonl: HISTORY_JSONL,
    sources,
    bySource,
    totals,
    sessions,
  };
  await writeFile(HISTORY_JSON, `${JSON.stringify(payload)}\n`, "utf8");

  console.log(`Unified history`);
  console.log(`  sessions: ${HISTORY_JSONL}`);
  console.log(`  index:    ${HISTORY_JSON}`);
  console.log(`  built:    ${builtAt}`);
  for (const source of sources) {
    const s = bySource[source];
    console.log(
      `  ${source}: files=${s.files} records=${s.records} out=${(s.bytes / 1024 / 1024).toFixed(1)}MB`,
    );
  }
  console.log(
    `  total: files=${totals.files} records=${totals.records} out=${(totals.bytes / 1024 / 1024).toFixed(1)}MB`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
