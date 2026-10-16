// A diffr run as the panel sees it: the manifest and per-file summaries up
// front, and each file's full record read from the host on demand.
import { MAX_READ_BYTES, type DiffRun, type FileRecord } from "../contract";
import { eventSchema, type ComparisonEnd, type DiffFile, type FileChange } from "../vendor/diffr/protocol/wire";

export interface DiffData {
  runId: string;
  args: string[];
  comparison: { lhs: ComparisonEnd; rhs: ComparisonEnd };
  /** The manifest, in diffr's order. `records` is indexed like it. */
  inventory: FileChange[];
  records: (FileRecord | null)[];
  /** Problems that are not about one file, such as an aborted run. */
  errors: string[];
}

/** File records read so far, by manifest index, and the reads that failed. */
export interface Loads {
  files: ReadonlyMap<number, DiffFile>;
  failures: ReadonlyMap<number, string>;
}

export function parseRun(run: DiffRun): DiffData {
  const start = eventSchema.parse(JSON.parse(run.start));
  if (start.type !== "start") throw new Error("diffr's output did not start with a start record");
  const errors: string[] = [];
  if (run.complete === null) {
    errors.push("diffr's output ended before its complete record");
  } else {
    const complete = eventSchema.parse(JSON.parse(run.complete));
    if (complete.type === "complete" && complete.aborted) errors.push(`diffr stopped early: ${complete.aborted.message}`);
  }
  return {
    runId: run.runId,
    args: run.args,
    comparison: { lhs: start.lhs, rhs: start.rhs },
    inventory: start.files,
    records: run.files,
    errors,
  };
}

/** Reads one byte range of the run's NDJSON; resolves to base64 gzip. */
export type ReadRange = (offset: number, length: number) => Promise<{ gzip: string }>;

async function gunzip(base64: string): Promise<Uint8Array> {
  const bytes = Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Read a file's record in ranges small enough for one RPC response each. */
export async function loadRecord(read: ReadRange, record: FileRecord): Promise<DiffFile> {
  const parts: Uint8Array[] = [];
  for (let offset = record.offset; offset < record.offset + record.length; offset += MAX_READ_BYTES) {
    const length = Math.min(MAX_READ_BYTES, record.offset + record.length - offset);
    parts.push(await gunzip((await read(offset, length)).gzip));
  }
  const bytes = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    bytes.set(part, at);
    at += part.length;
  }
  const event = eventSchema.parse(JSON.parse(new TextDecoder().decode(bytes)));
  if (event.type !== "file" || !event.diff) throw new Error("diffr's record for this file has no diff");
  return { ...event, diff: event.diff };
}
