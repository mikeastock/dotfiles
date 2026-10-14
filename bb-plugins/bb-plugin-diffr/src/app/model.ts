// diffr's NDJSON, parsed into the per-file shape the panel renders.
import {
  eventSchema,
  fileIdentity,
  filePath,
  type ComparisonEnd,
  type DiffFile,
  type FileChange,
} from "../vendor/diffr/protocol/wire";

export interface DiffData {
  comparison: { lhs: ComparisonEnd; rhs: ComparisonEnd };
  /** The manifest, in diffr's order. `files` and `failures` are indexed like it. */
  inventory: FileChange[];
  files: (DiffFile | undefined)[];
  failures: (string | undefined)[];
  /** Problems that are not about one file, such as an aborted run. */
  errors: string[];
}

export function parseDiff(ndjson: string): DiffData {
  let data: DiffData | null = null;
  const slots = new Map<string, number>();
  let complete = false;
  for (const line of ndjson.split("\n")) {
    if (line.trim() === "") continue;
    const event = eventSchema.parse(JSON.parse(line));
    if (event.type === "start") {
      data = {
        comparison: { lhs: event.lhs, rhs: event.rhs },
        inventory: event.files,
        files: event.files.map(() => undefined),
        failures: event.files.map(() => undefined),
        errors: [],
      };
      event.files.forEach((entry, index) => slots.set(fileIdentity(entry.file), index));
      continue;
    }
    if (data === null) throw new Error("diffr's output did not start with a start record");
    if (event.type === "file") {
      const slot = slots.get(fileIdentity(event.file));
      if (slot === undefined) throw new Error(`${filePath(event.file)} is not in diffr's manifest`);
      if (event.diff) data.files[slot] = { ...event, diff: event.diff };
      else data.failures[slot] = event.error?.message ?? "diffr sent neither a diff nor an error";
      continue;
    }
    complete = true;
    if (event.aborted) data.errors.push(`diffr stopped early: ${event.aborted.message}`);
  }
  if (data === null) throw new Error("diffr printed nothing");
  if (!complete) data.errors.push("diffr's output ended before its complete record");
  return data;
}
