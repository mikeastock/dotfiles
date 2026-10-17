// The typed boundary between the server entry and the host entry that runs
// diffr on the machine holding the thread's workspace.
//
// diffr's NDJSON carries every changed file's full text on both sides plus a
// capture name for every token, so a one-line change in a 5,000-line file is
// several megabytes. Host RPC output is capped at 8 MiB, so the host keeps
// each run's NDJSON on disk and the panel reads file records on demand, in
// gzip-compressed byte ranges.
import { defineRpcContract } from "@get-bb/plugin-sdk";
import { z } from "zod";

/**
 * What to compare. Both presets diff against the working tree and include
 * untracked files, so a file an agent just created shows up as added.
 * - `changes`: HEAD against the working tree (every uncommitted change).
 * - `branch`: the merge base with the environment's base branch against the
 *   working tree (everything this branch would ship).
 * - `custom`: diffr's own arguments, exactly as `git diff` takes them.
 */
export const diffModeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("changes") }).strict(),
  z.object({ kind: z.literal("branch") }).strict(),
  z
    .object({
      kind: z.literal("custom"),
      args: z.array(z.string().min(1).max(4096)).max(64),
    })
    .strict(),
]);
export type DiffMode = z.infer<typeof diffModeSchema>;

const lineCountsSchema = z.object({ added: z.number().int(), removed: z.number().int() }).strict();

/** What a file's header needs, read by the host so the panel need not load the record. */
export const fileSummarySchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("text"),
      stats: lineCountsSchema,
      /** Why diffr fell back to a line diff, when it did. */
      fallback: z.string().nullable(),
      /** diffr's classifier hid the file (generated, vendored, deleted, ...). */
      hidden: z.object({ collapsed: z.boolean(), label: z.string() }).strict(),
    })
    .strict(),
  z.object({ kind: z.literal("binary") }).strict(),
  z.object({ kind: z.literal("error"), message: z.string() }).strict(),
]);
export type FileSummary = z.infer<typeof fileSummarySchema>;

/** Where one file's record sits in the run's NDJSON. */
export const fileRecordSchema = z
  .object({
    offset: z.number().int().nonnegative(),
    length: z.number().int().positive(),
    summary: fileSummarySchema,
  })
  .strict();
export type FileRecord = z.infer<typeof fileRecordSchema>;

export const runIdSchema = z.string().regex(/^[0-9a-f-]{36}$/);

export const diffRunSchema = z
  .object({
    runId: runIdSchema,
    /** The arguments diffr ran with, after the preset was resolved. */
    args: z.array(z.string()),
    /** diffr's `start` record, verbatim. */
    start: z.string(),
    /** diffr's `complete` record, verbatim; null when the stream ended early. */
    complete: z.string().nullable(),
    /** One entry per manifest file, in manifest order; null when diffr sent no record for it. */
    files: z.array(fileRecordSchema.nullable()),
  })
  .strict();
export type DiffRun = z.infer<typeof diffRunSchema>;

/** Largest byte range one read returns, before compression. */
export const MAX_READ_BYTES = 4 * 1024 * 1024;

export const readRangeSchema = z
  .object({
    runId: runIdSchema,
    offset: z.number().int().nonnegative(),
    length: z.number().int().positive().max(MAX_READ_BYTES),
  })
  .strict();

/** The range's bytes, gzip-compressed, as base64. */
export const readResultSchema = z.object({ gzip: z.string() }).strict();

export const hostContract = defineRpcContract({
  diff: {
    input: z
      .object({
        cwd: z.string().min(1),
        binary: z.string().min(1),
        mode: diffModeSchema,
        /** Branch names to try, in order, for the `branch` preset. */
        bases: z.array(z.string().min(1)).max(8),
        /** diffr's `--byte-limit`: larger files get a line diff. Null keeps diffr's configured limit. */
        byteLimit: z.number().int().positive().nullable(),
      })
      .strict(),
    output: diffRunSchema,
  },
  read: {
    input: readRangeSchema,
    output: readResultSchema,
  },
});
