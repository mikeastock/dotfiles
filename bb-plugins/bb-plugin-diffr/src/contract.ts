// The typed boundary between the server entry and the host entry that runs
// diffr on the machine holding the thread's workspace.
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

export const diffResultSchema = z
  .object({
    /** diffr's NDJSON stream (wire v3), one record per line. */
    ndjson: z.string(),
    /** The arguments diffr ran with, after the preset was resolved. */
    args: z.array(z.string()),
  })
  .strict();
export type DiffResult = z.infer<typeof diffResultSchema>;

export const hostContract = defineRpcContract({
  diff: {
    input: z
      .object({
        cwd: z.string().min(1),
        binary: z.string().min(1),
        mode: diffModeSchema,
        /** Branch names to try, in order, for the `branch` preset. */
        bases: z.array(z.string().min(1)).max(8),
      })
      .strict(),
    output: diffResultSchema,
  },
});
