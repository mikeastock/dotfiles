// bb-plugin-diffr backend: resolves a thread's workspace and asks this
// plugin's host entry, on the machine that holds it, to run diffr there and
// read back file records.
import { defineRpcContract, type BbPluginApi } from "@get-bb/plugin-sdk";
import { z } from "zod";
import { diffModeSchema, diffRunSchema, hostContract, readRangeSchema, readResultSchema } from "./src/contract";

const threadIdSchema = z.string().min(1);

export const rpcContract = defineRpcContract({
  diff: {
    input: z.object({ threadId: threadIdSchema, mode: diffModeSchema }).strict(),
    output: diffRunSchema,
  },
  read: {
    input: readRangeSchema.extend({ threadId: threadIdSchema }),
    output: readResultSchema,
  },
});

/** diffr parses with tree-sitter and diffs every file; give large changes time. */
const DIFF_TIMEOUT_MS = 120_000;

export default async function plugin(bb: BbPluginApi) {
  const settings = bb.settings.define({
    diffrPath: {
      type: "string",
      label: "diffr binary",
      description:
        "Command or absolute path of diffr on the machine that holds each workspace. The default also tries ~/.local/bin/diffr, where the install script puts it.",
      default: "diffr",
    },
    byteLimit: {
      type: "string",
      label: "Structural diff size limit (bytes)",
      description:
        "Files larger than this on either side get a plain line diff (diffr's --byte-limit). diffr's own default, 1 MB, lets large JSON or data files take minutes to diff structurally. Leave empty to use diffr's configured limit.",
      default: "262144",
      experimental_schema: z.string().regex(/^\d*$/, "Enter a whole number of bytes, or leave it empty"),
    },
  });
  const host = bb.hosts.experimental_client({ contract: hostContract });

  async function workspace(threadId: string) {
    const thread = await bb.sdk.threads.get({ threadId });
    if (thread.environmentId === null) throw new Error("This thread has no workspace yet.");
    const environment = await bb.sdk.environments.get({ environmentId: thread.environmentId });
    if (environment.path === null) throw new Error("This thread's workspace has no path yet.");
    if (!environment.isGitRepo) throw new Error("diffr needs a Git repository; this workspace is not one.");
    return { ...environment, path: environment.path };
  }

  bb.rpc.register(rpcContract, {
    diff: async ({ threadId, mode }) => {
      const environment = await workspace(threadId);
      const { diffrPath, byteLimit } = await settings.get();
      const bases = [environment.mergeBaseBranch, environment.baseBranch, environment.defaultBranch].filter(
        (branch): branch is string => branch !== null && branch !== "",
      );
      return host.call(
        "diff",
        {
          cwd: environment.path,
          binary: diffrPath.trim() || "diffr",
          mode,
          bases: [...new Set(bases)],
          byteLimit: byteLimit.trim() === "" ? null : Number(byteLimit),
        },
        { hostId: environment.hostId, timeoutMs: DIFF_TIMEOUT_MS },
      );
    },
    read: async ({ threadId, runId, offset, length }) => {
      const environment = await workspace(threadId);
      return host.call("read", { runId, offset, length }, { hostId: environment.hostId });
    },
  });
}
