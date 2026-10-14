// bb-plugin-diffr backend: resolves a thread's workspace and asks this
// plugin's host entry, on the machine that holds it, to run diffr there.
import { defineRpcContract, type BbPluginApi } from "@get-bb/plugin-sdk";
import { z } from "zod";
import { diffModeSchema, diffResultSchema, hostContract } from "./src/contract";

export const rpcContract = defineRpcContract({
  diff: {
    input: z.object({ threadId: z.string().min(1), mode: diffModeSchema }).strict(),
    output: diffResultSchema,
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
  });
  const host = bb.hosts.experimental_client({ contract: hostContract });

  bb.rpc.register(rpcContract, {
    diff: async ({ threadId, mode }) => {
      const thread = await bb.sdk.threads.get({ threadId });
      if (thread.environmentId === null) throw new Error("This thread has no workspace yet.");
      const environment = await bb.sdk.environments.get({ environmentId: thread.environmentId });
      if (environment.path === null) throw new Error("This thread's workspace has no path yet.");
      if (!environment.isGitRepo) throw new Error("diffr needs a Git repository; this workspace is not one.");
      const { diffrPath } = await settings.get();
      const bases = [environment.mergeBaseBranch, environment.baseBranch, environment.defaultBranch].filter(
        (branch): branch is string => branch !== null && branch !== "",
      );
      return host.call(
        "diff",
        { cwd: environment.path, binary: diffrPath.trim() || "diffr", mode, bases: [...new Set(bases)] },
        { hostId: environment.hostId, timeoutMs: DIFF_TIMEOUT_MS },
      );
    },
  });
}
