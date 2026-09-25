import { expect, it, vi } from "vitest";
import { createFakePluginHost, makeThreadResponse } from "@get-bb/plugin-sdk/testing";
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { createThreadPortActions } from "./thread-ports";

it("routes port actions to the thread's current host and filters ownership", async () => {
  const call = vi.fn(async ({ method }: { method: string }) => method === "scan" ? {
    ports: [
      { environmentId: "env_a", port: 3000, pid: 100, source: "process", ownerThreadId: "thr_a" },
      { environmentId: "env_a", port: 3001, pid: 101, source: "process", ownerThreadId: "thr_b" },
      { environmentId: "env_a", port: 3002, pid: 102, source: "process" },
      { environmentId: "env_b", port: 3003, pid: 103, source: "process", ownerThreadId: "thr_a" },
    ],
  } : { signalled: [3000], skipped: [], failed: [] });
  const { bb, harness } = createFakePluginHost({
    experimental_callHostRpc: call,
    sdk: {
      threads: { get: async () => makeThreadResponse({ id: "thr_a", environmentId: "env_a" }) },
      environments: { get: async () => ({ id: "env_a", path: "/workspace/a", status: "ready", hostId: "host_a" }) as Awaited<ReturnType<BbPluginApi["sdk"]["environments"]["get"]>> },
    },
  });
  try {
    const actions = createThreadPortActions(bb);
    const result = await actions.getThreadPorts({ threadId: "thr_a" });
    expect(result).toEqual({ ports: [{ port: 3000, pid: 100 }] });
    await actions.closeThreadPorts({ threadId: "thr_a", ports: result.ports });
    expect(harness.inspection.experimental_hostRpcCalls.at(-1)).toMatchObject({
      hostId: "host_a", method: "closeOwnedPorts",
      input: { root: { environmentId: "env_a", path: "/workspace/a" }, threadId: "thr_a", ports: result.ports },
    });
  } finally {
    await harness.lifecycle.dispose();
  }
});
