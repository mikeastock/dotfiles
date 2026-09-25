import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { portScanContract } from "./port-scan-contract";
import type { OwnedPortTarget } from "./close-owned-ports";

export function createThreadPortActions(bb: BbPluginApi) {
  const host = bb.hosts.experimental_client({ contract: portScanContract });
  const controller = new AbortController();
  bb.onDispose(() => controller.abort());
  async function context(threadId: string) {
    const thread = await bb.sdk.threads.get({ threadId });
    if (!thread.environmentId) return null;
    const environment = await bb.sdk.environments.get({ environmentId: thread.environmentId });
    if (environment.status !== "ready" || !environment.path) throw new Error("Thread workspace is unavailable");
    return {
      root: { environmentId: environment.id, path: environment.path },
      options: { hostId: environment.hostId, signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20_000)]) },
    };
  }
  return {
    async getThreadPorts({ threadId }: { threadId: string }) {
      const target = await context(threadId);
      if (!target) return { ports: [] };
      const result = await host.call("scan", { roots: [target.root] }, target.options);
      return { ports: result.ports.filter((port) => port.environmentId === target.root.environmentId && port.ownerThreadId === threadId && port.source === "process" && port.pid && port.pid > 1).map((port) => ({ port: port.port, pid: port.pid! })) };
    },
    async closeThreadPorts({ threadId, ports }: { threadId: string; ports: OwnedPortTarget[] }) {
      const target = await context(threadId);
      if (!target) throw new Error("Thread has no workspace");
      return host.call("closeOwnedPorts", { root: target.root, threadId, ports }, target.options);
    },
  };
}
