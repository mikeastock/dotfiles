import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { portScanContract, type PortRoot } from "./port-scan-contract";
import type { PortSnapshot } from "./open-ports";

async function forEachConcurrent<T>(items: T[], limit: number, visit: (item: T) => Promise<void>) {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await visit(items[next++]);
  }));
}

export function createPortDiscovery(bb: BbPluginApi) {
  const host = bb.hosts.experimental_client({ contract: portScanContract });
  const controller = new AbortController();
  bb.onDispose(() => controller.abort());
  let cached: PortSnapshot = { groups: [] };
  let scannedAt = -Infinity;
  let pending: Promise<PortSnapshot> | null = null;
  let generation = 0;
  const environments = new Map<string, { root: PortRoot; hostId: string; expiresAt: number }>();
  const failures = new Map<string, { attempts: number; retryAt: number }>();

  async function scan(): Promise<PortSnapshot> {
    const ids = new Set<string>();
    const threadEnvironment = new Map<string, string>();
    for (let offset = 0; ; offset += 500) {
      const threads = await bb.sdk.threads.list({ archived: false, includeHidden: true, limit: 500, offset, signal: controller.signal });
      for (const thread of threads) if (thread.environmentId) {
        ids.add(thread.environmentId);
        threadEnvironment.set(thread.id, thread.environmentId);
      }
      if (threads.length < 500) break;
    }
    for (const id of environments.keys()) if (!ids.has(id)) environments.delete(id);
    const byHost = new Map<string, PortRoot[]>();
    await forEachConcurrent([...ids], 8, async (environmentId) => {
      controller.signal.throwIfAborted();
      try {
        let entry = environments.get(environmentId);
        if (!entry || Date.now() >= entry.expiresAt) {
          environments.delete(environmentId);
          const env = await bb.sdk.environments.get({ environmentId });
          if (env.status !== "ready" || !env.path) return;
          entry = { root: { environmentId, path: env.path }, hostId: env.hostId, expiresAt: Date.now() + 60_000 };
          environments.set(environmentId, entry);
        }
        const roots = byHost.get(entry.hostId) ?? [];
        roots.push(entry.root);
        byHost.set(entry.hostId, roots);
      } catch {
        controller.signal.throwIfAborted();
        // Deleted or inaccessible environment.
      }
    });
    for (const hostId of failures.keys()) if (!byHost.has(hostId)) failures.delete(hostId);
    const groups: PortSnapshot["groups"] = [];
    await forEachConcurrent([...byHost], 4, async ([hostId, roots]) => {
      controller.signal.throwIfAborted();
      if (Date.now() < (failures.get(hostId)?.retryAt ?? 0)) return;
      try {
        const result = await host.call("scan", { roots }, {
          hostId, signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20_000)]),
        });
        failures.delete(hostId);
        for (const root of roots) {
          const ports = result.ports.filter((port) => port.environmentId === root.environmentId).map(({ environmentId: _, ownerThreadId, ...port }) => ({
            ...port,
            ...(ownerThreadId && threadEnvironment.get(ownerThreadId) === root.environmentId ? { ownerThreadId } : {}),
          }));
          if (ports.length) groups.push({ environmentId: root.environmentId, ports });
        }
      } catch (error) {
        controller.signal.throwIfAborted();
        const attempts = Math.min((failures.get(hostId)?.attempts ?? 0) + 1, 5);
        failures.set(hostId, { attempts, retryAt: Date.now() + Math.min(30_000 * 2 ** (attempts - 1), 300_000) });
        bb.log.debug(`Port scan failed on ${hostId}: ${String(error)}`);
      }
    });
    return { groups };
  }

  const discover = () => {
    if (pending) return pending;
    controller.signal.throwIfAborted();
    if (Date.now() - scannedAt < 30_000) return Promise.resolve(cached);
    const scanGeneration = generation;
    pending = scan().then((snapshot) => {
      cached = snapshot;
      scannedAt = scanGeneration === generation ? Date.now() : -Infinity;
      return snapshot;
    }).finally(() => { pending = null; });
    return pending;
  };
  return Object.assign(discover, {
    invalidate() {
      generation++;
      scannedAt = -Infinity;
    },
  });
}
