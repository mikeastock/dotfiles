import { describe, expect, it, vi } from "vitest";
import { createFakePluginHost, makeThreadResponse } from "@get-bb/plugin-sdk/testing";
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { createPortDiscovery } from "./port-discovery";

type Environment = Awaited<ReturnType<BbPluginApi["sdk"]["environments"]["get"]>>;

describe("sidebar port discovery", () => {
  it("scans each host, shares concurrent results, and drops failed hosts on refresh", async () => {
    let offline = false;
    const scan = vi.fn(async ({ hostId }: { hostId: string }) => {
      if (offline) throw new Error("Host offline");
      return { ports: [
        { environmentId: hostId === "host_a" ? "env_a" : "env_b", port: 3000, processName: "node", pid: 1234, address: "127.0.0.1", source: "process", ownerThreadId: "a" },
        { environmentId: "unrequested", port: 9999 },
      ] };
    });
    const { bb, harness } = createFakePluginHost({
      experimental_callHostRpc: scan,
      sdk: {
        threads: { list: async () => [
          makeThreadResponse({ id: "a", environmentId: "env_a" }),
          makeThreadResponse({ id: "a2", environmentId: "env_a" }),
          makeThreadResponse({ id: "b", environmentId: "env_b" }),
        ] },
        environments: { get: async ({ environmentId }) => ({
          id: environmentId, status: "ready", path: `/workspace/${environmentId}`,
          hostId: environmentId === "env_a" ? "host_a" : "host_b",
        }) as Environment },
      },
    });
    const clock = vi.spyOn(Date, "now").mockReturnValue(100_000);
    try {
      const discover = createPortDiscovery(bb);
      const [first, second] = await Promise.all([discover(), discover()]);
      expect(first).toEqual(second);
      expect(first.groups.map((group) => group.environmentId).sort()).toEqual(["env_a", "env_b"]);
      expect(first.groups.find((group) => group.environmentId === "env_a")?.ports[0]).toEqual({ port: 3000, processName: "node", pid: 1234, address: "127.0.0.1", source: "process", ownerThreadId: "a" });
      expect(first.groups.find((group) => group.environmentId === "env_b")?.ports[0].ownerThreadId).toBeUndefined();
      expect(scan).toHaveBeenCalledTimes(2);
      await discover();
      expect(scan).toHaveBeenCalledTimes(2);
      discover.invalidate();
      await discover();
      expect(scan).toHaveBeenCalledTimes(4);
      scan.mockClear();
      offline = true;
      clock.mockReturnValue(131_000);
      expect(await discover()).toEqual({ groups: [] });
      expect(scan).toHaveBeenCalledTimes(2);
      clock.mockReturnValue(162_000);
      await discover();
      expect(scan).toHaveBeenCalledTimes(4);
      clock.mockReturnValue(193_000);
      await discover();
      expect(scan).toHaveBeenCalledTimes(4); // Second failure backs off for a minute.
      offline = false;
      clock.mockReturnValue(224_000);
      expect((await discover()).groups).toHaveLength(2);
      expect(scan).toHaveBeenCalledTimes(6);
      clock.mockReturnValue(255_000);
      await discover();
      expect(scan).toHaveBeenCalledTimes(8); // Recovery resets backoff.
    } finally {
      clock.mockRestore();
      await harness.lifecycle.dispose();
    }
  });

  it("bounds requests, reuses environment metadata, and refreshes moved environments", async () => {
    let environmentActive = 0;
    let hostActive = 0;
    let maxEnvironments = 0;
    let maxHosts = 0;
    let moved = false;
    const get = vi.fn(async ({ environmentId }: { environmentId: string }) => {
      maxEnvironments = Math.max(maxEnvironments, ++environmentActive);
      await new Promise((resolve) => setTimeout(resolve, 1));
      environmentActive--;
      return { id: environmentId, status: "ready", path: moved ? "/moved" : `/workspace/${environmentId}`, hostId: environmentId } as Environment;
    });
    const scan = vi.fn(async () => {
      maxHosts = Math.max(maxHosts, ++hostActive);
      await new Promise((resolve) => setTimeout(resolve, 1));
      hostActive--;
      return { ports: [] };
    });
    const list = vi.fn(async () => Array.from({ length: 20 }, (_, i) => makeThreadResponse({ id: `thr_${i}`, environmentId: `env_${i}` })));
    const { bb, harness } = createFakePluginHost({
      experimental_callHostRpc: scan,
      sdk: { threads: { list }, environments: { get } },
    });
    const clock = vi.spyOn(Date, "now").mockReturnValue(0);
    try {
      const discover = createPortDiscovery(bb);
      await discover();
      expect(maxEnvironments).toBe(8);
      expect(maxHosts).toBe(4);
      expect(get).toHaveBeenCalledTimes(20);
      clock.mockReturnValue(10_000);
      await discover();
      expect(list).toHaveBeenCalledTimes(1);
      expect(scan).toHaveBeenCalledTimes(20);
      clock.mockReturnValue(31_000);
      await discover();
      expect(get).toHaveBeenCalledTimes(20);
      expect(scan).toHaveBeenCalledTimes(40);
      moved = true;
      clock.mockReturnValue(62_000);
      await discover();
      expect(get).toHaveBeenCalledTimes(40);
      expect(harness.inspection.experimental_hostRpcCalls.at(-1)?.input).toEqual({ roots: [{ environmentId: "env_19", path: "/moved" }] });
    } finally {
      clock.mockRestore();
      await harness.lifecycle.dispose();
    }
  });

});
