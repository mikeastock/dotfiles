import { describe, expect, it, vi } from "vitest";
import { closeOwnedPortProcesses } from "./close-owned-ports";
import type { OpenPort } from "./open-ports";

describe("closing thread-owned ports", () => {
  it("stops each matching process once and never stops other threads or workspace-only listeners", async () => {
    const terminate = vi.fn();
    const listeners: OpenPort[] = [
      { port: 3000, pid: 10, source: "process", ownerThreadId: "thr_a" },
      { port: 3001, pid: 10, source: "process", ownerThreadId: "thr_a" },
      { port: 4000, pid: 20, source: "process", ownerThreadId: "thr_b" },
      { port: 5000, pid: 30, source: "process" },
      { port: 6000, pid: 40, source: "docker", ownerThreadId: "thr_a" },
    ];
    const result = await closeOwnedPortProcesses("thr_a", listeners.map(({ port, pid }) => ({ port, pid: pid! })), async () => listeners, terminate);
    expect(terminate.mock.calls).toEqual([[10]]);
    expect(result).toEqual({ signalled: [3000, 3001], skipped: [4000, 5000, 6000], failed: [] });
  });

  it("skips disappeared listeners and reused PIDs with different ports or owners", async () => {
    const terminate = vi.fn();
    const result = await closeOwnedPortProcesses("thr_a", [{ port: 3000, pid: 10 }, { port: 4000, pid: 20 }, { port: 5000, pid: 30 }], async () => [
      { port: 3001, pid: 10, source: "process", ownerThreadId: "thr_a" },
      { port: 4000, pid: 20, source: "process", ownerThreadId: "thr_b" },
    ], terminate);
    expect(terminate).not.toHaveBeenCalled();
    expect(result.skipped).toEqual([3000, 4000, 5000]);
  });

  it("rechecks between processes and reports shutdown failures", async () => {
    const scan = vi.fn()
      .mockResolvedValueOnce([{ port: 3000, pid: 10, source: "process", ownerThreadId: "thr_a" }])
      .mockResolvedValueOnce([]);
    const terminate = vi.fn(() => { throw new Error("Permission denied"); });
    expect(await closeOwnedPortProcesses("thr_a", [{ port: 3000, pid: 10 }, { port: 4000, pid: 20 }], scan, terminate))
      .toEqual({ signalled: [], skipped: [4000], failed: [3000] });
    expect(scan).toHaveBeenCalledTimes(2);
  });
});
