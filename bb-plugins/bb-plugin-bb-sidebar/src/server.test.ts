import { afterEach, describe, expect, it } from "vitest";
import {
  createFakePluginHost,
  makeThreadResponse,
} from "@get-bb/plugin-sdk/testing";
import plugin, { type StoredLifecycleRow } from "./server";

interface LifecycleListResult {
  rows: StoredLifecycleRow[];
}

const disposers: Array<() => Promise<void>> = [];

function standardProject() {
  return {
    id: "proj_1",
    name: "Sidebar",
    kind: "standard" as const,
    gitRemoteUrl: null,
    createdAt: 1,
    updatedAt: 1,
    sources: [
      {
        id: "source_1",
        projectId: "proj_1",
        type: "local_path" as const,
        hostId: "host_1",
        path: "/workspace/sidebar",
        isDefault: true,
        createdAt: 1,
        updatedAt: 1,
      },
    ],
  };
}

function terminalSession(
  overrides: {
    id: string;
    lastUserInputAt?: number | null;
    status?: "disconnected" | "exited" | "running" | "starting";
  },
) {
  return {
    closeReason: null,
    cols: 80,
    createdAt: 1,
    environmentId: null,
    exitCode: null,
    hostId: "host_1",
    initialCwd: "/workspace/sidebar",
    lastUserInputAt: null,
    rows: 24,
    status: "running" as const,
    threadId: "thr_1",
    title: "zsh",
    updatedAt: 1,
    ...overrides,
  };
}

function availablePullRequest(
  state: "closed" | "draft" | "merged" | "open",
  updatedAt = new Date().toISOString(),
) {
  return {
    outcome: "available" as const,
    pullRequest: {
      attention: state === "merged" ? ("merged" as const) : ("none" as const),
      baseRefName: "main",
      checks: {
        failedCount: 0,
        passedCount: 1,
        pendingCount: 0,
        state: "passing" as const,
        totalCount: 1,
      },
      headRefName: "feature",
      mergeability: {
        mergeStateStatus: "CLEAN" as const,
        mergeable: "MERGEABLE" as const,
        state: "mergeable" as const,
      },
      number: 12,
      review: {
        reviewRequestCount: 0,
        state: "approved" as const,
      },
      state,
      title: "Pull request",
      updatedAt,
      url: "https://example.com/pr/12",
    },
  };
}

afterEach(async () => {
  await Promise.all(disposers.splice(0).map((dispose) => dispose()));
});

async function loadPlugin(
  unpin: (input: {
    threadId: string;
  }) => Promise<ReturnType<typeof makeThreadResponse>> = async ({ threadId }) =>
    makeThreadResponse({ id: threadId }),
) {
  const { bb, harness } = createFakePluginHost({
    pluginId: "bb-sidebar",
    sdk: {
      threads: {
        list: async () => [],
        pin: async ({ threadId }) =>
          makeThreadResponse({ id: threadId, pinnedAt: Date.now() }),
        unpin,
        reorderPinned: async ({ threadId }) => [
          makeThreadResponse({
            id: threadId,
            pinnedAt: 1,
          }),
        ],
      },
    },
  });
  await plugin(bb);
  disposers.push(() => harness.lifecycle.dispose());
  return harness;
}

describe("lifecycle RPC", () => {
  it("returns no ports when no threads have environments", async () => {
    const harness = await loadPlugin();
    await expect(harness.behavior.callRpc("getOpenPorts", {})).resolves.toEqual({
      groups: [],
    });
  });

  it("returns only model and reasoning details, including unset options", async () => {
    const harness = await loadPlugin();
    harness.inspection.sdk.stub("threads.defaultExecutionOptions", async () => ({
      model: "gpt-6",
      reasoningLevel: "high",
      permissionMode: "auto",
      serviceTier: "default",
      source: "client/turn/start",
    }));
    await expect(harness.behavior.callRpc("getThreadExecutionDetails", {
      threadId: "thr_1",
    })).resolves.toEqual({ model: "gpt-6", reasoningLevel: "high" });
    harness.inspection.sdk.stub("threads.defaultExecutionOptions", async () => null);
    await expect(harness.behavior.callRpc("getThreadExecutionDetails", {
      threadId: "thr_1",
    })).resolves.toBeNull();
  });

  it("stores the grouped sidebar settings through RPC", async () => {
    const harness = await loadPlugin();
    expect(harness.inspection.registrations.settingsDescriptors).toEqual({});
    await expect(
      harness.behavior.callRpc("getSidebarSettings", {}),
    ).resolves.toEqual({
      snoozePresets: "1h, Wait refresh (5 hours)=5h, evening@18:00, tomorrow@09:00, next-week@09:00",
      inactiveThreadsEnabled: true,
      inactiveAfterHours: 6,
      showRunningChildrenWhenCollapsed: true,
      autoSettleInactive: true,
      autoSettleAfterDays: 3,
      autoSettleOnMerge: true,
    });
    await expect(
      harness.behavior.callRpc("updateSidebarSettings", {
        snoozePresets: "10m, 4h",
        inactiveThreadsEnabled: false,
        inactiveAfterHours: 12,
        showRunningChildrenWhenCollapsed: false,
        autoSettleInactive: false,
        autoSettleAfterDays: 7,
        autoSettleOnMerge: false,
      }),
    ).resolves.toEqual({
      snoozePresets: "10m, 4h",
      inactiveThreadsEnabled: false,
      inactiveAfterHours: 12,
      showRunningChildrenWhenCollapsed: false,
      autoSettleInactive: false,
      autoSettleAfterDays: 7,
      autoSettleOnMerge: false,
    });
    expect(harness.inspection.realtimeSignals).toContainEqual({
      channel: "sidebar-settings",
      payload: {},
    });
    expect(harness.inspection.registrations.schedules).toContainEqual(
      expect.objectContaining({ name: "auto-settle", cron: "*/5 * * * *" }),
    );
  });

  it("rejects invalid snooze shortcuts at the RPC boundary", async () => {
    const harness = await loadPlugin();

    await expect(
      harness.behavior.callRpc("updateSidebarSettings", {
        snoozePresets: "later",
        inactiveThreadsEnabled: true,
        inactiveAfterHours: 6,
        showRunningChildrenWhenCollapsed: true,
        autoSettleInactive: true,
        autoSettleAfterDays: 3,
        autoSettleOnMerge: true,
      }),
    ).rejects.toThrow("rpc input validation failed");
    await expect(
      harness.behavior.callRpc("getSidebarSettings", {}),
    ).resolves.toMatchObject({ snoozePresets: "1h, Wait refresh (5 hours)=5h, evening@18:00, tomorrow@09:00, next-week@09:00" });
  });

  it("saves editable calendar shortcuts and rejects invalid times", async () => {
    const harness = await loadPlugin();
    const settings = await harness.behavior.callRpc("getSidebarSettings", {}) as Record<string, unknown>;
    const snoozePresets = "1h, Wait refresh=5h, Tonight=evening@20:00, Morning=tomorrow@08:30, Monday=next-week@10:00";
    await expect(harness.behavior.callRpc("updateSidebarSettings", { ...settings, snoozePresets })).resolves.toMatchObject({ snoozePresets });
    await expect(harness.behavior.callRpc("getSidebarSettings", {})).resolves.toMatchObject({ snoozePresets });
    await expect(harness.behavior.callRpc("updateSidebarSettings", { ...settings, snoozePresets: "tomorrow@24:00" })).rejects.toThrow("rpc input validation failed");
    await expect(harness.behavior.callRpc("getSidebarSettings", {})).resolves.toMatchObject({ snoozePresets });
  });

  it("migrates values from the previous flat settings form", async () => {
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        plugins: {
          getSettings: async () => ({
            ok: true as const,
            schema: {},
            values: {
              snoozePresets: "20m, 6h",
              inactiveThreadsEnabled: false,
              inactiveAfterHours: "18",
              showRunningChildrenWhenCollapsed: false,
              autoSettleInactive: false,
              autoSettleAfterDays: "14",
              autoSettleOnMerge: false,
            },
          }),
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("getSidebarSettings", {}),
    ).resolves.toEqual({
      snoozePresets: "20m, 6h",
      inactiveThreadsEnabled: false,
      inactiveAfterHours: 18,
      showRunningChildrenWhenCollapsed: false,
      autoSettleInactive: false,
      autoSettleAfterDays: 14,
      autoSettleOnMerge: false,
    });
  });

  it("settles and restores a thread", async () => {
    const harness = await loadPlugin();

    await harness.behavior.callRpc("settle", { threadId: "thr_1" });
    expect(harness.inspection.sdk.callsTo("threads.unpin")).toEqual([
      [{ threadId: "thr_1" }],
    ]);
    const settled = (await harness.behavior.callRpc(
      "listLifecycle",
      {},
    )) as LifecycleListResult;
    expect(settled.rows).toEqual([
      expect.objectContaining({
        threadId: "thr_1",
        settledAt: expect.any(Number),
        snoozedUntil: null,
      }),
    ]);

    await harness.behavior.callRpc("unsettle", { threadId: "thr_1" });
    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({
      rows: [
        expect.objectContaining({
          threadId: "thr_1",
          settledAt: null,
          settledOverride: "active",
        }),
      ],
    });
  });

  it.each(["settle", "snooze", "park"])(
    "makes pin and %s mutually exclusive in both directions",
    async (method) => {
      const harness = await loadPlugin();
      let pinned = false;
      harness.inspection.sdk.stub("threads.pin", async ({ threadId }) => {
        pinned = true;
        return makeThreadResponse({ id: threadId, pinnedAt: Date.now() });
      });
      harness.inspection.sdk.stub("threads.unpin", async ({ threadId }) => {
        pinned = false;
        return makeThreadResponse({ id: threadId, pinnedAt: null });
      });

      await harness.behavior.callRpc("pin", { threadId: "thr_1" });
      expect(pinned).toBe(true);
      await harness.behavior.callRpc(method, {
        threadId: "thr_1",
        ...(method === "snooze" ? { snoozedUntil: Date.now() + 60_000 } : {}),
      });
      expect(pinned).toBe(false);
      const shelfField = method === "park" ? "parkedAt"
        : method === "snooze" ? "snoozedUntil" : "settledAt";
      await expect(harness.behavior.callRpc("listLifecycle", {})).resolves.toMatchObject({
        rows: [{ [shelfField]: expect.any(Number) }],
      });

      await expect(harness.behavior.callRpc("pin", { threadId: "thr_1" }))
        .resolves.toEqual({ ok: true });
      expect(pinned).toBe(true);
      await expect(harness.behavior.callRpc("listLifecycle", {})).resolves.toEqual({
        rows: [{
          threadId: "thr_1",
          parkedAt: null,
          settledAt: null,
          settledOverride: "active",
          snoozedUntil: null,
          snoozedAt: null,
        }],
      });
      expect(harness.inspection.realtimeSignals.at(-1)).toEqual({
        channel: "lifecycle",
        payload: { threadId: "thr_1" },
      });
    },
  );

  it.each(["settle", "snooze", "park"])(
    "preserves %s when native pinning fails",
    async (method) => {
      const harness = await loadPlugin();
      await harness.behavior.callRpc(method, {
        threadId: "thr_1",
        ...(method === "snooze" ? { snoozedUntil: Date.now() + 60_000 } : {}),
      });
      const before = await harness.behavior.callRpc("listLifecycle", {});
      harness.inspection.sdk.stub("threads.pin", async () => {
        throw new Error("pin update failed");
      });

      await expect(harness.behavior.callRpc("pin", { threadId: "thr_1" }))
        .rejects.toThrow("pin update failed");
      await expect(harness.behavior.callRpc("listLifecycle", {})).resolves.toEqual(before);
    },
  );

  it("releases the agent session and only the terminals nobody used", async () => {
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [],
          unpin: async ({ threadId }: { threadId: string }) =>
            makeThreadResponse({ id: threadId }),
          stop: async () => ({ ok: true as const }),
        },
        terminals: {
          list: async () => ({
            sessions: [
              terminalSession({ id: "term_idle" }),
              terminalSession({ id: "term_used", lastUserInputAt: 5 }),
              terminalSession({ id: "term_gone", status: "exited" }),
            ],
          }),
          close: async ({ terminalId }: { terminalId: string }) =>
            terminalSession({ id: terminalId, status: "exited" }),
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("settle", { threadId: "thr_1" }),
    ).resolves.toEqual({
      ok: true,
      reclaim: { closedTerminals: 1, keptTerminals: 1, stoppedRuntime: true },
    });
    expect(harness.inspection.sdk.callsTo("threads.stop")).toEqual([
      [{ threadId: "thr_1" }],
    ]);
    expect(harness.inspection.sdk.callsTo("terminals.close")).toEqual([
      [{ terminalId: "term_idle", mode: "if-clean" }],
    ]);
  });

  it("settles even when the runtime and terminals cannot be reached", async () => {
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [],
          unpin: async ({ threadId }: { threadId: string }) =>
            makeThreadResponse({ id: threadId }),
          stop: async () => {
            throw new Error("host offline");
          },
        },
        terminals: {
          list: async () => {
            throw new Error("host offline");
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("settle", { threadId: "thr_1" }),
    ).resolves.toEqual({
      ok: true,
      reclaim: { closedTerminals: 0, keptTerminals: 0, stoppedRuntime: false },
    });
    const settled = (await harness.behavior.callRpc(
      "listLifecycle",
      {},
    )) as LifecycleListResult;
    expect(settled.rows).toEqual([
      expect.objectContaining({ threadId: "thr_1", settledOverride: "settled" }),
    ]);
  });

  it("releases every archived runtime even when one stop fails", async () => {
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [],
          stop: async ({ threadId }: { threadId: string }) => {
            if (threadId === "thr_offline") throw new Error("host offline");
            return { ok: true as const };
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("releaseRuntimes", {
        threadIds: ["thr_offline", "thr_1"],
      }),
    ).resolves.toEqual({ ok: true });
    expect(harness.inspection.sdk.callsTo("threads.stop")).toEqual([
      [{ threadId: "thr_offline" }],
      [{ threadId: "thr_1" }],
    ]);
  });

  it("keeps settle and snooze mutually exclusive", async () => {
    const harness = await loadPlugin();
    const wakeAt = Date.now() + 60_000;

    await harness.behavior.callRpc("settle", { threadId: "thr_1" });
    await harness.behavior.callRpc("snooze", {
      threadId: "thr_1",
      snoozedUntil: wakeAt,
    });

    const result = (await harness.behavior.callRpc(
      "listLifecycle",
      {},
    )) as LifecycleListResult;
    expect(result.rows).toEqual([
      expect.objectContaining({
        threadId: "thr_1",
        settledAt: null,
        snoozedUntil: wakeAt,
        snoozedAt: expect.any(Number),
      }),
    ]);
  });

  it("clears a woken snooze when the user acknowledges it", async () => {
    const harness = await loadPlugin();
    await harness.behavior.callRpc("snooze", {
      threadId: "thr_woke",
      snoozedUntil: Date.now() - 1,
    });

    await harness.behavior.callRpc("acknowledgeWake", {
      threadId: "thr_woke",
    });

    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({ rows: [] });
  });

  it("persists pinned placement through the bb SDK", async () => {
    const harness = await loadPlugin();

    await expect(
      harness.behavior.callRpc("reorderPinned", {
        threadId: "thr_2",
        previousThreadId: "thr_1",
        nextThreadId: "thr_3",
      }),
    ).resolves.toEqual({ pinnedThreadIds: ["thr_2"] });
    expect(harness.inspection.sdk.callsTo("threads.reorderPinned")).toEqual([
      [
        {
          threadId: "thr_2",
          previousThreadId: "thr_1",
          nextThreadId: "thr_3",
        },
      ],
    ]);
  });

  it("persists inbox order in the plugin database and publishes it", async () => {
    const harness = await loadPlugin();

    await expect(
      harness.behavior.callRpc("reorderInbox", {
        inboxThreadIds: ["thr_2", "thr_1"],
      }),
    ).resolves.toEqual({ inboxThreadIds: ["thr_2", "thr_1"] });
    await expect(
      harness.behavior.callRpc("listInboxOrder", {}),
    ).resolves.toEqual({ inboxThreadIds: ["thr_2", "thr_1"] });
    expect(harness.inspection.realtimeSignals).toContainEqual({
      channel: "inbox-order",
      payload: {},
    });

    const reloaded = await harness.lifecycle.reload(plugin);
    disposers.push(() => reloaded.harness.lifecycle.dispose());
    await expect(
      reloaded.harness.behavior.callRpc("listInboxOrder", {}),
    ).resolves.toEqual({ inboxThreadIds: ["thr_2", "thr_1"] });
  });

  it("rejects duplicate inbox ids without replacing the saved order", async () => {
    const harness = await loadPlugin();
    await harness.behavior.callRpc("reorderInbox", {
      inboxThreadIds: ["thr_1", "thr_2"],
    });

    await expect(
      harness.behavior.callRpc("reorderInbox", {
        inboxThreadIds: ["thr_1", "thr_1"],
      }),
    ).rejects.toThrow();
    await expect(
      harness.behavior.callRpc("listInboxOrder", {}),
    ).resolves.toEqual({ inboxThreadIds: ["thr_1", "thr_2"] });
  });

  it("removes lifecycle state when bb deletes the thread", async () => {
    const harness = await loadPlugin();
    await harness.behavior.callRpc("settle", { threadId: "thr_1" });

    await harness.behavior.emitThreadEvent("thread.deleted", {
      thread: makeThreadResponse({ id: "thr_1" }),
    });

    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({ rows: [] });
  });

  it("removes a deleted thread from the saved inbox order", async () => {
    const harness = await loadPlugin();
    await harness.behavior.callRpc("reorderInbox", {
      inboxThreadIds: ["thr_1", "thr_2"],
    });

    await harness.behavior.emitThreadEvent("thread.deleted", {
      thread: makeThreadResponse({ id: "thr_1" }),
    });

    await expect(
      harness.behavior.callRpc("listInboxOrder", {}),
    ).resolves.toEqual({ inboxThreadIds: ["thr_2"] });
  });

  it.each(["settle", "snooze", "park"])("does not %s when native unpinning fails", async (method) => {
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          unpin: async () => {
            throw new Error("pin update failed");
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc(method, {
        threadId: "thr_1",
        ...(method === "snooze" ? { snoozedUntil: Date.now() + 60_000 } : {}),
      }),
    ).rejects.toThrow("pin update failed");
    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({ rows: [] });
    expect(harness.inspection.sdk.callsTo("threads.stop")).toEqual([]);
  });
});

describe("project icons", () => {
  it("stores per-project choices and searches only supported image files", async () => {
    const project = standardProject();
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        projects: {
          get: async () => project,
          list: async () => [project],
          paths: async () => ({
            paths: [
              {
                kind: "file" as const,
                name: "brand.svg",
                path: "public/brand.svg",
                positions: [],
                score: 1,
              },
              {
                kind: "file" as const,
                name: "readme.md",
                path: "README.md",
                positions: [],
                score: 0.5,
              },
            ],
            truncated: false,
          }),
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("listProjectIconSettings", {}),
    ).resolves.toEqual({
      projects: [
        {
          id: "proj_1",
          name: "Sidebar",
          customPath: null,
          customUploadName: null,
        },
      ],
    });
    await expect(
      harness.behavior.callRpc("searchProjectIconFiles", {
        projectId: "proj_1",
        query: "brand",
      }),
    ).resolves.toEqual({ paths: ["public/brand.svg"] });

    await expect(
      harness.behavior.callRpc("setProjectIcon", {
        projectId: "proj_1",
        path: "public/brand.svg",
      }),
    ).resolves.toEqual({
      customPath: "public/brand.svg",
      customUploadName: null,
    });
    await expect(
      harness.behavior.callRpc("listProjectIconSettings", {}),
    ).resolves.toEqual({
      projects: [
        {
          id: "proj_1",
          name: "Sidebar",
          customPath: "public/brand.svg",
          customUploadName: null,
        },
      ],
    });
    expect(harness.inspection.realtimeSignals).toContainEqual({
      channel: "project-icons",
      payload: { projectId: "proj_1" },
    });

    await expect(
      harness.behavior.callRpc("uploadProjectIcon", {
        projectId: "proj_1",
        filename: "brand.svg",
        mimeType: "image/svg+xml",
        contentBase64: "PHN2Zy8+",
      }),
    ).resolves.toEqual({
      customPath: null,
      customUploadName: "brand.svg",
    });
    await expect(
      harness.behavior.callRpc("listProjectIconSettings", {}),
    ).resolves.toEqual({
      projects: [
        {
          id: "proj_1",
          name: "Sidebar",
          customPath: null,
          customUploadName: "brand.svg",
        },
      ],
    });
    const response = await harness.behavior.fetchHttp(
      "GET",
      "/project-icon?projectId=proj_1",
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("image/svg+xml");
    await expect(response.text()).resolves.toBe("<svg/>");
  });

  it("serves an automatically discovered favicon through the local route", async () => {
    const project = standardProject();
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        projects: {
          get: async () => project,
          fileContent: async ({ path }) => {
            if (path !== "favicon.svg") throw new Error("not found");
            return {
              content: '<svg xmlns="http://www.w3.org/2000/svg"/>',
              contentEncoding: "utf8" as const,
              mimeType: "image/svg+xml",
              sizeBytes: 46,
            };
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    const [response, concurrentResponse] = await Promise.all([
      harness.behavior.fetchHttp(
        "GET",
        "/project-icon?projectId=proj_1",
      ),
      harness.behavior.fetchHttp(
        "GET",
        "/project-icon?projectId=proj_1",
      ),
    ]);
    expect(response.status).toBe(200);
    expect(concurrentResponse.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("image/svg+xml");
    await expect(response.text()).resolves.toContain("<svg");
    expect(harness.inspection.sdk.callsTo("projects.fileContent")).toEqual([
      [
        {
          projectId: "proj_1",
          hostId: "host_1",
          path: "favicon.svg",
        },
      ],
    ]);
  });

  it("does not cache a failed icon read as a missing icon", async () => {
    const project = standardProject();
    let hostReady = false;
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        projects: {
          get: async () => project,
          fileContent: async ({ path }) => {
            if (!hostReady) throw new Error("Host host_1 is not connected");
            if (path !== "icon.svg") throw new Error("not found");
            return {
              content: '<svg xmlns="http://www.w3.org/2000/svg"/>',
              contentEncoding: "utf8" as const,
              mimeType: "image/svg+xml",
              sizeBytes: 46,
            };
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    const failed = await harness.behavior.fetchHttp(
      "GET",
      "/project-icon?projectId=proj_1",
    );
    expect(failed.status).toBe(503);
    expect(failed.headers.get("cache-control")).toBe("no-store");

    hostReady = true;
    const recovered = await harness.behavior.fetchHttp(
      "GET",
      "/project-icon?projectId=proj_1",
    );
    expect(recovered.status).toBe(200);
    await expect(recovered.text()).resolves.toContain("<svg");
  });

  it("does not reuse or cache an icon resolution that was invalidated", async () => {
    const project = standardProject();
    let oldReadStarted!: () => void;
    const oldReadStartedPromise = new Promise<void>((resolve) => {
      oldReadStarted = resolve;
    });
    let resolveOldRead!: (file: {
      content: string;
      contentEncoding: "utf8";
      mimeType: string;
      sizeBytes: number;
    }) => void;
    const oldRead = new Promise<{
      content: string;
      contentEncoding: "utf8";
      mimeType: string;
      sizeBytes: number;
    }>((resolve) => {
      resolveOldRead = resolve;
    });
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        projects: {
          get: async () => project,
          fileContent: async ({ path }) => {
            if (path === "old.svg") {
              oldReadStarted();
              return oldRead;
            }
            if (path === "new.svg") {
              return {
                content: "new",
                contentEncoding: "utf8" as const,
                mimeType: "image/svg+xml",
                sizeBytes: 3,
              };
            }
            throw new Error("not found");
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await harness.behavior.callRpc("setProjectIcon", {
      projectId: "proj_1",
      path: "old.svg",
    });
    const firstResponse = harness.behavior.fetchHttp(
      "GET",
      "/project-icon?projectId=proj_1",
    );
    await oldReadStartedPromise;

    await expect(
      harness.behavior.callRpc("setProjectIcon", {
        projectId: "proj_1",
        path: "new.svg",
      }),
    ).resolves.toEqual({
      customPath: "new.svg",
      customUploadName: null,
    });
    const secondResponse = await harness.behavior.fetchHttp(
      "GET",
      "/project-icon?projectId=proj_1",
    );
    expect(secondResponse.status).toBe(200);
    await expect(secondResponse.text()).resolves.toBe("new");

    resolveOldRead({
      content: "old",
      contentEncoding: "utf8",
      mimeType: "image/svg+xml",
      sizeBytes: 3,
    });
    const first = await firstResponse;
    expect(first.status).toBe(200);
    await expect(first.text()).resolves.toBe("old");

    const afterPendingResponse = await harness.behavior.fetchHttp(
      "GET",
      "/project-icon?projectId=proj_1",
    );
    expect(afterPendingResponse.status).toBe(200);
    await expect(afterPendingResponse.text()).resolves.toBe("new");
  });
});

describe("project management", () => {
  it("renames standard projects and rejects personal projects or empty names", async () => {
    let project = standardProject();
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: { projects: { get: async () => project, update: async ({ name }) => ({ ...project, name: name! }) } },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());
    await expect(harness.behavior.callRpc("renameProject", { projectId: "proj_1", name: "  New name  " })).resolves.toEqual({ ok: true });
    expect(harness.inspection.sdk.callsTo("projects.update")).toEqual([[{ projectId: "proj_1", name: "New name" }]]);
    await expect(harness.behavior.callRpc("renameProject", { projectId: "proj_1", name: " " })).rejects.toThrow();
    project = { ...project, kind: "personal" } as unknown as typeof project;
    await expect(harness.behavior.callRpc("renameProject", { projectId: "proj_1", name: "No" })).rejects.toThrow("Personal projects");
    expect(harness.inspection.sdk.callsTo("projects.update")).toHaveLength(1);
  });

  it("only offers connected machines without a source and rejects duplicate paths", async () => {
    const project = standardProject();
    const host = { id: "host_1", name: "Desktop", status: "connected" as const, type: "persistent" as const,
      createdAt: 1, updatedAt: 1, lastSeenAt: 1, lastRejectedProtocolVersion: null, maxPermissionMode: "auto" as const };
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        hosts: { list: async () => [host, { ...host, id: "host_2", name: "Laptop" }, { ...host, id: "host_3", status: "disconnected" }] },
        projects: { get: async () => project, sources: { add: async () => ({ ...project.sources[0]!, hostId: "host_2" }) } },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());
    await expect(harness.behavior.callRpc("projectPathHosts", { projectId: "proj_1" })).resolves.toEqual({ hosts: [{ id: "host_2", name: "Laptop" }] });
    await expect(harness.behavior.callRpc("addProjectPath", { projectId: "proj_1", hostId: "host_1", path: "/work" })).rejects.toThrow("already has a path");
    expect(harness.inspection.sdk.callsTo("projects.sources.add")).toHaveLength(0);
    await harness.behavior.callRpc("addProjectPath", { projectId: "proj_1", hostId: "host_2", path: "/work" });
    expect(harness.inspection.sdk.callsTo("projects.sources.add")).toEqual([[{ projectId: "proj_1", hostId: "host_2", path: "/work", type: "local_path" }]]);
  });

  it("requires the project name before removing a standard project", async () => {
    const project = standardProject();
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        projects: {
          delete: async () => ({ ok: true as const }),
          get: async () => project,
          list: async () => [project],
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(harness.behavior.callRpc("listProjects", {})).resolves.toEqual({
      projects: [{ id: "proj_1", name: "Sidebar" }],
    });
    await expect(
      harness.behavior.callRpc("removeProject", {
        projectId: "proj_1",
        confirmation: "sidebar",
      }),
    ).rejects.toThrow("Enter the project name exactly as shown");
    expect(harness.inspection.sdk.callsTo("projects.delete")).toEqual([]);

    await harness.behavior.callRpc("uploadProjectIcon", {
      projectId: "proj_1",
      filename: "brand.svg",
      mimeType: "image/svg+xml",
      contentBase64: "PHN2Zy8+",
    });
    await expect(
      harness.behavior.callRpc("removeProject", {
        projectId: "proj_1",
        confirmation: "Sidebar",
      }),
    ).resolves.toEqual({ ok: true });
    expect(harness.inspection.sdk.callsTo("projects.delete")).toEqual([
      [{ projectId: "proj_1" }],
    ]);
    await expect(
      harness.behavior.callRpc("listProjectIconSettings", {}),
    ).resolves.toEqual({
      projects: [
        {
          id: "proj_1",
          name: "Sidebar",
          customPath: null,
          customUploadName: null,
        },
      ],
    });
    expect(harness.inspection.realtimeSignals).toContainEqual({
      channel: "project-icons",
      payload: { projectId: "proj_1" },
    });
  });
});

describe("automatic settle evaluation", () => {
  it("settles inactive threads and publishes one batched refresh", async () => {
    const old = Date.now() - 4 * 24 * 60 * 60 * 1_000;
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [
            makeThreadResponse({
              id: "thr_old",
              createdAt: old,
              updatedAt: old,
              latestAttentionAt: old,
              status: "idle",
            }),
          ],
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("evaluateAutoSettle", {}),
    ).resolves.toEqual({ changedThreadIds: ["thr_old"] });
    const result = (await harness.behavior.callRpc(
      "listLifecycle",
      {},
    )) as LifecycleListResult;
    expect(result.rows).toEqual([
      expect.objectContaining({
        threadId: "thr_old",
        settledAt: expect.any(Number),
        settledOverride: null,
      }),
    ]);
    expect(harness.inspection.realtimeSignals).toContainEqual({
      channel: "lifecycle",
      payload: { threadIds: ["thr_old"] },
    });
  });

  it("keeps manual un-settle active until real work clears the override", async () => {
    const old = Date.now() - 4 * 24 * 60 * 60 * 1_000;
    const thread = makeThreadResponse({
      id: "thr_override",
      createdAt: old,
      updatedAt: old,
      latestAttentionAt: old,
      status: "idle",
    });
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [thread],
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await harness.behavior.callRpc("unsettle", {
      threadId: "thr_override",
    });
    await expect(
      harness.behavior.callRpc("evaluateAutoSettle", {}),
    ).resolves.toEqual({ changedThreadIds: [] });

    await harness.behavior.emitThreadEvent("thread.active", { thread });
    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({ rows: [] });
  });

  it("looks up a shared environment once and settles merged PR threads together", async () => {
    const old = Date.now() - 60_000;
    const environmentId = "env_shared";
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [
            makeThreadResponse({
              id: "thr_a",
              environmentId,
              createdAt: old,
              updatedAt: old,
              latestAttentionAt: old,
              status: "idle",
            }),
            makeThreadResponse({
              id: "thr_b",
              environmentId,
              createdAt: old,
              updatedAt: old,
              latestAttentionAt: old,
              status: "idle",
            }),
            makeThreadResponse({
              id: "thr_running",
              environmentId: "env_running",
              createdAt: old,
              updatedAt: old,
              latestAttentionAt: old,
              status: "active",
            }),
            makeThreadResponse({
              id: "thr_pinned",
              environmentId: "env_pinned",
              createdAt: old,
              updatedAt: old,
              latestAttentionAt: old,
              pinnedAt: Date.now(),
              status: "idle",
            }),
          ],
        },
        environments: {
          pullRequest: async () => availablePullRequest("merged"),
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("evaluateAutoSettle", {}),
    ).resolves.toEqual({ changedThreadIds: ["thr_a", "thr_b"] });
    expect(
      harness.inspection.sdk.callsTo("environments.pullRequest"),
    ).toHaveLength(1);
  });

  it("queues one policy pass when settings change during evaluation", async () => {
    const old = Date.now() - 60_000;
    const environmentId = "env_queued";
    const thread = makeThreadResponse({
      id: "thr_queued",
      environmentId,
      createdAt: old,
      updatedAt: old,
      latestAttentionAt: old,
      status: "idle",
    });
    let pullRequestCalls = 0;
    let resolveFirstPullRequest!: (value: ReturnType<typeof availablePullRequest>) => void;
    const firstPullRequest = new Promise<ReturnType<typeof availablePullRequest>>(
      (resolve) => {
        resolveFirstPullRequest = resolve;
      },
    );
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: { list: async () => [thread] },
        environments: {
          pullRequest: async () => {
            pullRequestCalls += 1;
            return pullRequestCalls === 1
              ? firstPullRequest
              : availablePullRequest("merged");
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    const firstEvaluation = harness.behavior.callRpc("evaluateAutoSettle", {});
    for (let attempt = 0; attempt < 10 && pullRequestCalls < 1; attempt += 1) {
      await Promise.resolve();
    }
    expect(pullRequestCalls).toBe(1);

    await expect(
      harness.behavior.callRpc("updateSidebarSettings", {
        snoozePresets: "30m, 2h, 1d, 1w",
        inactiveThreadsEnabled: true,
        inactiveAfterHours: 6,
        showRunningChildrenWhenCollapsed: true,
        autoSettleInactive: false,
        autoSettleAfterDays: 3,
        autoSettleOnMerge: false,
      }),
    ).resolves.toMatchObject({ autoSettleInactive: false });

    resolveFirstPullRequest(availablePullRequest("merged"));
    await expect(firstEvaluation).resolves.toEqual({
      changedThreadIds: ["thr_queued"],
    });
    for (let attempt = 0; attempt < 10 && pullRequestCalls < 2; attempt += 1) {
      await Promise.resolve();
    }
    expect(pullRequestCalls).toBe(2);
    let lifecycle = (await harness.behavior.callRpc(
      "listLifecycle",
      {},
    )) as LifecycleListResult;
    for (let attempt = 0; attempt < 10 && lifecycle.rows.length > 0; attempt += 1) {
      await Promise.resolve();
      lifecycle = (await harness.behavior.callRpc(
        "listLifecycle",
        {},
      )) as LifecycleListResult;
    }
    expect(lifecycle).toEqual({ rows: [] });
  });

  it("returns a policy-settled thread when its PR reopens", async () => {
    const recent = Date.now() - 60_000;
    let pullRequestState: "merged" | "open" = "merged";
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [
            makeThreadResponse({
              id: "thr_pr",
              environmentId: "env_pr",
              createdAt: recent,
              updatedAt: recent,
              latestAttentionAt: recent,
              status: "idle",
            }),
          ],
        },
        environments: {
          pullRequest: async () => availablePullRequest(pullRequestState),
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await expect(
      harness.behavior.callRpc("evaluateAutoSettle", {}),
    ).resolves.toEqual({ changedThreadIds: ["thr_pr"] });
    pullRequestState = "open";
    await expect(
      harness.behavior.callRpc("evaluateAutoSettle", {}),
    ).resolves.toEqual({ changedThreadIds: ["thr_pr"] });
    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({ rows: [] });
  });

  it("clears policy-owned settled state when the user pins the thread", async () => {
    const old = Date.now() - 4 * 24 * 60 * 60 * 1_000;
    let pinnedAt: number | null = null;
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: {
          list: async () => [
            makeThreadResponse({
              id: "thr_pin",
              createdAt: old,
              updatedAt: old,
              latestAttentionAt: old,
              pinnedAt,
              status: "idle",
            }),
          ],
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());

    await harness.behavior.callRpc("evaluateAutoSettle", {});
    pinnedAt = Date.now();
    await expect(
      harness.behavior.callRpc("evaluateAutoSettle", {}),
    ).resolves.toEqual({ changedThreadIds: ["thr_pin"] });
    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({ rows: [] });
  });
});


describe("parked lifecycle", () => {
  it("stores parking, replaces snooze, and resumes with cleanup protection", async () => {
    const harness = await loadPlugin();
    await harness.behavior.callRpc("snooze", { threadId: "thr_1", snoozedUntil: Date.now() + 60000 });
    await harness.behavior.callRpc("park", { threadId: "thr_1" });
    expect(await harness.behavior.callRpc("listLifecycle", {})).toMatchObject({ rows: [{ parkedAt: expect.any(Number), snoozedUntil: null, settledAt: null }] });
    await harness.behavior.callRpc("resume", { threadId: "thr_1" });
    expect(await harness.behavior.callRpc("listLifecycle", {})).toMatchObject({ rows: [{ parkedAt: null, settledOverride: "active" }] });
  });
  it.each(["snooze", "settle"])("clears parking when moved to %s", async (method) => {
    const harness = await loadPlugin();
    await harness.behavior.callRpc("park", { threadId: "thr_1" });
    await harness.behavior.callRpc(method, { threadId: "thr_1", ...(method === "snooze" ? { snoozedUntil: Date.now() + 60000 } : {}) });
    expect(await harness.behavior.callRpc("listLifecycle", {})).toMatchObject({ rows: [{ parkedAt: null }] });
  });
  it("clears parking permanently when work starts", async () => {
    const harness = await loadPlugin();
    await harness.behavior.callRpc("park", { threadId: "thr_1" });
    await harness.behavior.emitThreadEvent("thread.active", { thread: makeThreadResponse({ id: "thr_1" }) });
    expect(await harness.behavior.callRpc("listLifecycle", {})).toEqual({ rows: [] });
  });
});


describe("parent thread RPC", () => {
  it("uses BB's thread update for assigning and removing a parent", async () => {
    const harness = await loadPlugin();
    harness.inspection.sdk.stub("threads.update", async ({ threadId }) => makeThreadResponse({ id: threadId }));
    for (const parentThreadId of ["thr_parent", null]) {
      await expect(harness.behavior.callRpc("setThreadParent", { threadId: "thr_1", parentThreadId })).resolves.toEqual({ ok: true });
    }
    expect(harness.inspection.sdk.callsTo("threads.update")).toEqual([
      [{ threadId: "thr_1", parentThreadId: "thr_parent" }],
      [{ threadId: "thr_1", parentThreadId: null }],
    ]);
  });
  it("propagates BB's validation failures", async () => {
    const harness = await loadPlugin();
    harness.inspection.sdk.stub("threads.update", async () => { throw new Error("Invalid parent relationship"); });
    await expect(harness.behavior.callRpc("setThreadParent", { threadId: "thr_1", parentThreadId: "thr_parent" })).rejects.toThrow("Invalid parent relationship");
  });
});
