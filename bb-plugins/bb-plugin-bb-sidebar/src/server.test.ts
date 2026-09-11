import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createFakePluginHost,
  makeThreadResponse,
} from "@get-bb/plugin-sdk/testing";
import plugin, {
  BOTS_REBIND_DELAY_MS,
  type StoredLifecycleRow,
} from "./server";

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
  it("stores the grouped sidebar settings through RPC", async () => {
    const harness = await loadPlugin();
    expect(harness.inspection.registrations.settingsDescriptors).toEqual({});
    await expect(
      harness.behavior.callRpc("getSidebarSettings", {}),
    ).resolves.toEqual({
      snoozePresets: "30m, 2h, 1d, 1w",
      inactiveThreadsEnabled: true,
      inactiveAfterHours: 6,
      autoSettleInactive: true,
      autoSettleAfterDays: 3,
      autoSettleOnMerge: true,
      showBots: true,
    });
    await expect(
      harness.behavior.callRpc("updateSidebarSettings", {
        snoozePresets: "10m, 4h",
        inactiveThreadsEnabled: false,
        inactiveAfterHours: 12,
        autoSettleInactive: false,
        autoSettleAfterDays: 7,
        autoSettleOnMerge: false,
        showBots: false,
      }),
    ).resolves.toEqual({
      snoozePresets: "10m, 4h",
      inactiveThreadsEnabled: false,
      inactiveAfterHours: 12,
      autoSettleInactive: false,
      autoSettleAfterDays: 7,
      autoSettleOnMerge: false,
      showBots: false,
    });
    // A client built before the Bots shelf omits the switch; the save still
    // lands and the switch keeps its default.
    await expect(
      harness.behavior.callRpc("updateSidebarSettings", {
        snoozePresets: "10m, 4h",
        inactiveThreadsEnabled: false,
        inactiveAfterHours: 12,
        autoSettleInactive: false,
        autoSettleAfterDays: 7,
        autoSettleOnMerge: false,
      }),
    ).resolves.toMatchObject({ showBots: true });
    expect(harness.inspection.realtimeSignals).toContainEqual({
      channel: "sidebar-settings",
      payload: {},
    });
    expect(harness.inspection.registrations.schedules).toContainEqual(
      expect.objectContaining({ name: "auto-settle", cron: "*/5 * * * *" }),
    );
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
      autoSettleInactive: false,
      autoSettleAfterDays: 14,
      autoSettleOnMerge: false,
      showBots: true,
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

  it("bulk settles successful rows and reports unpin failures", async () => {
    const harness = await loadPlugin(async ({ threadId }) => {
      if (threadId === "blocked") throw new Error("cannot unpin");
      return makeThreadResponse({ id: threadId });
    });

    await expect(
      harness.behavior.callRpc("bulkSettle", {
        threadIds: ["first", "blocked", "third"],
      }),
    ).resolves.toEqual({
      succeededThreadIds: ["first", "third"],
      failures: [{ threadId: "blocked", error: "cannot unpin" }],
    });
    const lifecycle = (await harness.behavior.callRpc(
      "listLifecycle",
      {},
    )) as LifecycleListResult;
    expect(lifecycle.rows.map((row) => row.threadId).sort()).toEqual([
      "first",
      "third",
    ]);
    expect(harness.inspection.realtimeSignals).toContainEqual({
      channel: "lifecycle",
      payload: { threadIds: ["first", "third"] },
    });
  });

  it("bulk snoozes rows with one lifecycle invalidation", async () => {
    const harness = await loadPlugin();
    const snoozedUntil = Date.now() + 60_000;

    await expect(
      harness.behavior.callRpc("bulkSnooze", {
        threadIds: ["first", "second"],
        snoozedUntil,
      }),
    ).resolves.toEqual({
      succeededThreadIds: ["first", "second"],
      failures: [],
    });
    const lifecycle = (await harness.behavior.callRpc(
      "listLifecycle",
      {},
    )) as LifecycleListResult;
    expect(lifecycle.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ threadId: "first", snoozedUntil }),
        expect.objectContaining({ threadId: "second", snoozedUntil }),
      ]),
    );
    expect(
      harness.inspection.realtimeSignals.filter(
        (signal) => signal.channel === "lifecycle",
      ),
    ).toEqual([
      {
        channel: "lifecycle",
        payload: { threadIds: ["first", "second"] },
      },
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

  it("does not settle when native unpinning fails", async () => {
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
      harness.behavior.callRpc("settle", { threadId: "thr_1" }),
    ).rejects.toThrow("pin update failed");
    await expect(
      harness.behavior.callRpc("listLifecycle", {}),
    ).resolves.toEqual({ rows: [] });
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
          path: "t3.json",
        },
      ],
      [
        {
          projectId: "proj_1",
          hostId: "host_1",
          path: "favicon.svg",
        },
      ],
    ]);
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

describe("listBots", () => {
  const upstream = {
    bots: [
      {
        id: "bot_1",
        name: "Reviewer",
        role: "Code review",
        avatar: {
          color: "#6d5efc",
          shape: "blob",
          expression: "focused",
          motion: "playful",
        },
        mainThreadId: "thr_main",
        hiddenUntilActivity: false,
        hiddenAt: null,
        sectionId: null,
        order: 0,
        linkedProjectIds: ["proj_1"],
        // Private state the bots plugin also returns; none of it may pass.
        soul: "You are a careful reviewer.",
        memory: "The user prefers terse feedback.",
        settings: { tone: "dry" },
        hostId: "host_1",
        stateHashes: {},
        updatedAt: 1,
      },
    ],
    sections: [{ id: "sec_1", name: "Ops", order: 0 }],
    threadBindings: [{ threadId: "thr_main", botId: "bot_1" }],
    hosts: [{ id: "host_1", name: "laptop", connected: true }],
    projects: [{ id: "proj_1", name: "bb" }],
    warnings: [],
    personalProjectId: "proj_personal",
  };

  type CallRpcArgs = {
    pluginId: string;
    method: string;
    input?: unknown;
    outputSchema: { parse(value: unknown): unknown };
  };

  async function loadWithBots(
    callRpc: (args: CallRpcArgs) => Promise<unknown>,
  ) {
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: { list: async () => [] },
        plugins: {
          // bb parses the other plugin's answer with the caller's schema;
          // the fake does the same, so narrowing is exercised here too.
          callRpc: async (args: CallRpcArgs) =>
            args.outputSchema.parse(await callRpc(args)),
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());
    return harness;
  }

  it("reads the bots plugin's list through bb and narrows it", async () => {
    const harness = await loadWithBots(async () => upstream);

    const result = await harness.behavior.callRpc("listBots", {});

    expect(result).toEqual({
      available: true,
      bots: [
        {
          id: "bot_1",
          name: "Reviewer",
          role: "Code review",
          mainThreadId: "thr_main",
          hiddenUntilActivity: false,
          hiddenAt: null,
          sectionId: null,
          order: 0,
          linkedProjectIds: ["proj_1"],
          avatar: {
            color: "#6d5efc",
            shape: "blob",
            expression: "focused",
            motion: "playful",
          },
          hostId: "host_1",
        },
      ],
      sections: [{ id: "sec_1", name: "Ops", order: 0 }],
      bindings: [{ threadId: "thr_main", botId: "bot_1" }],
      hosts: [{ id: "host_1", name: "laptop", connected: true }],
      personalProjectId: "proj_personal",
    });
    expect(JSON.stringify(result)).not.toContain("careful reviewer");

    const calls = harness.inspection.sdk.callsTo("plugins.callRpc");
    expect(calls).toHaveLength(1);
    expect(calls[0]![0]).toMatchObject({
      pluginId: "bots-sidebar",
      method: "bots_list",
      input: null,
    });
  });

  // The bots plugin is optional. Not installed, disabled, or answering in a
  // shape this plugin does not understand all mean the same thing to the
  // sidebar: no shelf, and no error in the user's face.
  it("answers unavailable, not an error, when the bots plugin cannot be read", async () => {
    const harness = await loadWithBots(async () => {
      throw new Error("plugin bots-sidebar is not installed");
    });

    await expect(harness.behavior.callRpc("listBots", {})).resolves.toEqual({
      available: false,
      reason: "plugin bots-sidebar is not installed",
    });
  });

  it("answers unavailable when the bots plugin's answer has the wrong shape", async () => {
    const harness = await loadWithBots(async () => ({ nope: true }));

    const result = (await harness.behavior.callRpc("listBots", {})) as {
      available: boolean;
    };

    expect(result.available).toBe(false);
  });
});

describe("bots re-read signal", () => {
  function botsSignals(harness: Awaited<ReturnType<typeof loadPlugin>>) {
    return harness.inspection.realtimeSignals.filter(
      (signal) => signal.channel === "bots",
    );
  }

  it("nudges the frontend after a thread is created, once the bots plugin has had time to bind", async () => {
    vi.useFakeTimers();
    try {
      const harness = await loadPlugin();
      await harness.behavior.emitThreadEvent("thread.created", {
        thread: makeThreadResponse({ id: "thr_new" }),
      });
      // Not at once: the bots plugin binds from the same event, and nothing
      // orders the two handlers.
      expect(botsSignals(harness)).toHaveLength(0);

      vi.advanceTimersByTime(BOTS_REBIND_DELAY_MS);

      expect(botsSignals(harness)).toEqual([
        { channel: "bots", payload: { threadId: "thr_new" } },
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("drops a pending nudge when the plugin unloads", async () => {
    vi.useFakeTimers();
    try {
      const harness = await loadPlugin();
      await harness.behavior.emitThreadEvent("thread.created", {
        thread: makeThreadResponse({ id: "thr_new" }),
      });
      // Dispose here rather than in afterEach, so the timer's fate is what
      // this test observes.
      await Promise.all(disposers.splice(0).map((dispose) => dispose()));

      vi.advanceTimersByTime(BOTS_REBIND_DELAY_MS * 2);

      expect(botsSignals(harness)).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("bot writes, proxied to the bots plugin", () => {
  const createdBot = {
    id: "bot_new",
    name: "Deployer",
    role: "Release",
    avatar: { color: "#e44f67", shape: "round", expression: "happy", motion: "calm" },
    hostId: "host_1",
    mainThreadId: null,
    hiddenUntilActivity: false,
    hiddenAt: null,
    sectionId: null,
    order: 1,
    linkedProjectIds: [],
    soul: "Ship it.",
  };

  async function loadRecording(answer: (method: string) => unknown) {
    const calls: Array<{ method: string; input: unknown }> = [];
    const { bb, harness } = createFakePluginHost({
      pluginId: "bb-sidebar",
      sdk: {
        threads: { list: async () => [] },
        plugins: {
          callRpc: async (args: {
            method: string;
            input?: unknown;
            outputSchema: { parse(value: unknown): unknown };
          }) => {
            calls.push({ method: args.method, input: args.input });
            return args.outputSchema.parse(answer(args.method));
          },
        },
      },
    });
    await plugin(bb);
    disposers.push(() => harness.lifecycle.dispose());
    return { harness, calls };
  }

  const botsSignals = (harness: Awaited<ReturnType<typeof loadPlugin>>) =>
    harness.inspection.realtimeSignals.filter(
      (signal) => signal.channel === "bots",
    );

  it("creates a bot in the main section with no projects, then tells clients", async () => {
    const { harness, calls } = await loadRecording(() => createdBot);
    const draft = {
      name: "Deployer",
      role: "Release",
      hostId: "host_1",
      avatar: createdBot.avatar,
      soul: "Ship it.",
    };

    const result = await harness.behavior.callRpc("createBot", draft);

    expect(calls).toEqual([
      {
        method: "bot_create",
        input: { ...draft, sectionId: null, linkedProjectIds: [] },
      },
    ]);
    expect(result).toMatchObject({ id: "bot_new", name: "Deployer" });
    expect(JSON.stringify(result)).not.toContain("Ship it");
    expect(botsSignals(harness)).toHaveLength(1);
  });

  it("refuses a draft the bots plugin would refuse, before calling it", async () => {
    const { harness, calls } = await loadRecording(() => createdBot);
    await expect(
      harness.behavior.callRpc("createBot", {
        name: "   ",
        role: "",
        hostId: "host_1",
        avatar: createdBot.avatar,
        soul: "",
      }),
    ).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it("reads the editor fields fresh and drops the bot's memory", async () => {
    const { harness, calls } = await loadRecording(() => ({
      ...createdBot,
      updatedAt: 42,
      stateHashes: { "SOUL.md": "a", "AGENTS.md": null, "MEMORY.md": "b", "settings.json": null },
      memory: "The user prefers terse feedback.",
      settings: { tone: "dry" },
    }));

    const result = await harness.behavior.callRpc("getBotEditor", {
      botId: "bot_new",
    });

    expect(calls).toEqual([{ method: "bot_prepare", input: { botId: "bot_new" } }]);
    expect(result).toEqual({
      id: "bot_new",
      name: "Deployer",
      role: "Release",
      avatar: createdBot.avatar,
      hostId: "host_1",
      sectionId: null,
      linkedProjectIds: [],
      soul: "Ship it.",
      updatedAt: 42,
      stateHashes: { "SOUL.md": "a", "AGENTS.md": null, "MEMORY.md": "b", "settings.json": null },
    });
    expect(JSON.stringify(result)).not.toContain("terse");
  });

  it("assigns a conversation and hides a bot through the bots plugin", async () => {
    const { harness, calls } = await loadRecording(() => ({ ok: true }));

    await expect(
      harness.behavior.callRpc("assignConversation", {
        botId: "bot_new",
        threadId: "thr_9",
      }),
    ).resolves.toEqual({ ok: true });
    await expect(
      harness.behavior.callRpc("setBotVisibility", {
        botId: "bot_new",
        hiddenUntilActivity: true,
      }),
    ).resolves.toEqual({ ok: true });

    expect(calls).toEqual([
      { method: "conversation_assign", input: { botId: "bot_new", threadId: "thr_9" } },
      { method: "visibility_set", input: { botId: "bot_new", hiddenUntilActivity: true } },
    ]);
    expect(botsSignals(harness)).toHaveLength(2);
  });

  it("starts a bot conversation with the composer's own request", async () => {
    const { harness, calls } = await loadRecording(() => ({ threadId: "thr_new" }));
    const request = {
      projectId: "proj_personal",
      providerId: "codex",
      model: "gpt",
      reasoningLevel: "medium",
      permissionMode: "auto",
      executionInputSources: {},
      environment: { type: "host", hostId: "host_1", workspace: { type: "personal" } },
      input: [{ type: "text", text: "Hello", mentions: [] }],
    };

    await expect(
      harness.behavior.callRpc("createBotConversation", {
        botId: "bot_new",
        request,
      }),
    ).resolves.toEqual({ threadId: "thr_new" });

    expect(calls).toEqual([
      {
        method: "conversation_create",
        input: { botId: "bot_new", request, makeMain: false },
      },
    ]);
  });
});
