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
    });
    await expect(
      harness.behavior.callRpc("updateSidebarSettings", {
        snoozePresets: "10m, 4h",
        inactiveThreadsEnabled: false,
        inactiveAfterHours: 12,
        autoSettleInactive: false,
        autoSettleAfterDays: 7,
        autoSettleOnMerge: false,
      }),
    ).resolves.toEqual({
      snoozePresets: "10m, 4h",
      inactiveThreadsEnabled: false,
      inactiveAfterHours: 12,
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
